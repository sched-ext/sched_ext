// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#include "scx_common.h"
#include "rhone_bpf_internal.h"

char _license[] SEC("license") = "GPL";

#define MAX_DISPATCH_BATCH 256

#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
                __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
		__uint(max_entries, RHONE_PERCPU_RB_SIZE);
	});
} uprod_ringbuffers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
		__uint(max_entries, RHONE_PERCPU_RB_SIZE);
	});
} kprod_ringbuffers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, s64);
} cpu_dq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u8);
} need_tasks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} manager_rb SEC(".maps");

unsigned long nr_overflowed;

unsigned long long nr_local_enqueued, nr_global_enqueued;
unsigned long long nr_local_dispatched, nr_global_dispatched;
unsigned long long nr_consumed;
unsigned long long nr_global_dq_dispatched, nr_global_dq_consumed;
unsigned long long nr_kernel_tasks;

volatile bool exiting = false;

/*
 * Whether the user-space scheduler will be making scheduling decisions for
 * kthreads. If this value is set to false, kthreads will be dispatched
 * immediately to the global DQ.
 */
bool schedule_kernel_tasks = false;

u32 bootstrap_rb = 0;
u32 consume_batch_size = 8;

static void *get_kprod_ringbuf(u32 cpu)
{
	return bpf_map_lookup_elem(&kprod_ringbuffers, &cpu);
}

static void *get_uprod_ringbuf(u32 cpu)
{
	return bpf_map_lookup_elem(&uprod_ringbuffers, &cpu);
}

static s64 cpu_to_dq_id(u32 cpu)
{
	s64 *dq_id;
	u32 key = cpu;

	dq_id = bpf_map_lookup_elem(&cpu_dq_map, &key);

	return dq_id ? *dq_id : -1;
}

static int dispatch_cpu_drain(struct bpf_dynptr *dynptr, void *context)
{
	struct rhone_bpf_user_sched_msg msg;
	struct task_struct *p;
	__s32 *num_drained = (__s32*)context;
	s32 cpu, pid;
	s64 dq_id;
	int err;

	err = bpf_dynptr_read(&msg, sizeof(msg), dynptr, 0, 0);
	if (err) {
		/* Should never happen. */
		bpf_printk("Failed to read dispatch dynptr: %d, forcing exit", err);
		goto exit_fail;
	}

	pid = msg.pid;
	p = scx_bpf_find_task_by_pid(pid);
	if (!p) {
		bpf_printk("Failed to find task for pid %d", pid);
		goto exit_fail;
	}

	/* First try to find an idle CPU. */
	cpu = scx_bpf_pick_idle_cpu(scx_bpf_task_cpumask(p));
	if (cpu >= 0) {
		scx_bpf_kick_cpu(cpu, 0);
		if (!scx_bpf_dispatch(p, SCX_DQ_LOCAL_ON | cpu)) {
			__sync_fetch_and_add(&nr_local_dispatched, 1);
			goto dispatch_finish;
		}
	}

	switch (msg.msg_type) {
	case RHONE_BPF_USER_MSG_TASK_DISPATCH:
		cpu = bpf_get_smp_processor_id();
		dq_id = cpu_to_dq_id(cpu);
		if (dq_id == -1) {
			/* Should never happen. */
			bpf_printk("Failed to look up dq_id, forcing exit");
			goto exit_fail;
		}
		if (!scx_bpf_dispatch(p, dq_id)) {
			__sync_fetch_and_add(&nr_global_dispatched, 1);
			break;
		}
		bpf_printk("Failed to dispatch %s to %ld, trying global dq",
			   p->comm, dq_id);
	case RHONE_BPF_USER_MSG_TASK_UNKNOWN:
		if (scx_bpf_dispatch(p, SCX_DQ_GLOBAL)) {
			bpf_printk("Failed to dispatch %s to global dq, exiting scheduler",
				   p->comm);
			goto exit_fail;
		}
		__sync_fetch_and_add(&nr_global_dq_dispatched, 1);
		break;
	default:
		bpf_printk("Unknown user message type: %d", msg.msg_type);
		goto exit_fail;
	}

dispatch_finish:
	*num_drained += 1;
	return *num_drained >= MAX_DISPATCH_BATCH;

exit_fail:
	*num_drained = -1;
	exiting = true;
	return 1;
}

s32 BPF_STRUCT_OPS(rhone_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (p->nr_cpus_allowed == 1 || scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	cpu = scx_bpf_pick_idle_cpu(scx_bpf_task_cpumask(p));
	if (cpu >= 0)
		return cpu;

	return prev_cpu;
}

s64 BPF_STRUCT_OPS(rhone_enqueue, struct task_struct *p, u64 enq_flags)
{
	void *kernel_rb, *user_rb;
	struct rhone_bpf_kernel_enqueue_msg *msg;
	u32 cpu;

	/*
	 * If the task isn't pinned to a single CPU (or we failed to lookup the
	 * task's context), send a message to this CPU's commander thread in
	 * userspace, and enqueue the task for later.
	 */
	cpu = bpf_get_smp_processor_id();

	user_rb = get_uprod_ringbuf(cpu);
	if (!user_rb)
		/* Should never happen. */
		return -ENOENT;

	if (exiting) {
		int ret, num_drained = 0;

		ret = bpf_user_ringbuf_drain(user_rb, dispatch_cpu_drain,
					     &num_drained, 0);
		if (ret < 0)
			return ret;

		__sync_fetch_and_add(&nr_local_enqueued, 1);
		return SCX_DQ_LOCAL;
	}

	if (p->nr_cpus_allowed == 1) {
		__sync_fetch_and_add(&nr_local_enqueued, 1);
		return SCX_DQ_LOCAL;
	} else if (!schedule_kernel_tasks && p->flags & PF_KTHREAD) {
		__sync_fetch_and_add(&nr_kernel_tasks, 1);
		return SCX_DQ_GLOBAL;
	}

	kernel_rb = get_kprod_ringbuf(cpu);
	if (!kernel_rb)
		/* Should never happen. */
		return -ENOENT;
	msg = bpf_ringbuf_reserve(kernel_rb, sizeof(*msg), 0);
	if (!msg) {
		/* If there's no memory left in the ringbuffer, just keep it on the local DQ. */
		__sync_fetch_and_add(&nr_overflowed, 1);
		__sync_fetch_and_add(&nr_local_enqueued, 1);
		return SCX_DQ_LOCAL;
	}

	msg->hdr.msg_type = RHONE_BPF_KERN_MSG_TASK_ENQUEUE;
	msg->pid = p->pid;
	msg->flags = enq_flags;

	bpf_ringbuf_submit(msg, 0);

	__sync_fetch_and_add(&nr_global_enqueued, 1);

	return SCX_DQ_NONE;
}

static int send_need_tasks_msg(s32 cpu)
{
	struct rhone_bpf_kernel_need_tasks_msg *msg;
	void *kprod_ringbuf;

	kprod_ringbuf = get_kprod_ringbuf(cpu);
	if (!kprod_ringbuf) {
		/* Should never happen. */
		bpf_printk("Failed to get kprod_ringbuf for %d", cpu);
		return -ENOENT;
	}

	msg = bpf_ringbuf_reserve(kprod_ringbuf, sizeof(*msg), 0);
	if (!msg) {
		bpf_printk("Couldn't reserve ringbuf consume msg for %d", cpu);
		__sync_fetch_and_add(&nr_overflowed, 1);
		return -ENODATA;
	}

	msg->hdr.msg_type = RHONE_BPF_KERN_MSG_NEED_TASKS;
	bpf_ringbuf_submit(msg, BPF_RB_FORCE_WAKEUP);

	return 0;
}

int BPF_STRUCT_OPS(rhone_dispatch, s32 cpu, struct task_struct *prev)
{
	void *user_rb;
	int ret;
	__s32 num_drained = 0;

	user_rb = get_uprod_ringbuf(cpu);
	if (!user_rb)
		return -ENOENT;

	ret = bpf_user_ringbuf_drain(user_rb, dispatch_cpu_drain, &num_drained, 0);
	/*
	 * -ENODATA means that there's nothing to drain. Any other error code is
	 * unexpected, and should only occur if the ringbuffer is contended
	 * amongst multiple readers. Each per-cpu ringbuffer is only read by the
	 * current CPU, and should never be contended.
	 */
	if (ret < 0 && ret != -ENODATA)
		return ret;

	if (num_drained < 0) {
		return num_drained;
	} else if (num_drained == 0) {
		ret = send_need_tasks_msg(cpu);
		if (ret < 0) {
			u8 one = 1;

			bpf_printk("Couldn't send need tasks msg: %d", ret);
			if (bpf_map_update_elem(&need_tasks_map, &cpu, &one, 0)) {
				bpf_printk("Couldn't set need task flag");
				exiting = true;
				return ret;
			}
			return 0;
		}
	}

	return  0;
}

void BPF_STRUCT_OPS(rhone_consume, s32 cpu)
{
	s32 key = cpu;
	s64 *dq_id;

	/* Always try to drain the global DQ. */
	if (scx_bpf_consume(SCX_DQ_GLOBAL))
		__sync_fetch_and_add(&nr_global_dq_consumed, 1);

	dq_id = bpf_map_lookup_elem(&cpu_dq_map, &key);
	if (!dq_id) {
		/* Should never happen. */
		bpf_printk("Failed to get dq_id for cpu %d", cpu);
		exiting = true;
		return;
	}

	if (scx_bpf_consume(*dq_id))
		__sync_fetch_and_add(&nr_consumed, 1);
}

int BPF_STRUCT_OPS(rhone_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	void *kernel_rb;
	struct rhone_bpf_kernel_task_enable_msg *msg;
	static int num_enabled;

	kernel_rb = &manager_rb;
	if (!kernel_rb)
		// Should never happen.
		return -ENOENT;

	msg = bpf_ringbuf_reserve(kernel_rb, sizeof(*msg), 0);
	if (!msg) {
		/*
		 * If there's no memory left in the ringbuffer, fail.
		 *
		 * TODO: Handle this and try to notify the user again later. Or
		 * add a helper that lets a BPF ringbuf producer block until
		 * there's space in the ringbuffer.
		 */
		__sync_fetch_and_add(&nr_overflowed, 1);
		return -ENOMEM;
	}

	msg->hdr.msg_type = RHONE_BPF_MANAGE_MSG_TASK_ENABLE;
	msg->pid = p->pid;
	if (bpf_probe_read_kernel_str(msg->name, sizeof(msg->name), p->comm) < 0)
		goto fail_probe_read_discard;

	if (bpf_probe_read_kernel(msg->cpumask, sizeof(msg->cpumask), p->cpus_ptr))
		goto fail_probe_read_discard;

	bpf_ringbuf_submit(msg, BPF_RB_FORCE_WAKEUP);
	return 0;

fail_probe_read_discard:
	/*
	 * For now just fail hard. In the future, we could instead just record
	 * the fact that we haven't successfully told user-space about this
	 * task, and keep trying in other callbacks. Alternatively, it might
	 * be handy to add a BPF helper here that can sleep until a sample
	 * is available.
	 */
	bpf_ringbuf_discard(msg, BPF_RB_FORCE_WAKEUP);
	return -EFAULT;
}


static int bootstrap_drain(struct bpf_dynptr *dynptr, void *context)
{
	struct dispatch_entry *entry;
	int err, *failed_bootstrap = context;
	struct rhone_bpf_user_bootstrap_msg msg;

	err = bpf_dynptr_read(&msg, sizeof(msg), dynptr, 0, 0);
	if (err) {
		bpf_printk("Failed to read from dynptr: %d\n", err);
		*failed_bootstrap = 1;
		return 1;
	}

	err = scx_bpf_create_dq(msg.dq_id, -1);
	if (err) {
		bpf_printk("Failed to create dq: %d\n", err);
		*failed_bootstrap = 1;
		return 1;
	}

	return 0;
}

int BPF_STRUCT_OPS(rhone_init)
{
	void *user_rb;
	int ret, num_drained = 0, failed_bootstrap = 0;

	user_rb = get_uprod_ringbuf(bootstrap_rb);
	if (!user_rb) {
		/* Should never happen. */
		bpf_printk("Failed to initialize");
		return -1;
	}

	ret = bpf_user_ringbuf_drain(user_rb, bootstrap_drain, &failed_bootstrap, 0);
	if (ret < 0) {
		/* Should never happen. */
		bpf_printk("Failed to create dispatch queues: %d", ret);
		return ret;
	}

	return failed_bootstrap ? -1 : 0;
}

void BPF_STRUCT_OPS(rhone_exit, struct scx_ops_exit_info *ei)
{
	static char exit_msg[SCX_OPS_EXIT_MSG_LEN];

	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	bpf_printk("INFO: exiting type=%d msg=\"%s\"", ei->type, exit_msg);
	exiting = true;
}

SEC(".struct_ops")
struct sched_ext_ops rhone = {
	.select_cpu		= (void *)rhone_select_cpu,
	.enqueue		= (void *)rhone_enqueue,
	.dispatch		= (void *)rhone_dispatch,
	.consume		= (void *)rhone_consume,
	.prep_enable		= (void *)rhone_prep_enable,
	.init			= (void *)rhone_init,
	.exit			= (void *)rhone_exit,
	.dispatch_max_batch	= MAX_DISPATCH_BATCH,
	.name			= "rhone",
};
