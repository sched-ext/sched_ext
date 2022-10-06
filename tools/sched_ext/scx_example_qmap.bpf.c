// SPDX-License-Identifier: GPL-2.0
#include "scx_common.h"
#include <linux/sched/prio.h>

char _license[] SEC("license") = "GPL";

const volatile u64 slice_ns = 200 * 1000 * 1000;

bool exited = false;

/*
 * The five scheduling FIFOs. A task gets assigned to one depending on its
 * compound weight. Each CPU round robins through the FIFOs and dispatches more
 * from FIFOs with higher indices - 1 from queue0, 2 from queue1, 4 from queue2
 * and so on
 */
struct qmap {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4096);
	__type(value, u32);
} queue0 SEC(".maps"),
  queue1 SEC(".maps"),
  queue2 SEC(".maps"),
  queue3 SEC(".maps"),
  queue4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 5);
	__type(key, int);
	__array(values, struct qmap);
} queue_arr SEC(".maps") = {
	.values = {
		[0] = &queue0,
		[1] = &queue1,
		[2] = &queue2,
		[3] = &queue3,
		[4] = &queue4,
	},
};

/* Per-task scheduling context */
struct task_ctx {
	bool	force_local;	/* Dispatch directly to local_dq */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* Per-cpu dispatch index and remaining count */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} dispatch_idx_cnt SEC(".maps");

/* Statistics */
unsigned long nr_queued, nr_dispatched;

/*
 * bpf_task_storage_get() may fail spuriously when called from irq context due
 * to bc235cdb423a ("bpf: Prevent deadlock from recursive
 * bpf_task_storage_[get|delete]"). This will be fixed but for now work around
 * by punting to the global dq.
 */
unsigned long nr_bad_lookups;

s32 BPF_STRUCT_OPS(qmap_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	s32 cpu;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		/* See the comment above nr_bad_lookups. */
		nr_bad_lookups++;
		return prev_cpu;
	}

	if (p->nr_cpus_allowed == 1 ||
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		tctx->force_local = true;
		return prev_cpu;
	}

	cpu = scx_bpf_pick_idle_cpu(scx_bpf_task_cpumask(p));
	if (cpu >= 0)
		return cpu;

	return prev_cpu;
}

s64 BPF_STRUCT_OPS(qmap_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u32 pid = p->pid;
	int idx;
	void *ring;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		/* See the comment above nr_bad_lookups. */
		nr_bad_lookups++;
		p->scx.slice = slice_ns;
		return SCX_DQ_GLOBAL;
	}

	/* Is select_cpu() is telling us to enqueue locally? */
	if (tctx->force_local) {
		tctx->force_local = false;
		p->scx.slice = slice_ns;
		return SCX_DQ_LOCAL;
	}

	/* Coarsely map the compount weight to a FIFO. */
	if (p->scx.weight <= 25)
		idx = 0;
	else if (p->scx.weight <= 50)
		idx = 1;
	else if (p->scx.weight < 200)
		idx = 2;
	else if (p->scx.weight < 400)
		idx = 3;
	else
		idx = 4;

	ring = bpf_map_lookup_elem(&queue_arr, &idx);
	if (!ring)
		return -ENOENT;

	/* Queue on the selected FIFO. If the FIFO overflows, punt to global. */
	if (bpf_map_push_elem(ring, &pid, 0)) {
		p->scx.slice = slice_ns;
		return SCX_DQ_GLOBAL;
	}

	__sync_fetch_and_add(&nr_queued, 1);
	return SCX_DQ_NONE;
}

s32 BPF_STRUCT_OPS(qmap_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 zero = 0, one = 1;
	u64 *idx = bpf_map_lookup_elem(&dispatch_idx_cnt, &zero);
	u64 *cnt = bpf_map_lookup_elem(&dispatch_idx_cnt, &one);
	void *fifo;
	s32 pid;
	int i;

	if (!idx || !cnt)
		return -EINVAL;

	for (i = 0; i < 5; i++) {
		/* Advance the dispatch cursor and pick the fifo. */
		if (!*cnt) {
			*idx = (*idx + 1) % 5;
			*cnt = 1 << *idx;
		}
		(*cnt)--;

		fifo = bpf_map_lookup_elem(&queue_arr, idx);
		if (!fifo)
			return -ENOENT;

		/* Dispatch or advance. */
		if (!bpf_map_pop_elem(fifo, &pid)) {
			struct task_struct *p;

			p = scx_bpf_find_task_by_pid(pid);
			if (p) {
				__sync_fetch_and_add(&nr_dispatched, 1);
				p->scx.slice = slice_ns;
				scx_bpf_dispatch(p, SCX_DQ_GLOBAL);
				return 0;
			}
		}

		*cnt = 0;
	}

	return 0;
}

s32 BPF_STRUCT_OPS(qmap_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	if (bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

void BPF_STRUCT_OPS(qmap_exit, struct scx_ops_exit_info *ei)
{
	static char exit_msg[SCX_OPS_EXIT_MSG_LEN];

	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exited = true;
}

SEC(".struct_ops")
struct sched_ext_ops qmap_ops = {
	.select_cpu		= (void *)qmap_select_cpu,
	.enqueue		= (void *)qmap_enqueue,
	/*
	 * The queue map doesn't support removal and sched_ext can handle
	 * spurious dispatches. Let's be lazy and not bother with dequeueing.
	 */
	.dispatch		= (void *)qmap_dispatch,
	.prep_enable		= (void *)qmap_prep_enable,
	.exit			= (void *)qmap_exit,
	.flags			= SCX_OPS_CGROUP_KNOB_WEIGHT,
	.name			= "qmap",
};
