/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>
#include <scx/compat/v1.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile bool switch_partial;

static u64 vtime_now;
struct user_exit_info uei;

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static inline void enqueue(struct task_struct *p, u64 enq_flags)
{
	/*
	 * If scx_select_cpu_dfl() is setting %SCX_ENQ_LOCAL, it indicates that
	 * running @p on its CPU directly shouldn't affect fairness. Just queue
	 * it on the local FIFO.
	 */
	if (bpf_core_enum_value_exists(enum scx_enq_flags___v1, SCX_ENQ_LOCAL) &&
	    (enq_flags & SCX_ENQ_LOCAL)) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	enqueue(p, enq_flags);
}

void BPF_STRUCT_OPS(simple_enqueue_v1, struct task_struct *p, u64 enq_flags)
{
	enqueue(p, enq_flags);
}

static inline void dispatch(void)
{
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	dispatch();
}

void BPF_STRUCT_OPS(simple_dispatch_v1, s32 cpu, struct task_struct *prev)
{
	dispatch();
}

static inline void running(struct task_struct *p)
{
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	running(p);
}

void BPF_STRUCT_OPS(simple_running_v1, struct task_struct *p)
{
	running(p);
}

static inline void stopping(struct task_struct *p)
{
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	stopping(p);
}

void BPF_STRUCT_OPS(simple_stopping_v1, struct task_struct *p, bool runnable)
{
	stopping(p);
}

static inline void enable(struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	enable(p);
}

void BPF_STRUCT_OPS(simple_enable_v1, struct task_struct *p,
		    struct scx_enable_args___v1 *args)
{
	enable(p);
}

static inline s32 init(void)
{
	if (!switch_partial)
		scx_bpf_switch_all();

	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	return init();
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init_v1)
{
	return init();
}

static inline void sched_exit(struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	sched_exit(ei);
}

void BPF_STRUCT_OPS(simple_exit_v1, struct scx_exit_info *ei)
{
	sched_exit(ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops___v1 simple_ops_v1 = {
	.enqueue		= (void *)simple_enqueue_v1,
	.dispatch		= (void *)simple_dispatch_v1,
	.running		= (void *)simple_running_v1,
	.stopping		= (void *)simple_stopping_v1,
	.enable			= (void *)simple_enable_v1,
	.init			= (void *)simple_init_v1,
	.exit			= (void *)simple_exit_v1,
	.name			= "simple",
};

SEC(".struct_ops.link")
struct sched_ext_ops simple_ops = {
	.enqueue		= (void *)simple_enqueue,
	.dispatch		= (void *)simple_dispatch,
	.running		= (void *)simple_running,
	.stopping		= (void *)simple_stopping,
	.enable			= (void *)simple_enable,
	.init			= (void *)simple_init,
	.exit			= (void *)simple_exit,
	.name			= "simple",
};
