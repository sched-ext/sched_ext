/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A central FIFO sched_ext scheduler which demonstrates the followings:
 *
 * a. Making all scheduling decisions from one CPU:
 *
 *    The central CPU is the only one making scheduling decisions. All other
 *    CPUs kick the central CPU when they run out of tasks to run.
 *
 *    There is one global BPF queue and the central CPU schedules all CPUs by
 *    dispatching from the global queue to each CPU's local dsq from dispatch().
 *    This isn't the most straight-forward. e.g. It'd be easier to bounce
 *    through per-CPU BPF queues. The current design is chosen to maximally
 *    utilize and verify various scx mechanisms such as LOCAL_ON dispatching and
 *    consume_final().
 *
 * b. Preemption
 *
 *    SCX_KICK_PREEMPT is used to trigger scheduling and CPUs to move to the
 *    next tasks.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include "scx_common.bpf.h"

char _license[] SEC("license") = "GPL";

enum {
	FALLBACK_DSQ_ID		= 0,
	MAX_CPUS		= 4096,
	MS_TO_NS		= 1000LLU * 1000,
	TIMER_INTERVAL_NS	= 1 * MS_TO_NS,
};

const volatile bool switch_all;
const volatile s32 central_cpu;
const volatile u32 nr_cpu_ids;

u64 nr_total, nr_locals, nr_queued, nr_lost_pids;
u64 nr_dispatches, nr_mismatches, nr_overflows;

struct user_exit_info uei;

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4096);
	__type(value, s32);
} central_q SEC(".maps");

/* can't use percpu map due to bad lookups */
static bool cpu_gimme_task[MAX_CPUS];

struct central_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct central_timer);
} central_timer SEC(".maps");

static bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

s32 BPF_STRUCT_OPS(central_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	/*
	 * Steer wakeups to the central CPU as much as possible to avoid
	 * disturbing other CPUs. It's safe to blindly return the central cpu as
	 * select_cpu() is a hint and if @p can't be on it, the kernel will
	 * automatically pick a fallback CPU.
	 */
	return central_cpu;
}

void BPF_STRUCT_OPS(central_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;

	__sync_fetch_and_add(&nr_total, 1);

	if (bpf_map_push_elem(&central_q, &pid, 0)) {
		__sync_fetch_and_add(&nr_overflows, 1);
		scx_bpf_dispatch(p, FALLBACK_DSQ_ID, SCX_SLICE_DFL, enq_flags);
		return;
	}

	__sync_fetch_and_add(&nr_queued, 1);

	if (!scx_bpf_task_running(p))
		scx_bpf_kick_cpu(central_cpu, SCX_KICK_PREEMPT);
}

static int dispatch_a_task_loopfn(u32 idx, void *data)
{
	s32 cpu = *(s32 *)data;
	s32 pid;
	struct task_struct *p;
	bool *gimme;

	if (bpf_map_pop_elem(&central_q, &pid))
		return 1;

	__sync_fetch_and_sub(&nr_queued, 1);

	p = scx_bpf_find_task_by_pid(pid);
	if (!p) {
		__sync_fetch_and_add(&nr_lost_pids, 1);
		return 0;
	}

	/*
	 * If we can't run the task at the top, do the dumb thing and bounce it
	 * to the fallback dsq.
	 */
	if (!scx_bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		__sync_fetch_and_add(&nr_mismatches, 1);
		scx_bpf_dispatch(p, FALLBACK_DSQ_ID, SCX_SLICE_DFL, 0);
		return 0;
	}

	/* dispatch to the local and mark that @cpu doesn't need more tasks */
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);

	if (cpu != central_cpu)
		scx_bpf_kick_cpu(cpu, 0);

	gimme = MEMBER_VPTR(cpu_gimme_task, [cpu]);
	if (gimme)
		*gimme = false;

	return 1;
}

static int dispatch_to_one_cpu_loopfn(u32 idx, void *data)
{
	s32 cpu = idx;

	if (cpu >= 0 && cpu < MAX_CPUS) {
		bool *gimme = MEMBER_VPTR(cpu_gimme_task, [cpu]);
		if (gimme && !*gimme)
			return 0;
	}

	bpf_loop(1 << 23, dispatch_a_task_loopfn, &cpu, 0);
	return 0;
}

void BPF_STRUCT_OPS(central_dispatch, s32 cpu, struct task_struct *prev)
{
	/* if out of tasks to run, gimme more */
	if (!scx_bpf_dsq_nr_queued(FALLBACK_DSQ_ID)) {
		bool *gimme = MEMBER_VPTR(cpu_gimme_task, [cpu]);
		if (gimme)
			*gimme = true;
	}

	if (cpu == central_cpu) {
		/* we're the scheduling CPU, dispatch for every CPU */
		__sync_fetch_and_add(&nr_dispatches, 1);
		bpf_loop(nr_cpu_ids, dispatch_to_one_cpu_loopfn, NULL, 0);
	} else {
		/*
		 * Force dispatch on the scheduling CPU so that it finds a task
		 * to run for us.
		 */
		scx_bpf_kick_cpu(central_cpu, SCX_KICK_PREEMPT);
	}
}

void BPF_STRUCT_OPS(central_consume, s32 cpu)
{
	/*
	 * When preempted, we want the central CPU to always run dispatch() as
	 * soon as possible so that it can schedule other CPUs. Don't consume
	 * the fallback dsq if central.
	 */
	if (cpu != central_cpu)
		scx_bpf_consume(FALLBACK_DSQ_ID);
}

void BPF_STRUCT_OPS(central_consume_final, s32 cpu)
{
	/*
	 * Now that the central CPU has dispatched, we can let it consume the
	 * fallback dsq.
	 */
	if (cpu == central_cpu)
		scx_bpf_consume(FALLBACK_DSQ_ID);
}

int BPF_STRUCT_OPS(central_init)
{
	if (switch_all)
		scx_bpf_switch_all();

	return scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
}

void BPF_STRUCT_OPS(central_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops")
struct sched_ext_ops central_ops = {
	/*
	 * We are offloading all scheduling decisions to the central CPU and
	 * thus being the last task on a given CPU doesn't mean anything
	 * special. Enqueue the last tasks like any other tasks.
	 */
	.flags			= SCX_OPS_ENQ_LAST,

	.select_cpu		= (void *)central_select_cpu,
	.enqueue		= (void *)central_enqueue,
	.dispatch		= (void *)central_dispatch,
	.consume		= (void *)central_consume,
	.consume_final		= (void *)central_consume_final,
	.init			= (void *)central_init,
	.exit			= (void *)central_exit,
	.name			= "central",
};
