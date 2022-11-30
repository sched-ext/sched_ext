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
 * b. Tickless operation
 *
 *    All tasks are dispatched with the infinite slice which allows stopping the
 *    ticks on CONFIG_NO_HZ_FULL kernels running with the proper nohz_full
 *    parameter. The tickless operation can be observed through
 *    /proc/interrupts.
 *
 *    Periodic switching is enforced by a periodic timer checking all CPUs and
 *    preempting them as necessary. Unfortunately, BPF timer currently doesn't
 *    have a way to pin to a specific CPU, so the periodic timer isn't pinned to
 *    the central CPU.
 *
 * c. Preemption
 *
 *    Kthreads are unconditionally queued to the head of a matching local dsq
 *    and dispatched with SCX_DSQ_PREEMPT. This ensures that a kthread is always
 *    prioritized over user threads, which is required for ensuring forward
 *    progress as e.g. the periodic timer may run on a ksoftirqd and if the
 *    ksoftirqd gets starved by a user thread, there may not be anything else to
 *    vacate that user thread.
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

/*
 * XXX - kernel should be able to shut down the associated timers. For now,
 * implement it manually. They should be bool but the verifier gets confused
 * about the value range of bool variables when verifying the return value of
 * the loopfns. Also, they can't be static because verification fails with BTF
 * error message for some reason.
 */
int timer_running;
int timer_kill;

u64 nr_total, nr_locals, nr_queued, nr_lost_pids;
u64 nr_timers, nr_dispatches, nr_mismatches, nr_overflows;

struct user_exit_info uei;

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4096);
	__type(value, s32);
} central_q SEC(".maps");

/* can't use percpu map due to bad lookups */
static bool cpu_gimme_task[MAX_CPUS];
static u64 cpu_started_at[MAX_CPUS];

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

	/*
	 * Push per-cpu kthreads at the head of local dsq's and preempt the
	 * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
	 * behind other threads which is necessary for forward progress
	 * guarantee as we depend on the BPF timer which may run from ksoftirqd.
	 */
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		__sync_fetch_and_add(&nr_locals, 1);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
				 enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

	if (bpf_map_push_elem(&central_q, &pid, 0)) {
		__sync_fetch_and_add(&nr_overflows, 1);
		scx_bpf_dispatch(p, FALLBACK_DSQ_ID, SCX_SLICE_INF, enq_flags);
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
		scx_bpf_dispatch(p, FALLBACK_DSQ_ID, SCX_SLICE_INF, 0);
		return 0;
	}

	/* dispatch to the local and mark that @cpu doesn't need more tasks */
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, 0);

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

void BPF_STRUCT_OPS(central_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	u64 *started_at = MEMBER_VPTR(cpu_started_at, [cpu]);
	if (started_at)
		*started_at = bpf_ktime_get_ns() ?: 1;	/* 0 indicates idle */
}

void BPF_STRUCT_OPS(central_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	u64 *started_at = MEMBER_VPTR(cpu_started_at, [cpu]);
	if (started_at)
		*started_at = 0;
}

static int kick_cpus_loopfn(u32 idx, void *data)
{
	s32 cpu = (nr_timers + idx) % nr_cpu_ids;
	u64 *nr_to_kick = data;
	u64 now = bpf_ktime_get_ns();
	u64 *started_at;
	s32 pid;

	if (cpu == central_cpu)
		goto kick;

	/* kick iff there's something pending */
	if (scx_bpf_dsq_nr_queued(FALLBACK_DSQ_ID) ||
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu))
		;
	else if (*nr_to_kick)
		(*nr_to_kick)--;
	else
		return 0;

	/* and the current one exhausted its slice */
	started_at = MEMBER_VPTR(cpu_started_at, [cpu]);
	if (started_at && *started_at &&
	    vtime_before(now, *started_at + SCX_SLICE_DFL))
		return 0;
kick:
	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	return 0;
}

static int central_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 nr_to_kick = nr_queued;

	if (timer_kill) {
		timer_running = 0;
		return 0;
	}

	bpf_loop(nr_cpu_ids, kick_cpus_loopfn, &nr_to_kick, 0);
	bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	__sync_fetch_and_add(&nr_timers, 1);
	return 0;
}

int BPF_STRUCT_OPS(central_init)
{
	u32 key = 0;
	struct bpf_timer *timer;
	int ret;

	if (switch_all)
		scx_bpf_switch_all();

	ret = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
	if (ret)
		return ret;

	timer = bpf_map_lookup_elem(&central_timer, &key);
	if (!timer)
		return -ESRCH;

	bpf_timer_init(timer, &central_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, central_timerfn);
	ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	timer_running = !ret;
	return ret;
}

static int exit_wait_timer_nested_loopfn(u32 idx, void *data)
{
	u64 expiration = *(u64 *)data;

	return !timer_running || vtime_before(expiration, bpf_ktime_get_ns());
}

static int exit_wait_timer_loopfn(u32 idx, void *data)
{
	u64 expiration = *(u64 *)data;

	bpf_loop(1 << 23, exit_wait_timer_nested_loopfn, data, 0);
	return !timer_running || vtime_before(expiration, bpf_ktime_get_ns());
}

void BPF_STRUCT_OPS(central_exit, struct scx_exit_info *ei)
{
	u64 expiration = bpf_ktime_get_ns() + 1000 * MS_TO_NS;

	/*
	 * XXX - We just need to make sure that the timer body isn't running on
	 * exit. If we catch the timer while waiting, great. If not, it's still
	 * highly likely that the timer body won't run in the future. Once bpf
	 * can shut down associated timers, this hackery should go away.
	 */
	timer_kill = 1;
	bpf_loop(1 << 23, exit_wait_timer_loopfn, &expiration, 0);

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
	.running		= (void *)central_running,
	.stopping		= (void *)central_stopping,
	.init			= (void *)central_init,
	.exit			= (void *)central_exit,
	.name			= "central",
};
