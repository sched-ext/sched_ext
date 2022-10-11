// SPDX-License-Identifier: GPL-2.0
#include "scx_common.h"
#include "scxl_example_flat.h"

char _license[] SEC("license") = "GPL";

__u64 lb_timer_at;

/*
 * const volatiles are set during initialization and treated as consts by the
 * jit compiler.
 */

/*
 * Domains and cpus
 */
const volatile __u32 nr_doms = 1;
const volatile __u32 cpu_dom_id_map[MAX_CPUS];

static u32 cpu_to_dom_id(s32 cpu)
{
	if (nr_doms <= 1)
		return 0;

	if (cpu >= 0 && cpu < MAX_CPUS)
		return cpu_dom_id_map[cpu];
	else
		return MAX_DOMS;
}

const volatile __u64 dom_cpumasks[MAX_DOMS][MAX_CPUS / 64] = {
	[0] = { [0 ... MAX_CPUS / 64 - 1] = -1 },
};

/*
 * Max cpu id + 1. Note that CPU IDs may not be allocated consecutively. We
 * wouldn't need the following if we could walk cpu_possible_mask.
 */
__u32 nr_cpu_ids;

static bool is_cpu_in_dom(u32 cpu, u32 dom_id)
{
	return dom_cpumasks[dom_id][cpu / 64] & (1LLU << (cpu % 64));
}

/* base slice duration */
const volatile __u64 slice_us = 20000;

/* running avg half-life in nsecs for load - 100ms */
const volatile __u64 load_hl = 100 * 1000 * 1000;

/* how much budget a sleeping task can accumulate expressed in % of @slice_us */
const volatile __u32 sleep_boost_pct = 50;

/* Skip enqueue and directly dispatch if the remaining budget is above
   @min_slice_us and the last dispatch from sq is not older than @duration_us.
   -1 indicates default - 1/4 of @slice_us for @min_slice_us and twice @slice_us
   for @duration_us. */
const volatile __u64 skip_enqueue_min_slice_us = -1;
const volatile __u64 skip_enqueue_duration_us = -1;

const volatile __u64 greedy_threshold = (u64)-1;

/*
 * Load balancing
 */
static __u64 global_load_sum;
__u64 global_load_avg;

/*
 * If a domain's load is higher than the average by more than load_imbal_high,
 * shed load to close the gap down to load_imbal_low. Don't shed more than
 * load_imbal_max_adj_pct in a single period.
 */
const volatile __u32 load_imbal_low_pct = 5;
const volatile __u32 load_imbal_high_pct = 10;
const volatile __u32 load_imbal_max_adj_pct = 10;

/*
 * XXX - kernel should be able to shut down the associated timers. For now,
 * implement it manually. They should be bool but the verifier gets confused
 * about the value range of bool variables when verifying the return value of
 * the loopfns. Also, they can't be static because verification fails with BTF
 * error message for some reason.
 */
int timer_running;
int timer_kill;

/*
 * Exit info
 */
int exit_type = SCX_OPS_EXIT_NONE;
char exit_msg[SCX_OPS_EXIT_MSG_LEN];

/* le_data->flags */
enum le_flags {
	LE_LOCAL		= (1 << 1),	/* dispatch to local */
};

/* extl_entity private data */
struct le_data {
	u64			vtime;		/* vtime cursor */
	u32			flags;		/* LE_* */
	u64			cpumask[MAX_CPUS / 64];
	u32			any_cpu;	/* any one allowed cpu */
	u32			dom_id;		/* the sq this task is bound to */
	u64			dom_mask;	/* the domains this task can run on */
	u64			prev_runtime;	/* used to calculate runtime delta */
	u64			dispatched_at;	/* timestamp of the last dispatch */
	u64			extra_runtime;	/* additional runtime to add to delta */

	struct ravg_data	load_data;
};

/* extl_sq private data */
struct sq_data {
	u64			vtime;
};

/*
 * Per-domain and per-cpu contexts
 */
struct dom_ctx dom_ctx[MAX_DOMS];
struct pcpu_ctx pcpu_ctx[MAX_CPUS];

/*
 * Statistics
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, FLAT_NR_STATS);
} stats SEC(".maps");

static void stat_add(enum stat_idx idx, u64 addend)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += addend;
}

/*
 * Load balance timer
 */
struct lb_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct lb_timer);
} lb_timer SEC(".maps");

static bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

s32 BPF_STRUCT_OPS(lflat_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct le_data *pled = (void *)p->scx.le->data;
	s32 cpu;

	/* if the previous CPU is idle, dispatch directly to it */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(FLAT_STAT_DIRECT_DISPATCH, 1);
		cpu = prev_cpu;
		goto local;
	}

	if (p->nr_cpus_allowed == 1)
		return pled->any_cpu;

	/* if any cpu is idle, dispatch directly to it */
	cpu = scx_bpf_pick_idle_cpu_untyped((unsigned long)pled->cpumask);
	if (cpu >= 0) {
		stat_add(FLAT_STAT_DIRECT_DISPATCH, 1);
		goto local;
	}

	return prev_cpu;

local:
	/* tell lflat_enqueue() that we already decided on local dispatching */
	pled->flags |= LE_LOCAL;
	return cpu;
}

/* @p is about to be enqueued and update its vtime */
static void refresh_vtime(struct task_struct *p)
{
	struct le_data *pled = (void *)p->scx.le->data;
	u64 weight = p->scx.weight;
	u64 runtime;

	/* how long has we run since the last enqueue? */
	runtime = p->se.sum_exec_runtime - pled->prev_runtime +
		pled->extra_runtime;
	if (!runtime)
		return;

	runtime = (runtime * 100 + weight - 1) / weight;

	pled->prev_runtime = p->se.sum_exec_runtime;
	pled->extra_runtime = 0;
	pled->vtime = pled->vtime + runtime;
}

/*
 * Record the dispatch timestamp and give it a new slice. Should be called on
 * every task which enters one of the dq's.
 */
static void update_dispatched(struct task_struct *p, u64 now)
{
	struct le_data *pled = (void *)p->scx.le->data;

	pled->dispatched_at = now;
	p->scx.slice = slice_us * 1000;
}

/* enqueue @p on its sq */
/*
 * XXX - verifier pukes w/ "At subprogram exit the register R0 is not a
 * scalar value (ptr_)" without always_inline
 */
static void inline __attribute((always_inline))
enqueue_task_to_sq(struct task_struct *p, u64 now)
{
	struct le_data *pled = (void *)p->scx.le->data;
	struct extl_sq *sq = extl_bpf_task_sq(p);
	struct sq_data *sqd = (void *)sq->data;
	u64 slice = slice_us * 1000;
	u64 min_vtime = sqd->vtime - (slice * sleep_boost_pct / 100);

	refresh_vtime(p);
	if (vtime_before(pled->vtime, min_vtime))
		pled->vtime = min_vtime;

	extl_bpf_enqueue_task(p, pled->vtime);
}

static void accumulate_load(struct ravg_data *load_data, u64 weight, u64 now)
{
	if (nr_doms > 1)
		ravg_accumulate(load_data, weight, now, load_hl);
}

s64 BPF_STRUCT_OPS(lflat_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct le_data *pled = (void *)p->scx.le->data;
	u64 now = bpf_ktime_get_ns();

	accumulate_load(&pled->load_data, p->scx.weight, now);

	/* did flat_select_cpu() already decide on local dispatching? */
	if (pled->flags & LE_LOCAL) {
		pled->flags &= ~LE_LOCAL;
		update_dispatched(p, now);
		return SCX_DQ_LOCAL;
	}

	/*
	 * When %current is runnable and the only task available for execution
	 * on the CPU, ext core would normally keep running it without invoking
	 * the bpf scheduler. We disabled this automatic last task dispatching
	 * by setting %SCX_OPS_ENQ_LAST primarily to monitor the event. If the
	 * task doesn't get dispatched to local, the CPU may stall.
	 */
	if (enq_flags & SCX_ENQ_LAST) {
		stat_add(FLAT_STAT_LAST_TASK, 1);
		update_dispatched(p, now);
		return SCX_DQ_LOCAL;
	}

	/*
	 * Once a task gets dispatched from its sq, we don't need it to go
	 * through full scheduling every time it goes to sleep and wakes up to
	 * maintain acceptable fairness. If the task has enough budget left and
	 * been last dispatched not too long ago, allow it to keep circulating
	 * in the dispatche queue.
	 */
	if (p->scx.slice > skip_enqueue_min_slice_us * 1000) {
		if (now - pled->dispatched_at < skip_enqueue_duration_us * 1000) {
			stat_add(FLAT_STAT_SKIP, 1);
			/*
			 * We're letting the task continue with the remaining
			 * budget from the last dispatching. Don't replenish it
			 * by calling update_dispatched().
			 */
			if (p->nr_cpus_allowed == 1)
				return SCX_DQ_LOCAL;
			else
				return pled->dom_id;
		} else {
			stat_add(FLAT_STAT_SKIP_EXPIRED, 1);
		}
	} else if (p->scx.slice) {
		stat_add(FLAT_STAT_SKIP_LOW_BUDGET, 1);
	} else {
		stat_add(FLAT_STAT_SLICE_DEPLETED, 1);
	}

	/* going to the sq to be ordered by vtime */
	extl_bpf_sq_lock_by_task(p);
	enqueue_task_to_sq(p, now);
	extl_bpf_sq_unlock();
	stat_add(FLAT_STAT_ENQUEUED, 1);
	return SCX_DQ_NONE;
}

void BPF_STRUCT_OPS(lflat_dequeue, struct task_struct *p, u64 deq_flags)
{
	extl_bpf_sq_lock_by_task(p);
	extl_bpf_dequeue_task(p);
	extl_bpf_sq_unlock();
	stat_add(FLAT_STAT_DEQUEUED, 1);
}

struct dispatch_ctx {
	struct extl_sq		*sq;		/* source sq */
	struct dom_ctx		*domc;
	u64			now;		/* current timestamp */
	bool			prev_runnable;	/* prev task is runnable */
	u64			prev_vtime;	/* prev task's vtime */

	s32			cpu;
	u32			dom_id;
	int			nr_dispatched;	/* total # dispatched */
	bool			dispatched_local; /* any of them local? */

	u64			lb_to_pull;
};

static s64 dispatch_verdict(struct dispatch_ctx *dspc, struct task_struct *p,
			    bool is_local)
{
	update_dispatched(p, dspc->now);
	dspc->nr_dispatched++;

	/*
	 * If we haven't dispatched any task to local yet and @p can run on the
	 * current CPU, dispatch to LOCAL. Otherwise, GLOBAL.
	 */
	if (!dspc->dispatched_local &&
	    (is_local || scx_bpf_cpumask_test_cpu(bpf_get_smp_processor_id(),
						  scx_bpf_task_cpumask(p)))) {
		dspc->dispatched_local = true;
		return SCX_DQ_LOCAL;
	} else {
		return dspc->dom_id;
	}
}

static int dispatch_loopfn(u32 idx, void *data)
{
	struct dispatch_ctx *dspc = data;
	struct le_data *sqd = (void *)dspc->sq->data;
	struct task_struct *p;
	struct le_data *pled;

	p = extl_bpf_sq_first_task(dspc->sq);
	if (!p)
		return 1;

	/*
	 * If the previous's vtime is before the first in sq, we should keep
	 * running the previous.
	 */
	pled = (void *)p->scx.le->data;
	if (dspc->prev_runnable && vtime_before(dspc->prev_vtime, pled->vtime))
		return 1;

	if (vtime_before(sqd->vtime, pled->vtime))
		sqd->vtime = pled->vtime;

	extl_bpf_dispatch_dequeue(p);
	scx_bpf_dispatch(p, dispatch_verdict(dspc, p, false));

	stat_add(FLAT_STAT_DISPATCHED, 1);

	/* gotta keep dispatching until the current CPU has something to run */
	if (!scx_bpf_dispatch_nr_slots() || dspc->dispatched_local)
		return 1;
	else
		return 0;
}

static u32 dom_rr_next(s32 cpu)
{
	if (cpu >= 0 && cpu < MAX_CPUS) {
		struct pcpu_ctx *pcpuc = &pcpu_ctx[cpu];
		u32 dom_id = (pcpuc->dom_rr_cur + 1) % nr_doms;

		if (dom_id == cpu_to_dom_id(cpu))
			dom_id = (dom_id + 1) % nr_doms;

		pcpuc->dom_rr_cur = dom_id;
		return dom_id;
	}
	return 0;
}

static int refresh_task_cpumask(u32 cpu, void *data)
{
	struct task_struct *p = *(void **)data;
	struct le_data *pled = (void *)p->scx.le->data;
	u32 dom_id = pled->dom_id;
	u64 mask = 1LLU << (cpu % 64);
	const volatile u64 *dptr;

	dptr = MEMBER_VPTR(dom_cpumasks, [dom_id][cpu / 64]);
	if (!dptr)
		return 1;
	if ((*dptr & mask) &&
	    scx_bpf_cpumask_test_cpu(cpu, scx_bpf_task_cpumask(p))) {
		u64 *cptr = MEMBER_VPTR(pled->cpumask, [cpu / 64]);
		if (!cptr)
			return 1;
		*cptr |= mask;
	} else {
		u64 *cptr = MEMBER_VPTR(pled->cpumask, [cpu / 64]);
		if (!cptr)
			return 1;
		*cptr &= ~mask;
	}
	return 0;
}

static void task_set_sq(struct task_struct *p, struct extl_sq *sq)
{
	struct le_data *pled = (void *)p->scx.le->data;
	struct le_data *sqd = (void *)sq->data;

	extl_bpf_set_task_sq(p, sq);
	pled->prev_runtime = p->se.sum_exec_runtime;
	/*
	 * Synchronize the vtime of the task being pulled to the local vtime.
	 * While this can be made more accurate, provided that the different
	 * domains are under similar pressures, this shouldn't affect @p's share
	 * noticeably as long as it doesn't keep getting bounced constantly.
	 */
	pled->vtime = sqd->vtime;
	pled->dom_id = sq->id;

	bpf_loop(nr_cpu_ids, refresh_task_cpumask, &p, 0);
}

static void dispatch_migrate_task(struct task_struct *p,
				  struct extl_sq *dst_sq,
				  struct extl_sq *src_sq,
				  u64 now)
{
	extl_bpf_dispatch_dequeue(p);
	task_set_sq(p, dst_sq);
}

static int lb_pull_one_loopfn(u32 idx, void *data)
{
	struct dispatch_ctx *dspc = data;
	u32 local_dom_id = dspc->dom_id;
	u32 remote_dom_id = dom_rr_next(dspc->cpu);
	struct extl_sq *local_sq = extl_bpf_find_sq(local_dom_id);
	struct extl_sq *remote_sq = extl_bpf_find_sq(remote_dom_id);
	u64 task_load;
	struct dom_ctx *local_domc, *remote_domc;
	struct le_data *pled;
	struct task_struct *p;

	if (local_dom_id >= MAX_DOMS || remote_dom_id >= MAX_DOMS)
		return 0;

	local_domc = &dom_ctx[local_dom_id];
	remote_domc = &dom_ctx[remote_dom_id];

	if (!remote_domc->load_to_give) {
		stat_add(FLAT_STAT_LB_PULL_CONFLICT, 1);
		return 0;
	}

	if (!remote_sq->nr_total_tasks) {
		stat_add(FLAT_STAT_LB_PULL_EMPTY, 1);
		return 0;
	}

	extl_bpf_sq_lock_double(local_sq, remote_sq);

	/*
	 * We're just gonna look at the first task and move onto the next domain
	 * if it can't be pulled. This is mostly because extl doesn't support
	 * proper iteration yet.
	 */
	p = extl_bpf_sq_first_task(remote_sq);
	if (!p) {
		stat_add(FLAT_STAT_LB_PULL_EMPTY, 1);
		goto out_unlock;
	}

	pled = (void *)p->scx.le->data;
	if (!(pled->dom_mask & (1LLU << local_dom_id))) {
		stat_add(FLAT_STAT_LB_PULL_AFFINITY, 1);
		goto out_unlock;
	}

	task_load = ravg_read(&pled->load_data, dspc->now, load_hl);

	/*
	 * We allow pulling over dspc->lb_to_pull as long as the task's load is
	 * below the total amount to be pulled. This is to avoid continuous
	 * scanning as lb_to_pull gradually increases during the slice. As we
	 * can't target the perfect balance anyway, the limited overshoot this
	 * can cause shouldn't make noticeable difference.
	 */
	if (task_load > remote_domc->load_to_give ||
	    task_load > local_domc->load_to_pull) {
		stat_add(FLAT_STAT_LB_PULL_LOW, 1);
		goto out_unlock;
	}
	remote_domc->load_to_give -= task_load;
	local_domc->load_pulled += task_load;

	dispatch_migrate_task(p, local_sq, remote_sq, dspc->now);

	scx_bpf_dispatch(p, dispatch_verdict(dspc, p, false));
	stat_add(FLAT_STAT_LB_PULL, 1);

out_unlock:
	extl_bpf_sq_unlock_double();
	return dspc->lb_to_pull <= local_domc->load_pulled ||
		!scx_bpf_dispatch_nr_slots();
}

static int lb_pull_loopfn(s32 idx, void *data)
{
	struct dispatch_ctx *dspc = data;
	struct dom_ctx *domc = dspc->domc;

	if (dspc->lb_to_pull > domc->load_pulled) {
		u64 last_pulled = domc->load_pulled;

		bpf_loop(nr_doms - 1, lb_pull_one_loopfn, dspc, 0);

		/* terminate if nothing could be pulled */
		return domc->load_pulled == last_pulled ||
			!scx_bpf_dispatch_nr_slots();
	} else {
		return 1;
	}
}

static int idle_pull_loopfn(s32 idx, void *data)
{
	struct dispatch_ctx *dspc = data;
	u32 local_dom_id = dspc->dom_id;
	u32 remote_dom_id = dom_rr_next(dspc->cpu);
	struct extl_sq *local_sq = extl_bpf_find_sq(local_dom_id);
	struct extl_sq *remote_sq = extl_bpf_find_sq(remote_dom_id);
	struct dom_ctx *remote_domc;
	struct task_struct *p;
	int ret = 0;

	if (remote_dom_id >= MAX_DOMS)
		return 0;

	remote_domc = &dom_ctx[remote_dom_id];

	/* if remote is pulling tasks for load balancing, don't fight it */
	if (remote_domc->load_to_pull) {
		stat_add(FLAT_STAT_IDLE_PULL_CONFLICT, 1);
		return 0;
	}

	if (!remote_sq->nr_total_tasks) {
		stat_add(FLAT_STAT_IDLE_PULL_EMPTY, 1);
		return 0;
	}

	extl_bpf_sq_lock_double(local_sq, remote_sq);

	/*
	 * We're just gonna look at the first task and move onto the next domain
	 * if it can't be pulled. This is mostly because extl doesn't support
	 * proper iteration yet.
	 */
	p = extl_bpf_sq_first_task(remote_sq);
	if (!p) {
		stat_add(FLAT_STAT_IDLE_PULL_EMPTY, 1);
		goto out_unlock;
	}

	if (!scx_bpf_cpumask_test_cpu(dspc->cpu, scx_bpf_task_cpumask(p))) {
		stat_add(FLAT_STAT_IDLE_PULL_AFFINITY, 1);
		goto out_unlock;
	}

	dispatch_migrate_task(p, local_sq, remote_sq, dspc->now);

	scx_bpf_dispatch(p, dispatch_verdict(dspc, p, true));
	stat_add(FLAT_STAT_IDLE_PULL, 1);

	ret = dspc->dispatched_local || !scx_bpf_dispatch_nr_slots();
out_unlock:
	extl_bpf_sq_unlock_double();
	return ret;
}

int BPF_STRUCT_OPS(lflat_dispatch, s32 cpu, struct task_struct *prev)
{
	struct dispatch_ctx dspc = {
		.cpu = cpu,
		.dom_id = cpu_to_dom_id(cpu),
		.now = bpf_ktime_get_ns()
	};
	u32 lb_seq;
	s64 progress;

	/*
	 * If @prev is still runnable, remember its vtime and use it to decide
	 * whether to dispatch a new task or keep running @prev.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		struct le_data *ppled = (void *)prev->scx.le->data;

		refresh_vtime(prev);
		dspc.prev_runnable = true;
		dspc.prev_vtime = ppled->vtime;
	}

	if (dspc.dom_id >= MAX_DOMS)
		return -ESRCH;
	dspc.domc = &dom_ctx[dspc.dom_id];

	dspc.sq = extl_bpf_find_sq(dspc.dom_id);
	if (!dspc.sq)
		return -ESRCH;

	extl_bpf_sq_lock(dspc.sq);
	bpf_loop(1 << 23, dispatch_loopfn, &dspc, 0);
	extl_bpf_sq_unlock();

	if (nr_doms <= 1 || !scx_bpf_dispatch_nr_slots())
		return 0;

	/* do load balancing pulls */
	progress = dspc.now - lb_timer_at;
	lb_seq = dspc.domc->lb_seq++;
	if (progress > 0 &&
	    !(lb_seq & ((1LLU << dspc.domc->lb_cadence_shift) - 1))) {
		u64 last_pulled = dspc.domc->load_pulled;

		if (progress > LB_INTERVAL_NS)
			progress = LB_INTERVAL_NS;

		dspc.lb_to_pull =
			dspc.domc->load_to_pull * progress / LB_INTERVAL_NS;
		bpf_loop(1024, lb_pull_loopfn, &dspc, 0);

		if (dspc.domc->load_pulled == last_pulled)
			dspc.domc->lb_cadence_shift++;
		else
			dspc.domc->lb_cadence_shift = 0;
	} else {
		stat_add(FLAT_STAT_LB_PULL_SKIP, 1);
	}

	/* if we still don't have a task to run, try pulling from another pool */
	if (!dspc.prev_runnable && !dspc.dispatched_local &&
	    scx_bpf_dispatch_nr_slots())
		bpf_loop(nr_doms - 1, idle_pull_loopfn, &dspc, 0);

	return 0;
}

static int greedy_loopfn(s32 idx, void *data)
{
	u32 dom_id = dom_rr_next(*(s32 *)data);

	if (scx_bpf_dq_nr_queued(dom_id) > greedy_threshold &&
	    scx_bpf_consume(dom_id)) {
		stat_add(FLAT_STAT_GREEDY, 1);
		return 1;
	} else {
		return 0;
	}
}

void BPF_STRUCT_OPS(lflat_consume, s32 cpu)
{
	scx_bpf_consume(cpu_to_dom_id(cpu));
}

void BPF_STRUCT_OPS(lflat_consume_final, s32 cpu)
{
	if (greedy_threshold != (u64)-1)
		bpf_loop(nr_doms - 1, greedy_loopfn, &cpu, 0);
}

static void update_cpu_load_weight_sum(u64 cpu, s32 weight_delta, u64 now)
{
	if (cpu < MAX_CPUS) {
		struct pcpu_ctx *pcpuc = &pcpu_ctx[cpu];

		accumulate_load(&pcpuc->load_data,
				pcpuc->load_data.val + weight_delta, now);
	}
}

void BPF_STRUCT_OPS(lflat_runnable, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);
	u64 now = bpf_ktime_get_ns();

	if (cpu >= nr_cpu_ids)
		nr_cpu_ids = cpu + 1;

	update_cpu_load_weight_sum(cpu, p->scx.weight, now);
}

void BPF_STRUCT_OPS(lflat_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct le_data *pled = (void *)p->scx.le->data;
	u64 cpu = scx_bpf_task_cpu(p);
	u64 now = bpf_ktime_get_ns();

	/* update the load */
	update_cpu_load_weight_sum(cpu, -p->scx.weight, now);
	accumulate_load(&pled->load_data, 0, now);

	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;
}

bool BPF_STRUCT_OPS(lflat_yield, struct task_struct *from, struct task_struct *to)
{
	struct le_data *pled = (void *)from->scx.le->data;

	if (to)
		return false;

	/* pretend that we consumed all of our slice */
	pled->extra_runtime = from->scx.slice;
	from->scx.slice = 0;
	return true;
}

struct cpumask_intersects_domain_loop_ctx {
	const struct cpumask	*cpumask;
	u32			dom_id;
	bool			ret;
};

static int cpumask_intersects_domain_loopfn(u32 idx, void *data)
{
	struct cpumask_intersects_domain_loop_ctx *lctx = data;

	if (scx_bpf_cpumask_test_cpu(idx, lctx->cpumask) &&
	    is_cpu_in_dom(idx, lctx->dom_id)) {
		lctx->ret = true;
		return 1;
	}
	return 0;
}

static bool cpumask_intersects_domain(const struct cpumask *cpumask, u32 dom_id)
{
	struct cpumask_intersects_domain_loop_ctx lctx = {
		.cpumask = cpumask,
		.dom_id = dom_id,
		.ret = false,
	};

	bpf_loop(nr_cpu_ids, cpumask_intersects_domain_loopfn, &lctx, 0);
	return lctx.ret;
}

struct pick_task_domain_loop_ctx {
	struct task_struct	*p;
	const struct cpumask	*cpumask;
	u64			dom_mask;
	u32			dom_rr_base;
	u32			any_dom_id;
	u32			best_dom_id;
};

static int pick_task_domain_loopfn(u32 idx, void *data)
{
	struct pick_task_domain_loop_ctx *lctx = data;
	u32 dom_id = (lctx->dom_rr_base + idx) % nr_doms;
	struct dom_ctx *domc;

	if (dom_id >= MAX_DOMS)
		return 1;
	domc = &dom_ctx[dom_id];

	if (cpumask_intersects_domain(lctx->cpumask, dom_id)) {
		lctx->dom_mask |= 1LLU << dom_id;
		if (lctx->any_dom_id == MAX_DOMS)
			lctx->any_dom_id = dom_id;
		if (lctx->best_dom_id == MAX_DOMS && domc->load_to_pull) {
			lctx->best_dom_id = dom_id;
			return 1;
		}
	}
	return 0;
}

static u32 pick_task_domain(struct task_struct *p, const struct cpumask *cpumask)
{
	struct pick_task_domain_loop_ctx lctx = {
		.p = p,
		.cpumask = cpumask,
		.any_dom_id = MAX_DOMS,
		.best_dom_id = MAX_DOMS,
	};
	s32 cpu = bpf_get_smp_processor_id();
	struct le_data *pled = (void *)p->scx.le->data;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return MAX_DOMS;

	lctx.dom_rr_base = ++(pcpu_ctx[cpu].dom_rr_cur);

	bpf_loop(nr_doms, pick_task_domain_loopfn, &lctx, 0);
	pled->dom_mask = lctx.dom_mask;

	if (lctx.best_dom_id != MAX_DOMS)
		return lctx.best_dom_id;
	else
		return lctx.any_dom_id;
}

static void task_set_domain(struct task_struct *p, const struct cpumask *cpumask)
{
	struct le_data *pled = (void *)p->scx.le->data;
	struct extl_sq *sq;
	u32 dom_id = 0;

	pled->any_cpu = scx_bpf_cpumask_first(cpumask);

	if (nr_doms > 1)
		dom_id = pick_task_domain(p, cpumask);

	sq = extl_bpf_find_sq(dom_id);
	if (sq) {
		extl_bpf_sq_lock_double_by_task(p, sq);
		task_set_sq(p, sq);
		extl_bpf_sq_unlock_double();
	} else {
		pled->dom_id = MAX_DOMS;
	}
}

void BPF_STRUCT_OPS(lflat_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	task_set_domain(p, cpumask);
}

void BPF_STRUCT_OPS(lflat_enable, struct task_struct *p)
{
	task_set_domain(p, scx_bpf_task_cpumask(p));
}

struct lb_load_sum_ctx {
	u32		dom_id;
	u64		now;
	u64		load_sum;
};

static int lb_refresh_cpu_load_loopfn(u64 cpu, void *data)
{
	struct lb_load_sum_ctx *sctx = data;

	if (cpu < MAX_CPUS && is_cpu_in_dom(cpu, sctx->dom_id)) {
		struct pcpu_ctx *pcpuc = &pcpu_ctx[cpu];

		pcpuc->load = ravg_read(&pcpuc->load_data, sctx->now, load_hl);
		sctx->load_sum += pcpuc->load;
	}
	return 0;
}

static int lb_dom_load_loopfn(u32 idx, void *data)
{
	struct lb_load_sum_ctx sctx = { .dom_id = idx, .now = lb_timer_at };

	bpf_loop(nr_cpu_ids, lb_refresh_cpu_load_loopfn, &sctx, 0);
	if (idx < MAX_DOMS) {
		struct dom_ctx *domc = &dom_ctx[idx];

		domc->load = sctx.load_sum;
		global_load_sum += sctx.load_sum;
	}

	return 0;
}

static int lb_dom_load_balance_target_loopfn(u32 idx, void *data)
{
	if (idx < MAX_DOMS) {
		struct dom_ctx *domc = &dom_ctx[idx];
		u64 low = global_load_avg * load_imbal_low_pct / 100;
		u64 high = global_load_avg * load_imbal_high_pct / 100;
		u64 adj_max = global_load_avg * load_imbal_max_adj_pct / 100;
		s64 imbal = domc->load - global_load_avg;
		u64 to_pull;

		domc->lb_cadence_shift = 0;
		domc->load_to_pull = 0;
		domc->load_pulled = 0;
		domc->load_to_give = 0;

		if (imbal >= 0) {
			domc->load_to_give = imbal;
			return 0;
		}

		imbal = -imbal;
		if (imbal <= high)
			return 0;

		to_pull = imbal - low;
		if (to_pull > adj_max)
			to_pull = adj_max;

		domc->load_to_pull = to_pull;
	}

	return 0;
}

static int lb_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	if (timer_kill) {
		timer_running = 0;
		return 0;
	}

	lb_timer_at = bpf_ktime_get_ns();

	global_load_sum = 0;
	bpf_loop(nr_doms, lb_dom_load_loopfn, NULL, 0);
	global_load_avg = global_load_sum / nr_doms;

	bpf_loop(nr_doms, lb_dom_load_balance_target_loopfn, NULL, 0);

	bpf_timer_start(timer, LB_INTERVAL_NS, 0);
	return 0;
}

static int lb_timer_init(void)
{
	u32 key = 0;
	struct bpf_timer *timer;
	int ret;

	timer = bpf_map_lookup_elem(&lb_timer, &key);
	if (!timer)
		return -ESRCH;

	bpf_timer_init(timer, &lb_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, lb_timer_cb);
	ret = bpf_timer_start(timer, LB_INTERVAL_NS, 0);
	timer_running = !ret;
	return ret;
}

static int init_domain_loopfn(u32 idx, void *data)
{
	struct extl_sq *sq;
	struct sq_data *sqd;
	int ret;

	sq = extl_bpf_create_sq(idx);
	if (!sq) {
		*(int *)data = -EINVAL;
		return 1;
	}

	ret = scx_bpf_create_dq(idx, -1);
	if (ret) {
		*(int *)data = ret;
		return 1;
	}

	sqd = (void *)sq->data;
	sqd->vtime = slice_us * 1000;
	return 0;
}

int BPF_STRUCT_OPS(lflat_init)
{
	int ret;

	ret = extl_bpf_init(sizeof(struct le_data), sizeof(struct sq_data));
	if (ret)
		return ret;

	bpf_loop(nr_doms, init_domain_loopfn, &ret, 0);
	if (ret)
		return ret;

	if (nr_doms > 1) {
		ret = lb_timer_init();
		if (ret)
			return ret;
	}

	return extl_bpf_enable();
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

void BPF_STRUCT_OPS(lflat_exit, struct scx_ops_exit_info *ei)
{
	u64 expiration = bpf_ktime_get_ns() + 1000 * MS_TO_NS;

	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_type = ei->type;

	/*
	 * XXX - We just need to make sure that the timer body isn't running on
	 * exit. If we catch the timer while waiting, great. If not, it's still
	 * highly likely that the timer body won't run in the future. Once bpf
	 * can shut down associated timers, this hackery should go away.
	 */
	timer_kill = 1;
	bpf_loop(1 << 23, exit_wait_timer_loopfn, &expiration, 0);
}

SEC(".struct_ops")
struct sched_ext_ops lflat_ops = {
	.select_cpu		= (void *)lflat_select_cpu,
	.enqueue		= (void *)lflat_enqueue,
	.dequeue		= (void *)lflat_dequeue,
	.dispatch		= (void *)lflat_dispatch,
	.consume		= (void *)lflat_consume,
	.consume_final		= (void *)lflat_consume_final,
	.runnable		= (void *)lflat_runnable,
	.quiescent		= (void *)lflat_quiescent,
	.yield			= (void *)lflat_yield,
	.set_cpumask		= (void *)lflat_set_cpumask,
	.enable			= (void *)lflat_enable,
	.init			= (void *)lflat_init,
	.exit			= (void *)lflat_exit,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	.name			= "lflat",
};
