/* SPDX-License-Identifier: GPL-2.0 */
/*
 * As described in [0], a Nest scheduler which encourages task placement on
 * cores that are likely to be running at higher frequency, based upon recent usage.
 *
 * [0]: https://hal.inria.fr/hal-03612592/file/paper.pdf
 *
 * It operates as a global weighted vtime scheduler (similarly to CFS), while
 * using the Nest algorithm to choose idle cores at wakup time.
 *
 * It also demonstrates the following niceties.
 *
 * - More robust task placement policies.
 * - Termination notification for userspace.
 *
 * While rather simple, this scheduler should work reasonably well on CPUs with
 * a uniform L3 cache topology. While preemption is not implemented, the fact
 * that the scheduling queue is shared across all CPUs means that whatever is
 * at the front of the queue is likely to be executed fairly quickly given
 * enough number of CPUs.
 *
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include "scx_common.bpf.h"
#include "vmlinux.h"
#include "scx_nest.h"

char _license[] SEC("license") = "GPL";

enum {
	FALLBACK_DSQ_ID		= 0,
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC		= USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC		= USEC_PER_MSEC * MSEC_PER_SEC,
};

#define CLOCK_BOOTTIME 7
#define NUMA_NO_NODE -1

const volatile u64 p_remove_ns = 2 * NSEC_PER_MSEC;
const volatile u64 r_max = 5;
const volatile u64 r_impatient = 2;
const volatile u64 slice_ns = SCX_SLICE_DFL;

static s32 nr_reserved;

static u64 vtime_now;
struct user_exit_info uei;

extern unsigned long CONFIG_HZ __kconfig;

/* Per-task scheduling context */
struct task_ctx {
	/*
	 * A temporary cpumask for calculating a task's primary and reserve
	 * mask.
	 */
	struct bpf_cpumask __kptr *tmp_mask;

	/*
	 * The number of times that a task observes that its previous core is
	 * not idle. If this occurs r_impatient times in a row, a core is
	 * attempted to be retrieved from either the reserve nest, or the
	 * fallback nest.
	 */
	u32 prev_misses;

	/* Dispatch directly to local_dsq */
	bool force_local;

	/* This task promoted a core to the primary nest. */
	bool promoted;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct pcpu_ctx {
	u64 touched;
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, s32);
	__type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");

const volatile u32 nr_cpus = 1; /* !0 for veristat, set during init. */

private(NESTS) struct bpf_cpumask __kptr *primary_cpumask;
private(NESTS) struct bpf_cpumask __kptr *reserve_cpumask;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, NR_STATS);
} stats SEC(".maps");


static __attribute__((always_inline)) void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static u64 jiffies_to_usecs(u64 jiffies)
{
	return jiffies * (USEC_PER_SEC / CONFIG_HZ);
}

static u64 jiffies_to_nsecs(u64 jiffies)
{
	return jiffies_to_usecs(jiffies) * NSEC_PER_USEC;
}

static u64 curr_ns(void)
{
	return jiffies_to_nsecs(bpf_jiffies64());
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static const struct cpumask *cast_mask(struct bpf_cpumask *mask)
{
	return (const struct cpumask *)mask;
}

static  __attribute__((always_inline)) void
try_make_core_reserved(s32 cpu, struct bpf_cpumask * reserved, bool promotion)
{
	s32 tmp_nr_reserved;

	/*
	 * This check is racy, but that's OK. If we incorrectly fail to promote
	 * a core to reserve, it's because another context added or removed a
	 * core from reserved in this small window. It will balance out over
	 * subsequent wakeups.
	 */
	tmp_nr_reserved = nr_reserved;
	if (tmp_nr_reserved < r_max) {
		if (__sync_bool_compare_and_swap(&nr_reserved,
					tmp_nr_reserved,
					tmp_nr_reserved + 1)) {
			bpf_cpumask_set_cpu(cpu, reserved);
			if (promotion)
				stat_inc(NEST_STAT(PROMOTED_TO_RESERVED));
			else
				stat_inc(NEST_STAT(DEMOTED_TO_RESERVED));
		} else {
			if (promotion)
				stat_inc(NEST_STAT(PROMOTE_RESERVE_CONTENDED));
			else
				stat_inc(NEST_STAT(DEMOTE_RESERVE_CONTENDED));
		}
	} else {
		stat_inc(NEST_STAT(RESERVED_AT_CAPACITY));
	}
}

s32 BPF_STRUCT_OPS(nest_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct bpf_cpumask *p_mask, *primary, *reserve;
	const struct cpumask *idle_smtmask;
	s32 cpu;
	struct task_ctx *tctx;
	struct pcpu_ctx *pcpu_ctx;
	bool prev_fully_idle, prev_in_primary;
	bool direct_to_primary = false;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return -ENOENT;

	bpf_rcu_read_lock();
	p_mask = tctx->tmp_mask;
	primary = primary_cpumask;
	reserve = reserve_cpumask;
	if (!p_mask || !primary || !reserve) {
		bpf_rcu_read_unlock();
		return -ENOENT;
	}

	// Unset below if we can't find a core to migrate to.
	tctx->force_local = true;

	idle_smtmask = scx_bpf_get_idle_smtmask();
	prev_fully_idle = bpf_cpumask_test_cpu(prev_cpu, idle_smtmask);
	scx_bpf_put_idle_cpumask(idle_smtmask);

	bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(primary));
	prev_in_primary = bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_mask));

	/*
	 * First try to stay on current core if it's in the primary set, and
	 * there's no hypertwin.
	 */
	if (prev_in_primary && prev_fully_idle &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		tctx->prev_misses = 0;
		stat_inc(NEST_STAT(WAKEUP_PREV_PRIMARY));
		goto migrate_primary;
	}

	if (r_impatient > 0 && ++tctx->prev_misses >= r_impatient) {
		direct_to_primary = true;
		stat_inc(NEST_STAT(TASK_IMPATIENT));
		goto search_reserved;
	}

	/* Then try any fully idle core in primary. */
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), SCX_PICK_IDLE_CORE);
	if (cpu >= 0) {
		stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_PRIMARY));
		goto migrate_primary;
	}

	/* Then try _any_ idle core in primary, even if its hypertwin is active. */
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
	if (cpu >= 0) {
		stat_inc(NEST_STAT(WAKEUP_HT_IDLE_PRIMARY));
		goto migrate_primary;
	}

search_reserved:
	/* Then try any fully idle core in reserve. */
	bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(reserve));
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), SCX_PICK_IDLE_CORE);
	if (cpu >= 0) {
		stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_RESERVE));
		goto promote_to_primary;
	}

	/* Then try _any_ idle core in reserve, even if its hypertwin is active. */
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
	if (cpu >= 0) {
		stat_inc(NEST_STAT(WAKEUP_HT_IDLE_RESERVE));
		goto promote_to_primary;
	}

	/* Then try _any_ idle core in the task's cpumask. */
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0) {
		/*
		 * Try to promote the current core to reserved. Do one extra
		 * double check that it's not in the primary or reserved
		 * cpumask before moving it into reserved, as we could
		 * potentially race with checking primary and reserve above.
		 */
		stat_inc(NEST_STAT(WAKEUP_IDLE_OTHER));
		if (!bpf_cpumask_test_cpu(cpu, cast_mask(primary)) &&
		    !bpf_cpumask_test_cpu(cpu, cast_mask(reserve))) {
			if (direct_to_primary)
				goto promote_to_primary;
			else
				try_make_core_reserved(cpu, reserve, true);
		}
		bpf_rcu_read_unlock();
		return cpu;
	}

	bpf_rcu_read_unlock();
	tctx->force_local = false;
	return prev_cpu;

promote_to_primary:
	bpf_cpumask_set_cpu(cpu, primary);
	/*
	 * Do one final check to make sure the CPU is still in reserved, as
	 * someone else could have theoretically come in, used it, and promoted
	 * it to primary between our initial primary check, and when we
	 * eventually are able to reserve it from the ext.c idle mask.
	 */
	tctx->promoted = true;
	if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve))) {
		__sync_sub_and_fetch(&nr_reserved, 1);
		bpf_cpumask_clear_cpu(cpu, reserve);
	}
	stat_inc(NEST_STAT(PROMOTED_TO_PRIMARY));
migrate_primary:
	pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
	if (pcpu_ctx)
		pcpu_ctx->touched = curr_ns();
	else
		scx_bpf_error("Failed to lookup pcpu ctx");
	if (!tctx->promoted)
		stat_inc(NEST_STAT(RENEWED_IN_PRIMARY));
	bpf_rcu_read_unlock();
	return cpu;
}

void BPF_STRUCT_OPS(nest_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	struct pcpu_ctx *pcpu_ctx;
	u64 vtime = p->scx.dsq_vtime;
	s32 cpu;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Unable to find task ctx");
		return;
	}

	if (tctx->promoted) {
		cpu = bpf_get_smp_processor_id();
		pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
		if (!pcpu_ctx) {
			scx_bpf_error("Unable to find pcpu_ctx");
			return;
		}
		/*
		 * The core is still primary. Don't remove it, and schedule
		 * another timer to check in timeout + 1us.
		 */
		bpf_timer_start(&pcpu_ctx->timer, p_remove_ns + 1000,
				BPF_F_TIMER_CPU_PIN);
		tctx->promoted = false;
	}

	if (tctx->force_local) {
		tctx->force_local = false;
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (vtime_before(vtime, vtime_now - slice_ns))
		vtime = vtime_now - slice_ns;

	scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns, vtime,
			       enq_flags);
}

void BPF_STRUCT_OPS(nest_dispatch, s32 cpu, struct task_struct *prev)
{
	struct pcpu_ctx *pcpu_ctx;
	struct bpf_cpumask *primary;
	s32 key = cpu;

	if (!scx_bpf_consume(FALLBACK_DSQ_ID)) {
		stat_inc(NEST_STAT(NOT_CONSUMED));
		return;
	}

	stat_inc(NEST_STAT(CONSUMED));
	primary = primary_cpumask;
	if (!primary) {
		scx_bpf_error("No primary cpumask");
		return;
	}

	/*
	 * If we're in the primary nest, signal that we were able to find a
	 * task to run by resetting last touched.
	 */
	if (bpf_cpumask_test_cpu(cpu, cast_mask(primary))) {
		pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);
		if (pcpu_ctx) {
			pcpu_ctx->touched = curr_ns();
			stat_inc(NEST_STAT(RENEWED_IN_PRIMARY));
		} else {
			scx_bpf_error("Failed to lookup pcpu ctx");
		}
	}
}

void BPF_STRUCT_OPS(nest_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(nest_stopping, struct task_struct *p, bool runnable)
{
	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;
}

s32 BPF_STRUCT_OPS(nest_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(&tctx->tmp_mask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

void BPF_STRUCT_OPS(nest_enable, struct task_struct *p,
		    struct scx_enable_args *args)
{
	p->scx.dsq_vtime = vtime_now;
}

static int check_primary_remove(void *map, int *key, struct bpf_timer *timer)
{
	u64 curr, delta;
	struct pcpu_ctx *pcpu_ctx;
	struct bpf_cpumask *primary, *reserve;
	s32 cpu = bpf_get_smp_processor_id();

	pcpu_ctx = bpf_map_lookup_elem(map, key);
	if (!pcpu_ctx) {
		scx_bpf_error("Couldn't find pcpu ctx");
		return 0;
	}

	curr = curr_ns();
	if (curr < pcpu_ctx->touched) {
		scx_bpf_error("Time moved backwards (curr %llu, touched %llu)",
			      curr, pcpu_ctx->touched);
		return 0;
	}

	delta = curr - pcpu_ctx->touched;
	if (delta >= p_remove_ns) {
		/*
		 * It's time to demote the core. Remove it from the primary
		 * cpumask and don't schedule another timer.
		 */
		bpf_rcu_read_lock();
		primary = primary_cpumask;
		reserve = reserve_cpumask;
		if (!primary || !reserve) {
			scx_bpf_error("Couldn't find primary or reserve");
			bpf_rcu_read_unlock();
			return 0;
		}

		bpf_cpumask_clear_cpu(cpu, primary);
		try_make_core_reserved(cpu, reserve, false);
		bpf_rcu_read_unlock();
	} else {
		/*
		 * The core is still primary. Don't remove it, and schedule
		 * another timer to check in timeout + 1us.
		 */
		bpf_timer_start(&pcpu_ctx->timer, p_remove_ns + 1000,
				BPF_F_TIMER_CPU_PIN);
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(nest_init)
{
	struct bpf_cpumask *cpumask;
	s32 cpu;
	int err;

	scx_bpf_switch_all();

	err = scx_bpf_create_dsq(FALLBACK_DSQ_ID, NUMA_NO_NODE);
	if (err) {
		scx_bpf_error("Failed to create fallback DSQ");
		return err;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	bpf_cpumask_clear(cpumask);
	cpumask = bpf_kptr_xchg(&primary_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	bpf_cpumask_clear(cpumask);
	cpumask = bpf_kptr_xchg(&reserve_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	bpf_for(cpu, 0, nr_cpus) {
		s32 key = cpu;
		struct pcpu_ctx *ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);

		if (!ctx) {
			scx_bpf_error("Failed to lookup pcpu_ctx");
			return -ENOENT;
		}
		ctx->touched = 0;
		if (bpf_timer_init(&ctx->timer, &pcpu_ctxs, CLOCK_BOOTTIME)) {
			scx_bpf_error("Failed to initialize pcpu timer");
			return -EINVAL;
		}
		bpf_timer_set_callback(&ctx->timer, check_primary_remove);
	}

	return 0;
}

void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops nest_ops = {
	.select_cpu		= (void *)nest_select_cpu,
	.enqueue		= (void *)nest_enqueue,
	.dispatch		= (void *)nest_dispatch,
	.running		= (void *)nest_running,
	.stopping		= (void *)nest_stopping,
	.prep_enable		= (void *)nest_prep_enable,
	.enable			= (void *)nest_enable,
	.init			= (void *)nest_init,
	.exit			= (void *)nest_exit,
	.name			= "nest",
};
