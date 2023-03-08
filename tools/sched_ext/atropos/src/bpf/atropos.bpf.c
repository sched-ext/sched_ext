// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
//
// Atropos is a multi-domain BPF / userspace hybrid scheduler where the BPF
// part does simple round robin in each domain and the userspace part
// calculates the load factor of each domain and tells the BPF part how to load
// balance the domains.
//
// Every task has an entry in the task_data map which lists which domain the
// task belongs to. When a task first enters the system (atropos_prep_enable),
// they are round-robined to a domain.
//
// atropos_select_cpu is the primary scheduling logic, invoked when a task
// becomes runnable. The lb_data map is populated by userspace to inform the BPF
// scheduler that a task should be migrated to a new domain. Otherwise, the task
// is scheduled in priority order as follows:
// * The current core if the task was woken up synchronously and there are idle
//   cpus in the system
// * The previous core, if idle
// * The pinned-to core if the task is pinned to a specific core
// * Any idle cpu in the domain
//
// If none of the above conditions are met, then the task is enqueued to a
// dispatch queue corresponding to the domain (atropos_enqueue).
//
// atropos_dispatch will attempt to consume a task from its domain's
// corresponding dispatch queue (this occurs after scheduling any tasks directly
// assigned to it due to the logic in atropos_select_cpu). If no task is found,
// then greedy load stealing will attempt to find a task on another dispatch
// queue to run.
//
// Load balancing is almost entirely handled by userspace. BPF populates the
// task weight, dom mask and current dom in the task_data map and executes the
// load balance based on userspace populating the lb_data map.
#include "../../../scx_common.bpf.h"
#include "atropos.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * const volatiles are set during initialization and treated as consts by the
 * jit compiler.
 */

/*
 * Domains and cpus
 */
const volatile __u32 nr_doms;
const volatile __u32 nr_cpus;
const volatile __u32 cpu_dom_id_map[MAX_CPUS];
const volatile __u64 dom_cpumasks[MAX_DOMS][MAX_CPUS / 64];

const volatile bool switch_partial;
const volatile __u32 greedy_threshold;

/* base slice duration */
const volatile __u64 slice_us = 20000;

/*
 * Exit info
 */
int exit_type = SCX_EXIT_NONE;
char exit_msg[SCX_EXIT_MSG_LEN];

struct pcpu_ctx {
	__u32 dom_rr_cur; /* used when scanning other doms */

	/* libbpf-rs does not respect the alignment, so pad out the struct explicitly */
	__u8 _padding[CACHELINE_SIZE - sizeof(u64)];
} __attribute__((aligned(CACHELINE_SIZE)));

struct pcpu_ctx pcpu_ctx[MAX_CPUS];

struct dom_cpumask {
	struct bpf_cpumask __kptr *cpumask;
};

/*
 * Domain cpumasks
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct dom_cpumask);
	__uint(max_entries, MAX_DOMS);
	__uint(map_flags, 0);
} dom_cpumask_map SEC(".maps");

/*
 * Statistics
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, ATROPOS_NR_STATS);
} stats SEC(".maps");

static inline void stat_add(enum stat_idx idx, u64 addend)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += addend;
}

// Map pid -> task_ctx
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, struct task_ctx);
	__uint(max_entries, 1000000);
	__uint(map_flags, 0);
} task_data SEC(".maps");

// This is populated from userspace to indicate which pids should be reassigned
// to new doms
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, u32);
	__uint(max_entries, 1000);
	__uint(map_flags, 0);
} lb_data SEC(".maps");

struct refresh_task_cpumask_loop_ctx {
	struct task_struct *p;
	struct task_ctx *ctx;
};

static bool task_set_dsq(struct task_ctx *task_ctx, struct task_struct *p,
			 u32 dom_id)
{
	struct dom_cpumask *dom_cpumask;
	struct bpf_cpumask *d_cpumask, *t_cpumask;
	bool has_cpus;

	dom_cpumask = bpf_map_lookup_elem(&dom_cpumask_map, &dom_id);
	if (!dom_cpumask) {
		scx_bpf_error("Failed to look up domain %u cpumask", dom_id);
		return false;
	}

	d_cpumask = bpf_cpumask_kptr_get(&dom_cpumask->cpumask);
	if (!d_cpumask) {
		scx_bpf_error("Failed to get domain %u cpumask kptr", dom_id);
		return false;
	}

	t_cpumask = bpf_cpumask_kptr_get(&task_ctx->cpumask);
	if (!t_cpumask) {
		scx_bpf_error("Failed to look up task cpumask");
		bpf_cpumask_release(d_cpumask);
		return false;
	}

	/*
	 * set_cpumask might have happened between userspace requesting LB and
	 * here and @p might not be able to run in @dom_id anymore. Verify.
	 */
	if (bpf_cpumask_intersects((const struct cpumask *)d_cpumask,
				   p->cpus_ptr)) {
		task_ctx->dom_id = dom_id;
		bpf_cpumask_and(t_cpumask, (const struct cpumask *)d_cpumask,
				p->cpus_ptr);
	}

	bpf_cpumask_release(d_cpumask);
	bpf_cpumask_release(t_cpumask);

	return task_ctx->dom_id == dom_id;
}

s32 BPF_STRUCT_OPS(atropos_select_cpu, struct task_struct *p, int prev_cpu,
		   u32 wake_flags)
{
	s32 cpu;
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);
	struct bpf_cpumask *p_cpumask;

	if (!task_ctx)
		return -ENOENT;

	/*
	 * If WAKE_SYNC and the machine isn't fully saturated, wake up @p to the
	 * local dsq of the waker.
	 */
	if (p->nr_cpus_allowed > 1 && (wake_flags & SCX_WAKE_SYNC)) {
		struct task_struct *current = (void *)bpf_get_current_task();

		if (!(BPF_CORE_READ(current, flags) & PF_EXITING) &&
		    task_ctx->dom_id < MAX_DOMS) {
			struct dom_cpumask *dmask_wrapper;
			struct bpf_cpumask *d_cpumask;
			const struct cpumask *idle_cpumask;
			bool has_idle;

			dmask_wrapper = bpf_map_lookup_elem(&dom_cpumask_map, &task_ctx->dom_id);
			if (!dmask_wrapper) {
				scx_bpf_error("Failed to query for domain %u cpumask",
					      task_ctx->dom_id);
				return prev_cpu;
			}
			d_cpumask = bpf_cpumask_kptr_get(&dmask_wrapper->cpumask);
			if (!d_cpumask) {
				scx_bpf_error("Failed to acquire domain %u cpumask kptr",
					      task_ctx->dom_id);
				return prev_cpu;
			}

			idle_cpumask = scx_bpf_get_idle_cpumask();

			has_idle = bpf_cpumask_intersects((const struct cpumask *)d_cpumask,
							  idle_cpumask);

			bpf_cpumask_release(d_cpumask);
			scx_bpf_put_idle_cpumask(idle_cpumask);

			if (has_idle) {
				cpu = bpf_get_smp_processor_id();
				if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
					stat_add(ATROPOS_STAT_WAKE_SYNC, 1);
					goto local;
				}
			}
		}
	}

	/* if the previous CPU is idle, dispatch directly to it */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(ATROPOS_STAT_PREV_IDLE, 1);
		cpu = prev_cpu;
		goto local;
	}

	/* If only one core is allowed, dispatch */
	if (p->nr_cpus_allowed == 1) {
		stat_add(ATROPOS_STAT_PINNED, 1);
		cpu = prev_cpu;
		goto local;
	}

	/* Find an idle cpu and just dispatch */
	p_cpumask = bpf_cpumask_kptr_get(&task_ctx->cpumask);
	if (!p_cpumask)
		return -ENOENT;
	cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)p_cpumask);
	bpf_cpumask_release(p_cpumask);
	if (cpu >= 0) {
		stat_add(ATROPOS_STAT_DIRECT_DISPATCH, 1);
		goto local;
	}

	return prev_cpu;

local:
	task_ctx->dispatch_local = true;
	return cpu;
}

void BPF_STRUCT_OPS(atropos_enqueue, struct task_struct *p, u32 enq_flags)
{
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);
	u32 *new_dom;

	if (!task_ctx) {
		scx_bpf_error("no task_ctx");
		return;
	}

	u32 prev_dom = task_ctx->dom_id;

	new_dom = bpf_map_lookup_elem(&lb_data, &pid);
	if (new_dom && *new_dom != task_ctx->dom_id &&
	    task_set_dsq(task_ctx, p, *new_dom)) {
		struct bpf_cpumask *p_cpumask;
		s32 cpu;

		stat_add(ATROPOS_STAT_LOAD_BALANCE, 1);
		task_ctx->dispatch_local = false;

		p_cpumask = bpf_cpumask_kptr_get(&task_ctx->cpumask);
		if (!p_cpumask) {
			scx_bpf_error("failed to get task_ctx->cpumask");
			return;
		}
		cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)p_cpumask);
		bpf_cpumask_release(p_cpumask);

		if (cpu >= 0)
			scx_bpf_kick_cpu(cpu, 0);
	}

	if (task_ctx->dispatch_local) {
		task_ctx->dispatch_local = false;
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_us * 1000, enq_flags);
		return;
	}

	scx_bpf_dispatch(p, task_ctx->dom_id, slice_us * 1000, enq_flags);
}

static u32 cpu_to_dom_id(s32 cpu)
{
	if (nr_doms <= 1)
		return 0;

	if (cpu >= 0 && cpu < MAX_CPUS) {
		u32 dom_id;

		/*
		 * XXX - idk why the verifier thinks cpu_dom_id_map[cpu] is not
		 * safe here.
		 */
		bpf_probe_read_kernel(&dom_id, sizeof(dom_id),
				      (const void *)&cpu_dom_id_map[cpu]);
		return dom_id;
	} else {
		return MAX_DOMS;
	}
}

static bool is_cpu_in_dom(u32 cpu, u32 dom_id)
{
	u64 mask = 0;

	/*
	 * XXX - derefing two dimensional array triggers the verifier, use
	 * probe_read instead.
	 */
	bpf_probe_read_kernel(&mask, sizeof(mask),
			      (const void *)&dom_cpumasks[dom_id][cpu / 64]);
	return mask & (1LLU << (cpu % 64));
}

struct cpumask_intersects_domain_loop_ctx {
	const struct cpumask *cpumask;
	u32 dom_id;
	bool ret;
};

static int cpumask_intersects_domain_loopfn(u32 idx, void *data)
{
	struct cpumask_intersects_domain_loop_ctx *lctx = data;
	const struct cpumask *cpumask = lctx->cpumask;

	if (bpf_cpumask_test_cpu(idx, cpumask) &&
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

	bpf_loop(nr_cpus, cpumask_intersects_domain_loopfn, &lctx, 0);
	return lctx.ret;
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

static int greedy_loopfn(s32 idx, void *data)
{
	u32 dom_id = dom_rr_next(*(s32 *)data);

	if (scx_bpf_dsq_nr_queued(dom_id) >= greedy_threshold &&
	    scx_bpf_consume(dom_id)) {
		stat_add(ATROPOS_STAT_GREEDY, 1);
		return 1;
	}
	return 0;
}

void BPF_STRUCT_OPS(atropos_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 dom = cpu_to_dom_id(cpu);
	if (scx_bpf_consume(dom)) {
		stat_add(ATROPOS_STAT_DSQ_DISPATCH, 1);
		return;
	}

	if (greedy_threshold)
		bpf_loop(nr_doms - 1, greedy_loopfn, &cpu, 0);
}

void BPF_STRUCT_OPS(atropos_runnable, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);

	if (!task_ctx) {
		scx_bpf_error("no task_ctx");
		return;
	}

	task_ctx->runnable_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(atropos_quiescent, struct task_struct *p, u64 deq_flags)
{
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);

	if (!task_ctx) {
		scx_bpf_error("no task_ctx");
		return;
	}

	task_ctx->runnable_for += bpf_ktime_get_ns() - task_ctx->runnable_at;
	task_ctx->runnable_at = 0;
}

void BPF_STRUCT_OPS(atropos_set_weight, struct task_struct *p, u32 weight)
{
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);

	if (!task_ctx) {
		scx_bpf_error("no task_ctx");
		return;
	}

	task_ctx->weight = weight;
}

struct pick_task_domain_loop_ctx {
	struct task_struct *p;
	const struct cpumask *cpumask;
	u64 dom_mask;
	u32 dom_rr_base;
	u32 dom_id;
};

static int pick_task_domain_loopfn(u32 idx, void *data)
{
	struct pick_task_domain_loop_ctx *lctx = data;
	u32 dom_id = (lctx->dom_rr_base + idx) % nr_doms;

	if (dom_id >= MAX_DOMS)
		return 1;

	if (cpumask_intersects_domain(lctx->cpumask, dom_id)) {
		lctx->dom_mask |= 1LLU << dom_id;
		if (lctx->dom_id == MAX_DOMS)
			lctx->dom_id = dom_id;
	}
	return 0;
}

static u32 pick_task_domain(struct task_ctx *task_ctx, struct task_struct *p,
			    const struct cpumask *cpumask)
{
	struct pick_task_domain_loop_ctx lctx = {
		.p = p,
		.cpumask = cpumask,
		.dom_id = MAX_DOMS,
	};
	s32 cpu = bpf_get_smp_processor_id();

	if (cpu < 0 || cpu >= MAX_CPUS)
		return MAX_DOMS;

	lctx.dom_rr_base = ++(pcpu_ctx[cpu].dom_rr_cur);

	bpf_loop(nr_doms, pick_task_domain_loopfn, &lctx, 0);
	task_ctx->dom_mask = lctx.dom_mask;

	return lctx.dom_id;
}

static void task_set_domain(struct task_ctx *task_ctx, struct task_struct *p,
			    const struct cpumask *cpumask)
{
	u32 dom_id = 0;

	if (nr_doms > 1)
		dom_id = pick_task_domain(task_ctx, p, cpumask);

	if (!task_set_dsq(task_ctx, p, dom_id))
		scx_bpf_error("failed to set domain %d for %s[%d]",
			      dom_id, p->comm, p->pid);
}

void BPF_STRUCT_OPS(atropos_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);
	if (!task_ctx) {
		scx_bpf_error("no task_ctx");
		return;
	}

	task_set_domain(task_ctx, p, cpumask);
}

s32 BPF_STRUCT_OPS(atropos_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	struct bpf_cpumask *cpumask;
	struct task_ctx task_ctx, *map_value;
	long ret;
	pid_t pid;

	memset(&task_ctx, 0, sizeof(task_ctx));

	pid = p->pid;
	ret = bpf_map_update_elem(&task_data, &pid, &task_ctx, BPF_NOEXIST);
	if (ret) {
		stat_add(ATROPOS_STAT_TASK_GET_ERR, 1);
		return ret;
	}

	/*
	 * Read the entry from the map immediately so we can add the cpumask
	 * with bpf_kptr_xchg().
	 */
	map_value = bpf_map_lookup_elem(&task_data, &pid);
	if (!map_value)
		/* Should never happen -- it was just inserted above. */
		return -EINVAL;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		bpf_map_delete_elem(&task_data, &pid);
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&map_value->cpumask, cpumask);
	if (cpumask) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		bpf_map_delete_elem(&task_data, &pid);
		return -EINVAL;
	}

	task_set_domain(map_value, p, p->cpus_ptr);

	return 0;
}

void BPF_STRUCT_OPS(atropos_disable, struct task_struct *p)
{
	pid_t pid = p->pid;
	long ret = bpf_map_delete_elem(&task_data, &pid);
	if (ret) {
		scx_bpf_error("no task_ctx");
		return;
	}
}

static int create_dom_dsq(u32 idx, void *data)
{
	struct dom_cpumask entry, *v;
	struct bpf_cpumask *cpumask;
	u32 cpu, dom_id = idx;
	s32 ret;

	ret = scx_bpf_create_dsq(dom_id, -1);
	if (ret < 0) {
		scx_bpf_error("Failed to create dsq %u (%d)", dom_id, ret);
		return 1;
	}

	memset(&entry, 0, sizeof(entry));
	ret = bpf_map_update_elem(&dom_cpumask_map, &dom_id, &entry, 0);
	if (ret) {
		scx_bpf_error("Failed to add dom_cpumask entry %u (%d)", dom_id, ret);
		return 1;
	}

	v = bpf_map_lookup_elem(&dom_cpumask_map, &dom_id);
	if (!v) {
		/* Should never happen, we just inserted it above. */
		scx_bpf_error("Failed to lookup dom element %u", dom_id);
		return 1;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create BPF cpumask for domain %u", dom_id);
		return 1;
	}

	for (cpu = 0; cpu < MAX_CPUS; cpu++) {
		const volatile __u64 *dmask;

		dmask = MEMBER_VPTR(dom_cpumasks, [dom_id][cpu / 64]);
		if (!dmask) {
			scx_bpf_error("array index error");
			bpf_cpumask_release(cpumask);
			return 1;
		}

		if (*dmask & (1LLU << (cpu % 64)))
			bpf_cpumask_set_cpu(cpu, cpumask);
	}

	cpumask = bpf_kptr_xchg(&v->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("Domain %u was already present", dom_id);
		bpf_cpumask_release(cpumask);
		return 1;
	}

	return 0;
}

int BPF_STRUCT_OPS_SLEEPABLE(atropos_init)
{
	if (!switch_partial)
		scx_bpf_switch_all();

	bpf_loop(nr_doms, create_dom_dsq, NULL, 0);

	for (u32 i = 0; i < nr_cpus; i++)
		pcpu_ctx[i].dom_rr_cur = i;

	return 0;
}

void BPF_STRUCT_OPS(atropos_exit, struct scx_exit_info *ei)
{
	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_type = ei->type;
}

SEC(".struct_ops")
struct sched_ext_ops atropos = {
	.select_cpu = (void *)atropos_select_cpu,
	.enqueue = (void *)atropos_enqueue,
	.dispatch = (void *)atropos_dispatch,
	.runnable = (void *)atropos_runnable,
	.quiescent = (void *)atropos_quiescent,
	.set_weight = (void *)atropos_set_weight,
	.set_cpumask = (void *)atropos_set_cpumask,
	.prep_enable = (void *)atropos_prep_enable,
	.disable = (void *)atropos_disable,
	.init = (void *)atropos_init,
	.exit = (void *)atropos_exit,
	.flags = 0,
	.name = "atropos",
};
