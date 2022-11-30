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
// task belongs to. When a task first enters the system (atropos_enable), they
// are round-robined to a domain.
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
// atropos_consume will attempt to consume a task from its domain's
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

const volatile bool switch_all;
const volatile __u64 greedy_threshold = (u64)-1;

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

static int refresh_task_cpumask(u32 cpu, void *data)
{
	struct refresh_task_cpumask_loop_ctx *c = data;
	struct task_struct *p = c->p;
	struct task_ctx *ctx = c->ctx;
	u64 mask = 1LLU << (cpu % 64);
	const volatile __u64 *dptr;

	dptr = MEMBER_VPTR(dom_cpumasks, [ctx->dom_id][cpu / 64]);
	if (!dptr)
		return 1;

	if ((*dptr & mask) &&
	    scx_bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		u64 *cptr = MEMBER_VPTR(ctx->cpumask, [cpu / 64]);
		if (!cptr)
			return 1;
		*cptr |= mask;
	} else {
		u64 *cptr = MEMBER_VPTR(ctx->cpumask, [cpu / 64]);
		if (!cptr)
			return 1;
		*cptr *= ~mask;
	}

	return 0;
}

static void task_set_dq(struct task_ctx *task_ctx, struct task_struct *p,
			u32 dom_id)
{
	struct refresh_task_cpumask_loop_ctx lctx = {
		.p = p,
		.ctx = task_ctx,
	};

	task_ctx->dom_id = dom_id;
	bpf_loop(nr_cpus, refresh_task_cpumask, &lctx, 0);
}

s32 BPF_STRUCT_OPS(atropos_select_cpu, struct task_struct *p, int prev_cpu,
		   u32 wake_flags)
{
	s32 cpu;

	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);
	if (!task_ctx) {
		stat_add(ATROPOS_STAT_TASK_GET_ERR, 1);
		return prev_cpu;
	}

	bool load_balanced = false;
	u32 *new_dom = bpf_map_lookup_elem(&lb_data, &pid);
	if (new_dom && *new_dom != task_ctx->dom_id) {
		task_set_dq(task_ctx, p, *new_dom);
		stat_add(ATROPOS_STAT_LOAD_BALANCE, 1);
		load_balanced = true;
	}

	/*
	 * If WAKE_SYNC and the machine isn't fully saturated, wake up @p to the
	 * local dq of the waker.
	 */
	if (p->nr_cpus_allowed > 1 && (wake_flags & SCX_WAKE_SYNC)) {
		struct task_struct *current = (void *)bpf_get_current_task();

		if (!(BPF_CORE_READ(current, flags) & PF_EXITING) &&
		    task_ctx->dom_id < MAX_DOMS &&
		    scx_bpf_has_idle_cpus_among_untyped(
			    (unsigned long)dom_cpumasks[task_ctx->dom_id])) {
			cpu = bpf_get_smp_processor_id();
			if (scx_bpf_cpumask_test_cpu(cpu,
						     p->cpus_ptr)) {
				stat_add(ATROPOS_STAT_WAKE_SYNC, 1);
				goto local;
			}
		}
	}

	/* if the previous CPU is idle, dispatch directly to it */
	if (!load_balanced) {
		u8 prev_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
		if (*(volatile u8 *)&prev_idle) {
			stat_add(ATROPOS_STAT_PREV_IDLE, 1);
			cpu = prev_cpu;
			goto local;
		}
	}

	/* If only one core is allowed, dispatch */
	if (p->nr_cpus_allowed == 1) {
		cpu = scx_bpf_cpumask_first_untyped(
			(unsigned long)task_ctx->cpumask);
		stat_add(ATROPOS_STAT_PINNED, 1);
		goto local;
	}

	/* Find an idle cpu and just dispatch */
	cpu = scx_bpf_pick_idle_cpu_untyped((unsigned long)task_ctx->cpumask);
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
	p->scx.slice = slice_us * 1000;

	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);
	if (!task_ctx) {
		stat_add(ATROPOS_STAT_TASK_GET_ERR, 1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	if (task_ctx->dispatch_local) {
		task_ctx->dispatch_local = false;
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	scx_bpf_dispatch(p, task_ctx->dom_id, SCX_SLICE_DFL, enq_flags);
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

	if (scx_bpf_dsq_nr_queued(dom_id) > greedy_threshold &&
	    scx_bpf_consume(dom_id)) {
		stat_add(ATROPOS_STAT_GREEDY, 1);
		return 1;
	}
	return 0;
}

void BPF_STRUCT_OPS(atropos_consume, s32 cpu)
{
	u32 dom = cpu_to_dom_id(cpu);
	if (scx_bpf_consume(dom)) {
		stat_add(ATROPOS_STAT_DSQ_DISPATCH, 1);
		return;
	}

	if (greedy_threshold != (u64)-1)
		bpf_loop(nr_doms - 1, greedy_loopfn, &cpu, 0);
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

	task_set_dq(task_ctx, p, dom_id);
}

void BPF_STRUCT_OPS(atropos_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	pid_t pid = p->pid;
	struct task_ctx *task_ctx = bpf_map_lookup_elem(&task_data, &pid);
	if (!task_ctx) {
		stat_add(ATROPOS_STAT_TASK_GET_ERR, 1);
		return;
	}

	task_set_domain(task_ctx, p, cpumask);
}

void BPF_STRUCT_OPS(atropos_enable, struct task_struct *p)
{
	struct task_ctx task_ctx;
	memset(&task_ctx, 0, sizeof(task_ctx));
	task_ctx.weight = p->scx.weight;

	task_set_domain(&task_ctx, p, p->cpus_ptr);
	pid_t pid = p->pid;
	long ret =
		bpf_map_update_elem(&task_data, &pid, &task_ctx, BPF_NOEXIST);
	if (ret) {
		stat_add(ATROPOS_STAT_TASK_GET_ERR, 1);
		return;
	}
}

void BPF_STRUCT_OPS(atropos_disable, struct task_struct *p)
{
	pid_t pid = p->pid;
	long ret = bpf_map_delete_elem(&task_data, &pid);
	if (ret) {
		stat_add(ATROPOS_STAT_TASK_GET_ERR, 1);
		return;
	}
}

int BPF_STRUCT_OPS(atropos_init)
{
	int ret;
	u32 local_nr_doms = nr_doms;

	bpf_printk("atropos init");

	if (switch_all)
		scx_bpf_switch_all();

	// BPF verifier gets cranky if we don't bound this like so
	if (local_nr_doms > MAX_DOMS)
		local_nr_doms = MAX_DOMS;

	for (u32 i = 0; i < local_nr_doms; ++i) {
		ret = scx_bpf_create_dsq(i, -1);
		if (ret < 0)
			return ret;
	}

	for (u32 i = 0; i < nr_cpus; ++i) {
		pcpu_ctx[i].dom_rr_cur = i;
	}

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
	.consume = (void *)atropos_consume,
	.set_cpumask = (void *)atropos_set_cpumask,
	.enable = (void *)atropos_enable,
	.disable = (void *)atropos_disable,
	.init = (void *)atropos_init,
	.exit = (void *)atropos_exit,
	.flags = 0,
	.name = "atropos",
};
