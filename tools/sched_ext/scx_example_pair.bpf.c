// SPDX-License-Identifier: GPL-2.0
/*
 * A demo core-scheduler which always makes every sibling CPU pair to execute
 * from the same CPU cgroup.
 *
 * CPUs are paired up according to stride. All tasks are queued to the matching
 * per-cgroup FIFO and cgroups with pending tasks are queued on the top-level
 * FIFO. Each CPU pair share a pair_ctx which tracks the cgroup the pair is
 * executing and when it started. After a set duration or if the cgroup becomes
 * empty, the cgroup transitions to the draining state and stops executing new
 * tasks from the cgroup. The last CPU which stops moves the pair to the next
 * cgroup and the cycle repeats.
 *
 * The scheduling behavior is simple but the code is complex mostly because this
 * implementation hits several BPF shortcomings and has to work around in often
 * awkward ways. Most of the shortcomings are expected to be resolved in the
 * near future which should allow greatly simplifying this scheduler.
 */
#include "scx_common.h"
#include "scx_example_pair.h"

char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpu_ids;

/* a pair of CPUs stay on a cgroup for this duration */
const volatile u32 pair_batch_dur_ns = SCX_SLICE_DFL;

/* cpu ID -> pair cpu ID */
const volatile s32 pair_cpu[MAX_CPUS] = { [0 ... MAX_CPUS - 1] = -1 };

/* cpu ID -> pair_id */
const volatile u32 pair_id[MAX_CPUS];

/* CPU ID -> CPU # in the pair (0 or 1) */
const volatile u32 in_pair_idx[MAX_CPUS];

struct pair_ctx {
	struct bpf_spin_lock	lock;

	/* the cgroup the pair is currently executing */
	u64			cgid;

	/* the pair started executing the current cgroup at */
	u64			started_at;

	/* whether the current cgroup is draining */
	bool			draining;

	/* the CPUs that are currently active on the cgroup */
	u32			active_mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS / 2);
	__type(key, u32);
	__type(value, struct pair_ctx);
} pair_ctx SEC(".maps");

/* queue of cgrp_q's possibly with tasks on them */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	/*
	 * Because it's difficult to build strong synchronization encompassing
	 * multiple non-trivial operations in BPF, this queue is managed in an
	 * opportunistic way so that we guarantee that a cgroup w/ active tasks
	 * is always on it but possibly multiple times. Once we have more robust
	 * synchronization constructs and e.g. linked list, we should be able to
	 * do this in a prettier way but for now just size it big enough.
	 */
	__uint(max_entries, 4 * MAX_CGRPS);
	__type(value, u64);
} top_q SEC(".maps");

/* per-cgroup q which FIFOs the tasks from the cgroup */
struct cgrp_q {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_QUEUED);
	__type(value, u32);
};

/*
 * Ideally, we want to allocate cgrp_q and cgrq_q_len in the cgroup local
 * storage; however, a cgroup local storage can only be accessed from the BPF
 * progs attached to the cgroup. For now, work around by allocating array of
 * cgrp_q's and then allocating per-cgroup indices.
 *
 * Another caveat: It's difficult to populate a large array of maps statically
 * or from BPF. Initialize it from userland.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_CGRPS);
	__type(key, s32);
	__array(values, struct cgrp_q);
} cgrp_q_arr SEC(".maps");

static u64 cgrp_q_len[MAX_CGRPS];

/*
 * This and cgrp_q_idx_hash combine into a poor man's IDR. This likely would be
 * useful to have as a map type.
 */
static u32 cgrp_q_idx_cursor;
static u64 cgrp_q_idx_busy[MAX_CGRPS];

/*
 * All added up, the following is what we do:
 *
 * 1. When a cgroup is enabled, RR cgroup_q_idx_busy array doing cmpxchg looking
 *    for a free ID. If not found, fail cgroup creation with -EBUSY.
 *
 * 2. Hash the cgroup ID to the allocated cgrp_q_idx in the following
 *    cgrp_q_idx_hash.
 *
 * 3. Whenever a cgrp_q needs to be accessed, first look up the cgrp_q_idx from
 *    cgrp_q_idx_hash and then access the corresponding entry in cgrp_q_arr.
 *
 * This is sadly complicated for something pretty simple. Hopefully, we should
 * be able to simplify in the future.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CGRPS);
	__uint(key_size, sizeof(u64));		/* cgrp ID */
	__uint(value_size, sizeof(s32));	/* cgrp_q idx */
} cgrp_q_idx_hash SEC(".maps");

/* statistics */
u64 nr_total, nr_dispatched, nr_missing, nr_kicks;
u64 nr_exps, nr_exp_waits, nr_exp_empty;
u64 nr_cgrp_next, nr_cgrp_coll, nr_cgrp_empty;

bool exited;

static bool time_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

s64 BPF_STRUCT_OPS(pair_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;
	u64 cgid = p->sched_task_group->css.cgroup->kn->id;
	u32 *q_idx;
	struct cgrp_q *cgq;
	u64 *cgq_len;

	__sync_fetch_and_add(&nr_total, 1);

	/* find the cgroup's q and push @p into it */
	q_idx = bpf_map_lookup_elem(&cgrp_q_idx_hash, &cgid);
	if (!q_idx)
		return -EINVAL;

	cgq = bpf_map_lookup_elem(&cgrp_q_arr, q_idx);
	if (!cgq)
		return -EINVAL;

	if (bpf_map_push_elem(cgq, &pid, 0))
		return -EOVERFLOW;

	/* bump q len, if going 0 -> 1, queue cgroup into the top_q */
	cgq_len = MEMBER_VPTR(cgrp_q_len, [*q_idx]);
	if (!cgq_len)
		return -EINVAL;

	if (!__sync_fetch_and_add(cgq_len, 1) &&
	    bpf_map_push_elem(&top_q, &cgid, 0))
	    return -EOVERFLOW;

	return SCX_DQ_NONE;
}

/* find the next cgroup to execute and return it in *data */
static int next_cgid_loopfn(u32 idx, void *data)
{
	u64 cgid;
	u32 *q_idx;
	u64 *cgq_len;

	if (bpf_map_pop_elem(&top_q, &cgid))
		return 1;

	q_idx = bpf_map_lookup_elem(&cgrp_q_idx_hash, &cgid);
	if (!q_idx)
		return 0;

	/* this is the only place where empty cgroups are taken off the top_q */
	cgq_len = MEMBER_VPTR(cgrp_q_len, [*q_idx]);
	if (!cgq_len || !*cgq_len)
		return 0;

	/* if it has any tasks, requeue as we may race and not execute it */
	bpf_map_push_elem(&top_q, &cgid, 0);
	*(u64 *)data = cgid;
	return 1;
}

struct claim_task_loopctx {
	u32		q_idx;
	bool		claimed;
};

/* claim one task from the specified cgq */
static int claim_task_loopfn(u32 idx, void *data)
{
	struct claim_task_loopctx *claimc = data;
	u64 *cgq_len;
	u64 len;

	cgq_len = MEMBER_VPTR(cgrp_q_len, [claimc->q_idx]);
	if (!cgq_len)
		return 1;

	len = *cgq_len;
	if (!len)
		return 1;

	if (__sync_val_compare_and_swap(cgq_len, len, len - 1) != len)
		return 0;

	claimc->claimed = true;
	return 1;
}

struct dispatch_loopctx {
	s32		cpu;
	int		ret;
};

static int dispatch_loopfn(u32 idx, void *data)
{
	struct dispatch_loopctx *dlc = data;
	struct pair_ctx *pairc;
	struct bpf_map *cgq_map;
	struct claim_task_loopctx claimc;
	struct task_struct *p;
	u64 now = bpf_ktime_get_ns();
	bool kick_pair = false;
	bool expired;
	u32 *vptr, in_pair_mask;
	s32 pid;
	u64 cgid;

	vptr = (u32 *)MEMBER_VPTR(pair_id, [dlc->cpu]);
	if (!vptr) {
		dlc->ret = -EINVAL;
		return 1;
	}

	pairc = bpf_map_lookup_elem(&pair_ctx, vptr);
	if (!pairc) {
		dlc->ret = -EINVAL;
		return 1;
	}

	vptr = (u32 *)MEMBER_VPTR(in_pair_idx, [dlc->cpu]);
	if (!vptr) {
		dlc->ret = -EINVAL;
		return 1;
	}
	in_pair_mask = 1U << *vptr;

	bpf_spin_lock(&pairc->lock);
	pairc->active_mask &= ~in_pair_mask;

	expired = time_before(pairc->started_at + pair_batch_dur_ns, now);
	if (expired || pairc->draining) {
		u64 new_cgid = 0;

		__sync_fetch_and_add(&nr_exps, 1);

		/*
		 * We're done with the current cgid. An obvious optimization
		 * would be not draining if the next cgroup is the current one.
		 * For now, be dumb and always expire.
		 */
		pairc->draining = true;

		if (pairc->active_mask) {
			/*
			 * The other CPU is still active. We want to wait until
			 * this cgroup expires. If already expired, kick. When
			 * the other CPU arrives at dispatch and clears its
			 * active mask, it'll push the pair to the next cgroup
			 * and kick this CPU.
			 */
			__sync_fetch_and_add(&nr_exp_waits, 1);
			bpf_spin_unlock(&pairc->lock);
			if (expired)
				kick_pair = true;
			goto out_maybe_kick;
		}

		bpf_spin_unlock(&pairc->lock);

		/*
		 * Pick the next cgroup. It'd be easier / cleaner to not drop
		 * pairc->lock and use stronger synchronization here especially
		 * given that we'll be switching cgroups significantly less
		 * frequently than tasks. Unfortunately, bpf_spin_lock can't
		 * really protect anything non-trivial. Let's do opportunistic
		 * operations instead.
		 */
		bpf_loop(1 << 23, next_cgid_loopfn, &new_cgid, 0);
		/* no active cgroup, go idle */
		if (!new_cgid) {
			__sync_fetch_and_add(&nr_exp_empty, 1);
			return 1;
		}

		bpf_spin_lock(&pairc->lock);

		/*
		 * The other CPU may already have started on a new cgroup while
		 * we dropped the lock. Make sure that we're still draining and
		 * start on the new cgroup.
		 */
		if (pairc->draining && !pairc->active_mask) {
			__sync_fetch_and_add(&nr_cgrp_next, 1);
			pairc->cgid = new_cgid;
			pairc->started_at = now;
			pairc->draining = false;
			kick_pair = true;
		} else {
			__sync_fetch_and_add(&nr_cgrp_coll, 1);
		}
	}

	cgid = pairc->cgid;
	pairc->active_mask |= in_pair_mask;
	bpf_spin_unlock(&pairc->lock);

	/* again, it'd be better to do all these with the lock held, oh well */
	vptr = bpf_map_lookup_elem(&cgrp_q_idx_hash, &cgid);
	if (!vptr) {
		dlc->ret = -EINVAL;
		return 1;
	}

	claimc = (struct claim_task_loopctx){ .q_idx = *vptr };
	bpf_loop(1 << 23, claim_task_loopfn, &claimc, 0);
	if (!claimc.claimed) {
		/* the cgroup must be empty, expire and repeat */
		__sync_fetch_and_add(&nr_cgrp_empty, 1);
		bpf_spin_lock(&pairc->lock);
		pairc->draining = true;
		pairc->active_mask &= ~in_pair_mask;
		bpf_spin_unlock(&pairc->lock);
		return 0;
	}

	cgq_map = bpf_map_lookup_elem(&cgrp_q_arr, &claimc.q_idx);
	if (!cgq_map) {
		dlc->ret = -EINVAL;
		return 1;
	}

	if (bpf_map_pop_elem(cgq_map, &pid)) {
		dlc->ret = -ESRCH;
		return 1;
	}

	p = scx_bpf_find_task_by_pid(pid);
	if (p) {
		__sync_fetch_and_add(&nr_dispatched, 1);
		p->scx.slice = SCX_SLICE_DFL;
		scx_bpf_dispatch(p, SCX_DQ_GLOBAL);
	} else {
		/* we don't handle dequeues, retry on lost tasks */
		__sync_fetch_and_add(&nr_missing, 1);
		return 0;
	}

out_maybe_kick:
	if (kick_pair) {
		s32 *pair = (s32 *)MEMBER_VPTR(pair_cpu, [dlc->cpu]);
		if (pair) {
			__sync_fetch_and_add(&nr_kicks, 1);
			scx_bpf_kick_cpu(*pair, SCX_KICK_PREEMPT);
		}
	}
	return 1;
}

s32 BPF_STRUCT_OPS(pair_dispatch, s32 cpu, struct task_struct *prev)
{
	struct dispatch_loopctx dlc = { .cpu = cpu };

	bpf_loop(1 << 23, dispatch_loopfn, &dlc, 0);
	return dlc.ret;
}

static int alloc_cgrp_q_idx_loopfn(u32 idx, void *data)
{
	u32 q_idx;

	q_idx = __sync_fetch_and_add(&cgrp_q_idx_cursor, 1) % MAX_CGRPS;
	if (!__sync_val_compare_and_swap(&cgrp_q_idx_busy[q_idx], 0, 1)) {
		*(s32 *)data = q_idx;
		return 1;
	}
	return 0;
}

s32 BPF_STRUCT_OPS(pair_cgroup_init, struct cgroup *cgrp)
{
	u64 cgid = cgrp->kn->id;
	s32 q_idx = -1;

	bpf_loop(MAX_CGRPS, alloc_cgrp_q_idx_loopfn, &q_idx, 0);
	if (q_idx < 0)
		return -EBUSY;

	if (bpf_map_update_elem(&cgrp_q_idx_hash, &cgid, &q_idx, BPF_ANY)) {
		u64 *busy = MEMBER_VPTR(cgrp_q_idx_busy, [q_idx]);
		if (busy)
			*busy = 0;
		return -EBUSY;
	}

	return 0;
}

void BPF_STRUCT_OPS(pair_cgroup_exit, struct cgroup *cgrp)
{
	u64 cgid = cgrp->kn->id;
	s32 *q_idx;

	q_idx = bpf_map_lookup_elem(&cgrp_q_idx_hash, &cgid);
	if (q_idx) {
		u64 *busy = MEMBER_VPTR(cgrp_q_idx_busy, [*q_idx]);
		if (busy)
			*busy = 0;
		bpf_map_delete_elem(&cgrp_q_idx_hash, &cgid);
	}
}

void BPF_STRUCT_OPS(pair_exit, struct scx_ops_exit_info *ei)
{
	exited = true;
}

SEC(".struct_ops")
struct sched_ext_ops pair_ops = {
	.enqueue		= (void *)pair_enqueue,
	.dispatch		= (void *)pair_dispatch,
	.cgroup_init		= (void *)pair_cgroup_init,
	.cgroup_exit		= (void *)pair_cgroup_exit,
	.exit			= (void *)pair_exit,
	.name			= "pair",
};
