/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#define SCX_OP_IDX(op)		(offsetof(struct sched_ext_ops, op) / sizeof(void (*)(void)))

enum scx_internal_consts {
	SCX_NR_ONLINE_OPS	 = SCX_OP_IDX(init),
	SCX_DSP_DFL_MAX_BATCH	 = 32,
};

enum scx_ops_enable_state {
	SCX_OPS_PREPPING,
	SCX_OPS_ENABLING,
	SCX_OPS_ENABLED,
	SCX_OPS_DISABLING,
	SCX_OPS_DISABLED,
};

/*
 * sched_ext_entity->ops_state
 *
 * Used to track the task ownership between the SCX core and the BPF scheduler.
 * State transitions look as follows:
 *
 * NONE -> QUEUEING -> QUEUED -> DISPATCHING -> NONE
 *   ^              |                 |
 *   |              v                 v
 *   \-------------------------------/
 *
 * QUEUEING and DISPATCHING states can be waited upon. See wait_ops_state() call
 * sites for explanations on the conditions being waited upon and why they are
 * safe. Transitions out of them into NONE or QUEUED must store_release and the
 * waiters should load_acquire.
 *
 * Tracking scx_ops_state enables sched_ext core to reliably determine whether
 * any given task can be dispatched by the BPF scheduler at all times and thus
 * relaxes the requirements on the BPF scheduler. This allows the BPF scheduler
 * to try to dispatch any task anytime regardless of its state as the SCX core
 * can safely reject invalid dispatches.
 */
enum scx_ops_state {
	SCX_OPSS_NONE,		/* owned by the SCX core */
	SCX_OPSS_QUEUEING,	/* in transit to the BPF scheduler */
	SCX_OPSS_QUEUED,	/* owned by the BPF scheduler */
	SCX_OPSS_DISPATCHING,	/* in transit back to the SCX core */

	/*
	 * QSEQ brands each QUEUED instance so that, when dispatch races
	 * dequeue/requeue, the dispatcher can tell whether it still has a claim
	 * on the task being dispatched.
	 */
	SCX_OPSS_QSEQ_SHIFT	= 2,
	SCX_OPSS_STATE_MASK	= (1LLU << SCX_OPSS_QSEQ_SHIFT) - 1,
	SCX_OPSS_QSEQ_MASK	= ~SCX_OPSS_STATE_MASK,
};

/*
 * During exit, a task may schedule after losing its PIDs. When disabling the
 * BPF scheduler, we need to be able to iterate tasks in every state to
 * guarantee system safety. Maintain a dedicated task list which contains every
 * task between its fork and eventual free.
 */
static DEFINE_SPINLOCK(scx_tasks_lock);
static LIST_HEAD(scx_tasks);

/* ops enable/disable */
static struct kthread_worker *scx_ops_helper;
static DEFINE_MUTEX(scx_ops_enable_mutex);
DEFINE_STATIC_KEY_FALSE(__scx_ops_enabled);
DEFINE_STATIC_PERCPU_RWSEM(scx_fork_rwsem);
static atomic_t scx_ops_enable_state_var = ATOMIC_INIT(SCX_OPS_DISABLED);
static struct sched_ext_ops scx_ops;
static bool warned_zero_slice;

static DEFINE_STATIC_KEY_FALSE(scx_ops_enq_last);
static DEFINE_STATIC_KEY_FALSE(scx_ops_enq_exiting);
static DEFINE_STATIC_KEY_FALSE(scx_builtin_idle_enabled);

struct static_key_false scx_has_op[SCX_NR_ONLINE_OPS] =
	{ [0 ... SCX_NR_ONLINE_OPS-1] = STATIC_KEY_FALSE_INIT };

static atomic_t scx_exit_type = ATOMIC_INIT(SCX_EXIT_DONE);
static struct scx_exit_info scx_exit_info;

static atomic64_t scx_nr_rejected = ATOMIC64_INIT(0);

/* idle tracking */
#ifdef CONFIG_SMP
#ifdef CONFIG_CPUMASK_OFFSTACK
#define CL_ALIGNED_IF_ONSTACK
#else
#define CL_ALIGNED_IF_ONSTACK __cacheline_aligned_in_smp
#endif

static struct {
	cpumask_var_t cpu;
	cpumask_var_t smt;
} idle_masks CL_ALIGNED_IF_ONSTACK;

static bool __cacheline_aligned_in_smp has_idle_cpus;
#endif

/*
 * Direct dispatch marker.
 *
 * Non-NULL values are used for direct dispatch from enqueue path. A valid
 * pointer points to the task currently being enqueued. An ERR_PTR value is used
 * to indicate that direct dispatch has already happened.
 */
static DEFINE_PER_CPU(struct task_struct *, direct_dispatch_task);

/* dispatch queues */
static struct scx_dispatch_q __cacheline_aligned_in_smp scx_dsq_global;

static const struct rhashtable_params dsq_hash_params = {
	.key_len		= 8,
	.key_offset		= offsetof(struct scx_dispatch_q, id),
	.head_offset		= offsetof(struct scx_dispatch_q, hash_node),
};

static struct rhashtable dsq_hash;
static DEFINE_RAW_SPINLOCK(all_dsqs_lock);
static LIST_HEAD(all_dsqs);
static LLIST_HEAD(dsqs_to_free);

/* dispatch buf */
struct dispatch_buf_ent {
	struct task_struct	*task;
	u64			qseq;
	u64			dsq_id;
	u64			enq_flags;
};

static u32 dispatch_max_batch;
static struct dispatch_buf_ent __percpu *dispatch_buf;
static DEFINE_PER_CPU(u32, dispatch_buf_cursor);

/* consume context */
struct consume_ctx {
	struct rq		*rq;
	struct rq_flags		*rf;
};

static DEFINE_PER_CPU(struct consume_ctx, consume_ctx);

void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice,
		      u64 enq_flags);
__printf(2, 3) static void scx_ops_error_type(enum scx_exit_type type,
					      const char *fmt, ...);
#define scx_ops_error(fmt, args...)						\
	scx_ops_error_type(SCX_EXIT_ERROR, fmt, ##args)

struct scx_task_iter {
	struct sched_ext_entity		cursor;
	struct task_struct		*locked;
	struct rq			*rq;
	struct rq_flags			rf;
};

/**
 * scx_task_iter_init - Initialize a task iterator
 * @iter: iterator to init
 *
 * Initialize @iter. Must be called with scx_tasks_lock held. Once initialized,
 * @iter must eventually be exited with scx_task_iter_exit().
 *
 * scx_tasks_lock may be released between this and the first next() call or
 * between any two next() calls. If scx_tasks_lock is released between two
 * next() calls, the caller is responsible for ensuring that the task being
 * iterated remains accessible either through RCU read lock or obtaining a
 * reference count.
 *
 * All tasks which existed when the iteration started are guaranteed to be
 * visited as long as they still exist.
 */
static void scx_task_iter_init(struct scx_task_iter *iter)
{
	lockdep_assert_held(&scx_tasks_lock);

	iter->cursor = (struct sched_ext_entity){ .flags = SCX_TASK_CURSOR };
	list_add(&iter->cursor.tasks_node, &scx_tasks);
	iter->locked = NULL;
}

/**
 * scx_task_iter_exit - Exit a task iterator
 * @iter: iterator to exit
 *
 * Exit a previously initialized @iter. Must be called with scx_tasks_lock held.
 * If the iterator holds a task's rq lock, that rq lock is released. See
 * scx_task_iter_init() for details.
 */
static void scx_task_iter_exit(struct scx_task_iter *iter)
{
	struct list_head *cursor = &iter->cursor.tasks_node;

	lockdep_assert_held(&scx_tasks_lock);

	if (iter->locked) {
		task_rq_unlock(iter->rq, iter->locked, &iter->rf);
		iter->locked = NULL;
	}

	if (list_empty(cursor))
		return;

	list_del_init(cursor);
}

/**
 * scx_task_iter_next - Next task
 * @iter: iterator to walk
 *
 * Visit the next task. See scx_task_iter_init() for details.
 */
static struct task_struct *scx_task_iter_next(struct scx_task_iter *iter)
{
	struct list_head *cursor = &iter->cursor.tasks_node;
	struct sched_ext_entity *pos;

	lockdep_assert_held(&scx_tasks_lock);

	list_for_each_entry(pos, cursor, tasks_node) {
		if (&pos->tasks_node == &scx_tasks)
			return NULL;
		if (!(pos->flags & SCX_TASK_CURSOR)) {
			list_move(cursor, &pos->tasks_node);
			return container_of(pos, struct task_struct, scx);
		}
	}

	/* can't happen, should always terminate at scx_tasks above */
	BUG();
}

/**
 * scx_task_iter_next_filtered - Next non-idle task
 * @iter: iterator to walk
 *
 * Visit the next non-idle task. See scx_task_iter_init() for details.
 */
static struct task_struct *
scx_task_iter_next_filtered(struct scx_task_iter *iter)
{
	struct task_struct *p;

	while ((p = scx_task_iter_next(iter))) {
		if (!is_idle_task(p))
			return p;
	}
	return NULL;
}

/**
 * scx_task_iter_next_filtered_locked - Next non-idle task with its rq locked
 * @iter: iterator to walk
 *
 * Visit the next non-idle task with its rq lock held. See scx_task_iter_init()
 * for details.
 */
static struct task_struct *
scx_task_iter_next_filtered_locked(struct scx_task_iter *iter)
{
	struct task_struct *p;

	if (iter->locked) {
		task_rq_unlock(iter->rq, iter->locked, &iter->rf);
		iter->locked = NULL;
	}

	p = scx_task_iter_next_filtered(iter);
	if (!p)
		return NULL;

	iter->rq = task_rq_lock(p, &iter->rf);
	iter->locked = p;
	return p;
}

static enum scx_ops_enable_state scx_ops_enable_state(void)
{
	return atomic_read(&scx_ops_enable_state_var);
}

static enum scx_ops_enable_state
scx_ops_set_enable_state(enum scx_ops_enable_state to)
{
	return atomic_xchg(&scx_ops_enable_state_var, to);
}

static bool scx_ops_tryset_enable_state(enum scx_ops_enable_state to,
					enum scx_ops_enable_state from)
{
	int from_v = from;

	return atomic_try_cmpxchg(&scx_ops_enable_state_var, &from_v, to);
}

static bool scx_ops_disabling(void)
{
	return unlikely(scx_ops_enable_state() == SCX_OPS_DISABLING);
}

#define SCX_HAS_OP(op)	static_branch_likely(&scx_has_op[SCX_OP_IDX(op)])

static void wait_ops_state(struct task_struct *p, u64 opss)
{
	/*
	 * We're waiting @p to transit out of QUEUEING or DISPATCHING.
	 * load_acquire ensures that we see the updates.
	 */
	do {
		cpu_relax();
	} while (atomic64_read_acquire(&p->scx.ops_state) == opss);
}

/**
 * ops_cpu_valid - Verify a cpu number
 * @cpu: cpu number which came from a BPF ops
 *
 * @cpu is a cpu number which came from the BPF scheduler and can be any value.
 * Verify that it is in range and one of the possible cpus.
 */
static bool ops_cpu_valid(s32 cpu)
{
	return likely(cpu >= 0 && cpu < nr_cpu_ids && cpu_possible(cpu));
}

/**
 * ops_sanitize_err - Sanitize a -errno value
 * @ops_name: operation to blame on failure
 * @err: -errno value to sanitize
 *
 * Verify @err is a valid -errno. If not, trigger scx_ops_error() and return
 * -%EPROTO. This is necessary because returning a rogue -errno up the chain can
 * cause misbehaviors. For an example, a large negative return from
 * ops.prep_enable() triggers an oops when passed up the call chain because the
 * value fails IS_ERR() test after being encoded with ERR_PTR() and then is
 * handled as a pointer.
 */
static int ops_sanitize_err(const char *ops_name, s32 err)
{
	if (err < 0 && err >= -MAX_ERRNO)
		return err;

	scx_ops_error("ops.%s() returned an invalid errno %d", ops_name, err);
	return -EPROTO;
}

static void update_curr_scx(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 now = rq_clock_task(rq);
	u64 delta_exec;

	if (time_before_eq64(now, curr->se.exec_start))
		return;

	delta_exec = now - curr->se.exec_start;
	curr->se.exec_start = now;
	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);
	cgroup_account_cputime(curr, delta_exec);

	curr->scx.slice -= min(curr->scx.slice, delta_exec);
}

static void dispatch_enqueue(struct scx_dispatch_q *dsq, struct task_struct *p,
			     u64 enq_flags)
{
	bool is_local = dsq->id == SCX_DSQ_LOCAL;

	WARN_ON_ONCE(p->scx.dsq || !list_empty(&p->scx.dsq_node));

	if (!is_local) {
		raw_spin_lock(&dsq->lock);
		if (unlikely(dsq->id == SCX_DSQ_INVALID)) {
			scx_ops_error("attempting to dispatch to a destroyed dsq");
			/* fall back to the global dsq */
			raw_spin_unlock(&dsq->lock);
			dsq = &scx_dsq_global;
			raw_spin_lock(&dsq->lock);
		}
	}

	if (enq_flags & SCX_ENQ_HEAD)
		list_add(&p->scx.dsq_node, &dsq->fifo);
	else
		list_add_tail(&p->scx.dsq_node, &dsq->fifo);
	dsq->nr++;
	p->scx.dsq = dsq;

	/*
	 * We're transitioning out of QUEUEING or DISPATCHING. store_release to
	 * match waiters' load_acquire.
	 */
	if (enq_flags & SCX_ENQ_CLEAR_OPSS)
		atomic64_set_release(&p->scx.ops_state, SCX_OPSS_NONE);

	if (is_local) {
		struct rq *rq = container_of(dsq, struct rq, scx.local_dsq);

		if (sched_class_above(&ext_sched_class, rq->curr->sched_class))
			resched_curr(rq);
	} else {
		raw_spin_unlock(&dsq->lock);
	}
}

static void dispatch_dequeue(struct scx_rq *scx_rq, struct task_struct *p)
{
	struct scx_dispatch_q *dsq = p->scx.dsq;
	bool is_local = dsq == &scx_rq->local_dsq;

	if (!dsq) {
		WARN_ON_ONCE(!list_empty(&p->scx.dsq_node));
		/*
		 * When dispatching directly from the BPF scheduler to a local
		 * dsq, the task isn't associated with any dsq but
		 * @p->scx.holding_cpu may be set under the protection of
		 * %SCX_OPSS_DISPATCHING.
		 */
		if (p->scx.holding_cpu >= 0)
			p->scx.holding_cpu = -1;
		return;
	}

	if (!is_local)
		raw_spin_lock(&dsq->lock);

	/*
	 * Now that we hold @dsq->lock, @p->holding_cpu and @p->scx.dsq_node
	 * can't change underneath us.
	*/
	if (p->scx.holding_cpu < 0) {
		/* @p must still be on @dsq, dequeue */
		WARN_ON_ONCE(list_empty(&p->scx.dsq_node));
		list_del_init(&p->scx.dsq_node);
		dsq->nr--;
	} else {
		/*
		 * We're racing against dispatch_to_local_dsq() which already
		 * removed @p from @dsq and set @p->scx.holding_cpu. Clear the
		 * holding_cpu which tells dispatch_to_local_dsq() that it lost
		 * the race.
		 */
		WARN_ON_ONCE(!list_empty(&p->scx.dsq_node));
		p->scx.holding_cpu = -1;
	}
	p->scx.dsq = NULL;

	if (!is_local)
		raw_spin_unlock(&dsq->lock);
}

static struct scx_dispatch_q *find_non_local_dsq(u64 dsq_id)
{
	lockdep_assert(rcu_read_lock_any_held());

	if (dsq_id == SCX_DSQ_GLOBAL)
		return &scx_dsq_global;
	else
		return rhashtable_lookup_fast(&dsq_hash, &dsq_id,
					      dsq_hash_params);
}

static struct scx_dispatch_q *find_dsq_for_dispatch(struct rq *rq, u64 dsq_id,
						    struct task_struct *p)
{
	struct scx_dispatch_q *dsq;

	if (dsq_id == SCX_DSQ_LOCAL)
		return &rq->scx.local_dsq;

	dsq = find_non_local_dsq(dsq_id);
	if (unlikely(!dsq)) {
		scx_ops_error("non-existent dsq 0x%llx for %s[%d]",
			      dsq_id, p->comm, p->pid);
		return &scx_dsq_global;
	}

	return dsq;
}

static void direct_dispatch(struct task_struct *ddsp_task, struct task_struct *p,
			    u64 dsq_id, u64 enq_flags)
{
	struct scx_dispatch_q *dsq;

	/* @p must match the task which is being enqueued */
	if (unlikely(p != ddsp_task)) {
		if (IS_ERR(ddsp_task))
			scx_ops_error("%s[%d] already direct-dispatched",
				      p->comm, p->pid);
		else
			scx_ops_error("enqueueing %s[%d] but trying to direct-dispatch %s[%d]",
				      ddsp_task->comm, ddsp_task->pid,
				      p->comm, p->pid);
		return;
	}

	/*
	 * %SCX_DSQ_LOCAL_ON is not supported during direct dispatch because
	 * dispatching to the local dsq of a different CPU requires unlocking
	 * the current rq which isn't allowed in the enqueue path. Use
	 * ops.select_cpu() to be on the target CPU and then %SCX_DSQ_LOCAL.
	 */
	if (unlikely((dsq_id & SCX_DSQ_LOCAL_ON) == SCX_DSQ_LOCAL_ON)) {
		scx_ops_error("SCX_DSQ_LOCAL_ON can't be used for direct-dispatch");
		return;
	}

	dsq = find_dsq_for_dispatch(task_rq(p), dsq_id, p);
	dispatch_enqueue(dsq, p, enq_flags | SCX_ENQ_CLEAR_OPSS);

	/*
	 * Mark that dispatch already happened by spoiling direct_dispatch_task
	 * with a non-NULL value which can never match a valid task pointer.
	 */
	__this_cpu_write(direct_dispatch_task, ERR_PTR(-ESRCH));
}

static void do_enqueue_task(struct rq *rq, struct task_struct *p, u64 enq_flags,
			    int sticky_cpu)
{
	struct task_struct **ddsp_taskp;
	u64 qseq;

	WARN_ON_ONCE(!(p->scx.flags & SCX_TASK_QUEUED));

	if (p->scx.flags & SCX_TASK_ENQ_LOCAL) {
		enq_flags |= SCX_ENQ_LOCAL;
		p->scx.flags &= ~SCX_TASK_ENQ_LOCAL;
	}

	/* rq migration */
	if (sticky_cpu == cpu_of(rq))
		goto local_norefill;

	/*
	 * If !rq->online, we already told the BPF scheduler that the CPU is
	 * offline. We're just trying to on/offline the CPU. Don't bother the
	 * BPF scheduler.
	 */
	if (unlikely(!rq->online))
		goto local;

	/* see %SCX_OPS_ENQ_EXITING */
	if (!static_branch_unlikely(&scx_ops_enq_exiting) &&
	    unlikely(p->flags & PF_EXITING))
		goto local;

	/* see %SCX_OPS_ENQ_LAST */
	if (!static_branch_unlikely(&scx_ops_enq_last) &&
	    (enq_flags & SCX_ENQ_LAST))
		goto local;

	if (!SCX_HAS_OP(enqueue)) {
		if (enq_flags & SCX_ENQ_LOCAL)
			goto local;
		else
			goto global;
	}

	/* dsq bypass didn't trigger, enqueue on the BPF scheduler */
	qseq = rq->scx.ops_qseq++ << SCX_OPSS_QSEQ_SHIFT;

	WARN_ON_ONCE(atomic64_read(&p->scx.ops_state) != SCX_OPSS_NONE);
	atomic64_set(&p->scx.ops_state, SCX_OPSS_QUEUEING | qseq);

	ddsp_taskp = this_cpu_ptr(&direct_dispatch_task);
	WARN_ON_ONCE(*ddsp_taskp);
	*ddsp_taskp = p;

	scx_ops.enqueue(p, enq_flags);

	/*
	 * If not directly dispatched, QUEUEING isn't clear yet and dispatch or
	 * dequeue may be waiting. The store_release matches their load_acquire.
	 */
	if (*ddsp_taskp == p)
		atomic64_set_release(&p->scx.ops_state, SCX_OPSS_QUEUED | qseq);
	*ddsp_taskp = NULL;
	return;

local:
	p->scx.slice = SCX_SLICE_DFL;
local_norefill:
	dispatch_enqueue(&rq->scx.local_dsq, p, enq_flags);
	return;

global:
	p->scx.slice = SCX_SLICE_DFL;
	dispatch_enqueue(&scx_dsq_global, p, enq_flags);
}

static void enqueue_task_scx(struct rq *rq, struct task_struct *p, int enq_flags)
{
	int sticky_cpu = p->scx.sticky_cpu;

	if (sticky_cpu >= 0)
		p->scx.sticky_cpu = -1;

	/*
	 * Restoring a running task will be immediately followed by
	 * set_next_task_scx() which expects the task to not be on the BPF
	 * scheduler as tasks can only start running through local dsqs. Force
	 * direct-dispatch into the local dsq by setting the sticky_cpu.
	 */
	if (unlikely(enq_flags & ENQUEUE_RESTORE) && task_current(rq, p))
		sticky_cpu = cpu_of(rq);

	if (p->scx.flags & SCX_TASK_QUEUED)
		return;

	p->scx.flags |= SCX_TASK_QUEUED;
	rq->scx.nr_running++;
	add_nr_running(rq, 1);

	do_enqueue_task(rq, p, enq_flags, sticky_cpu);
}

static void dequeue_task_scx(struct rq *rq, struct task_struct *p, int deq_flags)
{
	struct scx_rq *scx_rq = &rq->scx;
	u64 opss;

	if (!(p->scx.flags & SCX_TASK_QUEUED))
		return;

	/* acquire ensures that we see the preceding updates on QUEUED */
	opss = atomic64_read_acquire(&p->scx.ops_state);

	switch (opss & SCX_OPSS_STATE_MASK) {
	case SCX_OPSS_NONE:
		break;
	case SCX_OPSS_QUEUEING:
		BUG();
	case SCX_OPSS_QUEUED:
		if (SCX_HAS_OP(dequeue))
			scx_ops.dequeue(p, deq_flags);

		if (atomic64_try_cmpxchg(&p->scx.ops_state, &opss,
					 SCX_OPSS_NONE))
			break;
		fallthrough;
	case SCX_OPSS_DISPATCHING:
		/*
		 * If @p is being dispatched from the BPF scheduler to a dsq,
		 * wait for the transfer to complete so that @p doesn't get
		 * added to its dsq after dequeueing is complete.
		 *
		 * As we're waiting on DISPATCHING with @rq locked, the
		 * dispatching side shouldn't try to lock @rq while DISPATCHING
		 * is set. See dispatch_to_local_dsq().
		 */
		wait_ops_state(p, SCX_OPSS_DISPATCHING);
		BUG_ON(atomic64_read(&p->scx.ops_state) != SCX_OPSS_NONE);
		break;
	}

	p->scx.flags &= ~SCX_TASK_QUEUED;
	scx_rq->nr_running--;
	sub_nr_running(rq, 1);

	dispatch_dequeue(scx_rq, p);
}

static void yield_task_scx(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (SCX_HAS_OP(yield))
		scx_ops.yield(p, NULL);
	else
		p->scx.slice = 0;
}

static bool yield_to_task_scx(struct rq *rq, struct task_struct *to)
{
	struct task_struct *from = rq->curr;

	if (SCX_HAS_OP(yield))
		return scx_ops.yield(from, to);
	else
		return false;
}

#ifdef CONFIG_SMP
/**
 * move_task_to_local_dsq - Move a task from a different rq to a local dsq
 * @rq: rq to move the task into, currently locked
 * @p: task to move
 *
 * Move @p which is currently on a different rq to @rq's local dsq. The caller
 * must:
 *
 * 1. Start with exclusive access to @p either through its dsq lock or
 *    %SCX_OPSS_DISPATCHING flag.
 *
 * 2. Set @p->scx.holding_cpu to raw_smp_processor_id().
 *
 * 3. Remember task_rq(@p). Release the exclusive access so that we don't
 *    deadlock with dequeue.
 *
 * 4. Lock @rq and the task_rq from #3.
 *
 * 5. Call this function.
 *
 * Returns %true if @p was successfully moved. %false after racing dequeue and
 * losing.
 */
static bool move_task_to_local_dsq(struct rq *rq, struct task_struct *p)
{
	struct rq *task_rq;

	lockdep_assert_rq_held(rq);

	/*
	 * If dequeue got to @p while we were trying to lock both rq's, it'd
	 * have cleared @p->scx.holding_cpu to -1. While other cpus may have
	 * updated it to different values afterwards, as this operation can't be
	 * preempted or recurse, @p->scx.holding_cpu can never become
	 * raw_smp_processor_id() again before we're done. Thus, we can tell
	 * whether we lost to dequeue by testing whether @p->scx.holding_cpu is
	 * still raw_smp_processor_id().
	 *
	 * See dispatch_dequeue() for the counterpart.
	 */
	if (unlikely(p->scx.holding_cpu != raw_smp_processor_id()))
		return false;

	/* @p->rq couldn't have changed if we're still the holding cpu */
	task_rq = task_rq(p);
	lockdep_assert_rq_held(task_rq);

	WARN_ON_ONCE(!cpumask_test_cpu(cpu_of(rq), p->cpus_ptr));
	deactivate_task(task_rq, p, 0);
	set_task_cpu(p, cpu_of(rq));
	p->scx.sticky_cpu = cpu_of(rq);
	activate_task(rq, p, 0);

	return true;
}

/**
 * dispatch_to_local_dsq_lock - Ensure source and desitnation rq's are locked
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @src_rq: rq to move task from
 * @dst_rq: rq to move task to
 *
 * We're holding @rq lock and trying to dispatch a task from @src_rq to
 * @dst_rq's local dsq and thus need to lock both @src_rq and @dst_rq. Whether
 * @rq stays locked isn't important as long as the state is restored after
 * dispatch_to_local_dsq_unlock().
 */
static void dispatch_to_local_dsq_lock(struct rq *rq, struct rq_flags *rf,
				       struct rq *src_rq, struct rq *dst_rq)
{
	rq_unpin_lock(rq, rf);

	if (src_rq == dst_rq) {
		raw_spin_rq_unlock(rq);
		raw_spin_rq_lock(dst_rq);
	} else if (rq == src_rq) {
		double_lock_balance(rq, dst_rq);
		rq_repin_lock(rq, rf);
	} else if (rq == dst_rq) {
		double_lock_balance(rq, src_rq);
		rq_repin_lock(rq, rf);
	} else {
		raw_spin_rq_unlock(rq);
		double_rq_lock(src_rq, dst_rq);
	}
}

/**
 * dispatch_to_local_dsq_unlock - Undo dispatch_to_local_dsq_lock()
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @src_rq: rq to move task from
 * @dst_rq: rq to move task to
 *
 * Unlock @src_rq and @dst_rq and ensure that @rq is locked on return.
 */
static void dispatch_to_local_dsq_unlock(struct rq *rq, struct rq_flags *rf,
					 struct rq *src_rq, struct rq *dst_rq)
{
	if (src_rq == dst_rq) {
		raw_spin_rq_unlock(dst_rq);
		raw_spin_rq_lock(rq);
		rq_repin_lock(rq, rf);
	} else if (rq == src_rq) {
		double_unlock_balance(rq, dst_rq);
	} else if (rq == dst_rq) {
		double_unlock_balance(rq, src_rq);
	} else {
		double_rq_unlock(src_rq, dst_rq);
		raw_spin_rq_lock(rq);
		rq_repin_lock(rq, rf);
	}
}
#endif

static void set_consume_ctx(struct rq *rq, struct rq_flags *rf)
{
	*this_cpu_ptr(&consume_ctx) = (struct consume_ctx){ .rq = rq, .rf = rf };
}

static bool consume_dispatch_q(struct rq *rq, struct rq_flags *rf,
			       struct scx_dispatch_q *dsq)
{
	struct scx_rq *scx_rq = &rq->scx;
	struct task_struct *p;
	struct rq *task_rq;
	bool moved = false;
retry:
	if (list_empty(&dsq->fifo))
		return false;

	raw_spin_lock(&dsq->lock);
	list_for_each_entry(p, &dsq->fifo, scx.dsq_node) {
		task_rq = task_rq(p);
		if (rq == task_rq)
			goto this_rq;
		if (likely(rq->online) && !is_migration_disabled(p) &&
		    cpumask_test_cpu(cpu_of(rq), p->cpus_ptr))
			goto remote_rq;
	}
	raw_spin_unlock(&dsq->lock);
	return false;

this_rq:
	/* @dsq is locked and @p is on this rq */
	WARN_ON_ONCE(p->scx.holding_cpu >= 0);
	list_move_tail(&p->scx.dsq_node, &scx_rq->local_dsq.fifo);
	dsq->nr--;
	scx_rq->local_dsq.nr++;
	p->scx.dsq = &scx_rq->local_dsq;
	raw_spin_unlock(&dsq->lock);
	return true;

remote_rq:
#ifdef CONFIG_SMP
	/*
	 * @dsq is locked and @p is on a remote rq. @p is currently protected by
	 * @dsq->lock. We want to pull @p to @rq but may deadlock if we grab
	 * @task_rq while holding @dsq and @rq locks. As dequeue can't drop the
	 * rq lock or fail, do a little dancing from our side. See
	 * move_task_to_local_dsq().
	 */
	WARN_ON_ONCE(p->scx.holding_cpu >= 0);
	list_del_init(&p->scx.dsq_node);
	dsq->nr--;
	p->scx.holding_cpu = raw_smp_processor_id();
	raw_spin_unlock(&dsq->lock);

	rq_unpin_lock(rq, rf);
	double_lock_balance(rq, task_rq);
	rq_repin_lock(rq, rf);

	moved = move_task_to_local_dsq(rq, p);

	double_unlock_balance(rq, task_rq);
#endif /* CONFIG_SMP */
	if (likely(moved))
		return true;
	goto retry;
}

enum dispatch_to_local_dsq_ret {
	DTL_DISPATCHED,		/* successfully dispatched */
	DTL_LOST,		/* lost race to dequeue */
	DTL_NOT_LOCAL,		/* destination is not a local dsq */
	DTL_INVALID,		/* invalid local dsq_id */
};

/**
 * dispatch_to_local_dsq - Dispatch a task to a local dsq
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @dsq_id: destination dsq ID
 * @p: task to dispatch
 * @enq_flags: %SCX_ENQ_*
 *
 * We're holding @rq lock and want to dispatch @p to the local dsq identified by
 * @dsq_id. This function performs all the synchronization dancing needed
 * because local dsq's are protected with rq locks.
 *
 * The caller must have exclusive ownership of @p (e.g. through
 * %SCX_OPSS_DISPATCHING).
 */
static enum dispatch_to_local_dsq_ret
dispatch_to_local_dsq(struct rq *rq, struct rq_flags *rf, u64 dsq_id,
		      struct task_struct *p, u64 enq_flags)
{
	struct rq *src_rq = task_rq(p);
	struct rq *dst_rq;

	/*
	 * We're synchronized against dequeue through DISPATCHING. As @p can't
	 * be dequeued, its task_rq and cpus_allowed are stable too.
	 */
	if (dsq_id == SCX_DSQ_LOCAL) {
		dst_rq = rq;
	} else if ((dsq_id & SCX_DSQ_LOCAL_ON) == SCX_DSQ_LOCAL_ON) {
		s32 cpu = dsq_id & SCX_DSQ_LOCAL_CPU_MASK;

		if (!ops_cpu_valid(cpu)) {
			scx_ops_error("invalid cpu %d in SCX_DSQ_LOCAL_ON verdict for %s[%d]",
				      cpu, p->comm, p->pid);
			return DTL_INVALID;
		}
		dst_rq = cpu_rq(cpu);
	} else {
		return DTL_NOT_LOCAL;
	}

	/* if dispatching to @rq that @p is already on, no lock dancing needed */
	if (rq == src_rq && rq == dst_rq) {
		dispatch_enqueue(&dst_rq->scx.local_dsq, p,
				 enq_flags | SCX_ENQ_CLEAR_OPSS);
		return DTL_DISPATCHED;
	}

#ifdef CONFIG_SMP
	if (cpumask_test_cpu(cpu_of(dst_rq), p->cpus_ptr)) {
		struct rq *locked_dst_rq = dst_rq;
		bool dsp;

		/*
		 * @p is on a possibly remote @src_rq which we need to lock to
		 * move the task. If dequeue is in progress, it'd be locking
		 * @src_rq and waiting on DISPATCHING, so we can't grab @src_rq
		 * lock while holding DISPATCHING.
		 *
		 * As DISPATCHING guarantees that @p is wholly ours, we can
		 * pretend that we're moving from a dsq and use the same
		 * mechanism - mark the task under transfer with holding_cpu,
		 * release DISPATCHING and then follow the same protocol.
		 */
		p->scx.holding_cpu = raw_smp_processor_id();

		/* store_release ensures that dequeue sees the above */
		atomic64_set_release(&p->scx.ops_state, SCX_OPSS_NONE);

		dispatch_to_local_dsq_lock(rq, rf, src_rq, locked_dst_rq);

		/*
		 * We don't require the BPF scheduler to avoid dispatching to
		 * offline CPUs mostly for convenience but also because CPUs can
		 * go offline between scx_bpf_dispatch() calls and here. If @p
		 * is destined to an offline CPU, queue it on its current CPU
		 * instead, which should always be safe. As this is an allowed
		 * behavior, don't trigger an ops error.
		 */
		if (unlikely(!dst_rq->online))
			dst_rq = src_rq;

		if (src_rq == dst_rq) {
			/*
			 * As @p is staying on the same rq, there's no need to
			 * go through the full deactivate/activate cycle.
			 * Optimize by abbreviating the operations in
			 * move_task_to_local_dsq().
			 */
			dsp = p->scx.holding_cpu == raw_smp_processor_id();
			if (likely(dsp)) {
				p->scx.holding_cpu = -1;
				dispatch_enqueue(&dst_rq->scx.local_dsq, p,
						 enq_flags);
			}
		} else {
			dsp = move_task_to_local_dsq(dst_rq, p);
		}

		/* if the destination CPU is idle, wake it up */
		if (dsp && p->sched_class > dst_rq->curr->sched_class)
			resched_curr(dst_rq);

		dispatch_to_local_dsq_unlock(rq, rf, src_rq, locked_dst_rq);

		return dsp ? DTL_DISPATCHED : DTL_LOST;
	}
#endif /* CONFIG_SMP */

	scx_ops_error("SCX_DSQ_LOCAL[_ON] verdict target cpu %d not allowed for %s[%d]",
		      cpu_of(dst_rq), p->comm, p->pid);
	return DTL_INVALID;
}

/**
 * finish_dispatch - Asynchronously finish dispatching a task
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @p: task to finish dispatching
 * @qseq_at_dispatch: qseq when @p started getting dispatched
 * @dsq_id: destination dsq ID
 * @enq_flags: %SCX_ENQ_*
 *
 * Dispatching to local dsq's may need to wait for queueing to complete or
 * require rq lock dancing. As we don't wanna do either while inside
 * ops.dispatch() to avoid locking order inversion, we split dispatching into
 * two parts. scx_bpf_dispatch() which is called by ops.dispatch() records the
 * task and its qseq. Once ops.dispatch() returns, this function is called to
 * finish up.
 *
 * There is no guarantee that @p is still valid for dispatching or even that it
 * was valid in the first place. Make sure that the task is still owned by the
 * BPF scheduler and claim the ownership before dispatching.
 */
static bool finish_dispatch(struct rq *rq, struct rq_flags *rf,
			    struct task_struct *p, u64 qseq_at_dispatch,
			    u64 dsq_id, u64 enq_flags)
{
	struct scx_dispatch_q *dsq;
	u64 opss;

retry:
	/*
	 * No need for _acquire here. @p is accessed only after a successful
	 * try_cmpxchg to DISPATCHING.
	 */
	opss = atomic64_read(&p->scx.ops_state);

	switch (opss & SCX_OPSS_STATE_MASK) {
	case SCX_OPSS_DISPATCHING:
	case SCX_OPSS_NONE:
		/* someone else already got to it */
		return false;
	case SCX_OPSS_QUEUED:
		/*
		 * If qseq doesn't match, @p has gone through at least one
		 * dispatch/dequeue and re-enqueue cycle between
		 * scx_bpf_dispatch() and here and we have no claim on it.
		 */
		if ((opss & SCX_OPSS_QSEQ_MASK) != qseq_at_dispatch)
			return false;

		/*
		 * While we know @p is accessible, we don't yet have a claim on
		 * it - the BPF scheduler is allowed to dispatch tasks
		 * spuriously and there can be a racing dequeue attempt. Let's
		 * claim @p by atomically transitioning it from QUEUED to
		 * DISPATCHING.
		 */
		if (likely(atomic64_try_cmpxchg(&p->scx.ops_state, &opss,
						SCX_OPSS_DISPATCHING)))
			break;
		goto retry;
	case SCX_OPSS_QUEUEING:
		/*
		 * do_enqueue_task() is in the process of transferring the task
		 * to the BPF scheduler while holding @p's rq lock. As we aren't
		 * holding any kernel or BPF resource that the enqueue path may
		 * depend upon, it's safe to wait.
		 */
		wait_ops_state(p, opss);
		goto retry;
	}

	BUG_ON(!(p->scx.flags & SCX_TASK_QUEUED));

	switch (dispatch_to_local_dsq(rq, rf, dsq_id, p, enq_flags)) {
	case DTL_DISPATCHED:
		return true;
	case DTL_LOST:
		return false;
	case DTL_INVALID:
		dsq_id = SCX_DSQ_GLOBAL;
		break;
	case DTL_NOT_LOCAL:
		break;
	}

	dsq = find_dsq_for_dispatch(cpu_rq(raw_smp_processor_id()), dsq_id, p);
	dispatch_enqueue(dsq, p, enq_flags | SCX_ENQ_CLEAR_OPSS);
	return false;
}

int balance_scx(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct scx_rq *scx_rq = &rq->scx;
	bool prev_on_scx = prev->sched_class == &ext_sched_class;

	lockdep_assert_rq_held(rq);

	if (prev_on_scx) {
		WARN_ON_ONCE(prev->scx.flags & SCX_TASK_BAL_KEEP);
		update_curr_scx(rq);

		/*
		 * If @prev is runnable & has slice left, it has priority and
		 * fetching more just increases latency for the fetched tasks.
		 * Tell put_prev_task_scx() to put @prev on local_dsq.
		 *
		 * See scx_ops_disable_workfn() for the explanation on the
		 * disabling() test.
		 */
		if ((prev->scx.flags & SCX_TASK_QUEUED) &&
		    prev->scx.slice > 0 && !scx_ops_disabling()) {
			prev->scx.flags |= SCX_TASK_BAL_KEEP;
			return 1;
		}
	}
retry:
	/* if there already are tasks to run, nothing to do */
	if (scx_rq->local_dsq.nr)
		return 1;

	if (SCX_HAS_OP(consume)) {
		set_consume_ctx(rq, rf);
		scx_ops.consume(cpu_of(rq));
		if (scx_rq->local_dsq.nr)
			return 1;
	} else {
		if (consume_dispatch_q(rq, rf, &scx_dsq_global))
			return 1;
	}

	if (SCX_HAS_OP(dispatch)) {
		int i, nr, nr_local = 0;

		*this_cpu_ptr(&dispatch_buf_cursor) = 0;

		if (prev_on_scx)
			scx_ops.dispatch(cpu_of(rq), prev);
		else
			scx_ops.dispatch(cpu_of(rq), NULL);

		nr = this_cpu_read(dispatch_buf_cursor);
		if (!nr) {
			if (SCX_HAS_OP(consume_final)) {
				set_consume_ctx(rq, rf);
				scx_ops.consume_final(cpu_of(rq));
				return rq->scx.local_dsq.nr > 0;
			}
			return 0;
		}

		for (i = 0; i < nr; i++) {
			struct dispatch_buf_ent *ent =
				&this_cpu_ptr(dispatch_buf)[i];

			if (finish_dispatch(rq, rf, ent->task, ent->qseq,
					    ent->dsq_id, ent->enq_flags))
				nr_local++;
		}

		if (nr_local)
			return 1;
		else
			goto retry;
	}

	return 0;
}

static void set_next_task_scx(struct rq *rq, struct task_struct *p, bool first)
{
	if (p->scx.flags & SCX_TASK_QUEUED) {
		WARN_ON_ONCE(atomic64_read(&p->scx.ops_state) != SCX_OPSS_NONE);
		dispatch_dequeue(&rq->scx, p);
	}

	p->se.exec_start = rq_clock_task(rq);
}

static void put_prev_task_scx(struct rq *rq, struct task_struct *p)
{
	update_curr_scx(rq);

	/*
	 * If we're being called from put_prev_task_balance(), balance_scx() may
	 * have decided that @p should keep running.
	 */
	if (p->scx.flags & SCX_TASK_BAL_KEEP) {
		p->scx.flags &= ~SCX_TASK_BAL_KEEP;
		dispatch_enqueue(&rq->scx.local_dsq, p, SCX_ENQ_HEAD);
		return;
	}

	if (p->scx.flags & SCX_TASK_QUEUED) {
		/*
		 * If @p has slice left and balance_scx() didn't tag it for
		 * keeping, @p is getting preempted by a higher priority
		 * scheduler class. Leave it at the head of the local dsq.
		 */
		if (p->scx.slice > 0 && !scx_ops_disabling()) {
			dispatch_enqueue(&rq->scx.local_dsq, p, SCX_ENQ_HEAD);
			return;
		}

		/*
		 * If we're in the pick_next_task path, balance_scx() should
		 * have already populated the local dsq if there are any other
		 * available tasks. If empty, tell ops.enqueue() that @p is the
		 * only one available for this cpu. ops.enqueue() should put it
		 * on the local dsq so that the subsequent pick_next_task_scx()
		 * can find the task unless it wants to trigger a separate
		 * follow-up scheduling event.
		 */
		if (list_empty(&rq->scx.local_dsq.fifo))
			do_enqueue_task(rq, p, SCX_ENQ_LAST | SCX_ENQ_LOCAL, -1);
		else
			do_enqueue_task(rq, p, 0, -1);
	}
}

static struct task_struct *pick_task_scx(struct rq *rq)
{
	return list_first_entry_or_null(&rq->scx.local_dsq.fifo,
					struct task_struct, scx.dsq_node);
}

static struct task_struct *pick_next_task_scx(struct rq *rq)
{
	struct task_struct *p;

	p = pick_task_scx(rq);
	if (!p)
		return NULL;

	if (unlikely(!p->scx.slice)) {
		if (!scx_ops_disabling() && !warned_zero_slice) {
			printk_deferred(KERN_WARNING "sched_ext: %s[%d] has zero slice in pick_next_task_scx()\n",
					p->comm, p->pid);
			warned_zero_slice = true;
		}
		p->scx.slice = SCX_SLICE_DFL;
	}

	set_next_task_scx(rq, p, true);

	return p;
}

#ifdef CONFIG_SMP

static bool test_and_clear_cpu_idle(int cpu)
{
	if (cpumask_test_and_clear_cpu(cpu, idle_masks.cpu)) {
		if (cpumask_empty(idle_masks.cpu))
			has_idle_cpus = false;
		return true;
	} else {
		return false;
	}
}

static int scx_pick_idle_cpu(const struct cpumask *cpus_allowed)
{
	int cpu;

	do {
		cpu = cpumask_any_and_distribute(idle_masks.smt, cpus_allowed);
		if (cpu < nr_cpu_ids) {
			const struct cpumask *sbm = topology_sibling_cpumask(cpu);

			/*
			 * If offline, @cpu is not its own sibling and we can
			 * get caught in an infinite loop as @cpu is never
			 * cleared from idle_masks.smt. Clear @cpu directly in
			 * such cases.
			 */
			if (likely(cpumask_test_cpu(cpu, sbm)))
				cpumask_andnot(idle_masks.smt, idle_masks.smt, sbm);
			else
				cpumask_andnot(idle_masks.smt, idle_masks.smt, cpumask_of(cpu));
		} else {
			cpu = cpumask_any_and_distribute(idle_masks.cpu, cpus_allowed);
			if (cpu >= nr_cpu_ids)
				return -EBUSY;
		}
	} while (!test_and_clear_cpu_idle(cpu));

	return cpu;
}

static s32 scx_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (!static_branch_likely(&scx_builtin_idle_enabled)) {
		scx_ops_error("built-in idle tracking is disabled");
		return prev_cpu;
	}

	/*
	 * If WAKE_SYNC and the machine isn't fully saturated, wake up @p to the
	 * local dsq of the waker.
	 */
	if ((wake_flags & SCX_WAKE_SYNC) && p->nr_cpus_allowed > 1 &&
	    has_idle_cpus && !(current->flags & PF_EXITING)) {
		cpu = smp_processor_id();
		if (cpumask_test_cpu(cpu, p->cpus_ptr)) {
			p->scx.flags |= SCX_TASK_ENQ_LOCAL;
			return cpu;
		}
	}

	/* if the previous CPU is idle, dispatch directly to it */
	if (test_and_clear_cpu_idle(prev_cpu)) {
		p->scx.flags |= SCX_TASK_ENQ_LOCAL;
		return prev_cpu;
	}

	if (p->nr_cpus_allowed == 1)
		return prev_cpu;

	cpu = scx_pick_idle_cpu(p->cpus_ptr);
	if (cpu >= 0) {
		p->scx.flags |= SCX_TASK_ENQ_LOCAL;
		return cpu;
	}

	return prev_cpu;
}

static int select_task_rq_scx(struct task_struct *p, int prev_cpu, int wake_flags)
{
	if (SCX_HAS_OP(select_cpu)) {
		s32 cpu;

		cpu = scx_ops.select_cpu(p, prev_cpu, wake_flags);
		if (ops_cpu_valid(cpu)) {
			return cpu;
		} else {
			scx_ops_error("select_cpu returned invalid cpu %d", cpu);
			return prev_cpu;
		}
	} else {
		return scx_select_cpu_dfl(p, prev_cpu, wake_flags);
	}
}

static void set_cpus_allowed_scx(struct task_struct *p,
				 const struct cpumask *new_mask, u32 flags)
{
	set_cpus_allowed_common(p, new_mask, flags);

	/*
	 * The effective cpumask is stored in @p->cpus_ptr which may temporarily
	 * differ from the configured one in @p->cpus_mask. Always tell the bpf
	 * scheduler the effective one.
	 *
	 * Fine-grained memory write control is enforced by BPF making the const
	 * designation pointless. Cast it away when calling the operation.
	 */
	if (SCX_HAS_OP(set_cpumask))
		scx_ops.set_cpumask(p, (struct cpumask *)p->cpus_ptr);
}

static void reset_idle_masks(void)
{
	/* consider all cpus idle, should converge to the actual state quickly */
	cpumask_setall(idle_masks.cpu);
	cpumask_setall(idle_masks.smt);
	has_idle_cpus = true;
}

void __scx_update_idle(struct rq *rq, bool idle)
{
	int cpu = cpu_of(rq);
	struct cpumask *sib_mask = topology_sibling_cpumask(cpu);

	if (SCX_HAS_OP(update_idle)) {
		scx_ops.update_idle(cpu_of(rq), idle);
		if (!static_branch_unlikely(&scx_builtin_idle_enabled))
			return;
	}

	if (idle) {
		cpumask_set_cpu(cpu, idle_masks.cpu);
		if (!has_idle_cpus)
			has_idle_cpus = true;

		/*
		 * idle_masks.smt handling is racy but that's fine as it's only
		 * for optimization and self-correcting.
		 */
		for_each_cpu(cpu, sib_mask) {
			if (!cpumask_test_cpu(cpu, idle_masks.cpu))
				return;
		}
		cpumask_or(idle_masks.smt, idle_masks.smt, sib_mask);
	} else {
		cpumask_clear_cpu(cpu, idle_masks.cpu);
		if (has_idle_cpus && cpumask_empty(idle_masks.cpu))
			has_idle_cpus = false;

		cpumask_andnot(idle_masks.smt, idle_masks.smt, sib_mask);
	}
}

#else /* !CONFIG_SMP */

static bool test_and_clear_cpu_idle(int cpu) { return false; }
static int scx_pick_idle_cpu(const struct cpumask *cpus_allowed) { return -EBUSY; }
static void reset_idle_masks(void) {}

#endif /* CONFIG_SMP */

static void task_tick_scx(struct rq *rq, struct task_struct *curr, int queued)
{
	update_curr_scx(rq);

	/* always resched while disabling as we can't trust the slice */
	if (!curr->scx.slice || scx_ops_disabling())
		resched_curr(rq);
}

static int scx_ops_prepare_task(struct task_struct *p, struct task_group *tg)
{
	int ret;

	WARN_ON_ONCE(p->scx.flags & SCX_TASK_OPS_PREPPED);

	if (SCX_HAS_OP(prep_enable)) {
		struct scx_enable_args args = { };

		ret = scx_ops.prep_enable(p, &args);
		if (unlikely(ret)) {
			ret = ops_sanitize_err("prep_enable", ret);
			return ret;
		}
	}

	p->scx.flags |= SCX_TASK_OPS_PREPPED;
	return 0;
}

static void scx_ops_enable_task(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));
	WARN_ON_ONCE(!(p->scx.flags & SCX_TASK_OPS_PREPPED));

	if (SCX_HAS_OP(enable)) {
		struct scx_enable_args args = { };
		scx_ops.enable(p, &args);
	}
	p->scx.flags &= ~SCX_TASK_OPS_PREPPED;
	p->scx.flags |= SCX_TASK_OPS_ENABLED;
}

static void scx_ops_disable_task(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));

	if (p->scx.flags & SCX_TASK_OPS_PREPPED) {
		if (SCX_HAS_OP(cancel_enable)) {
			struct scx_enable_args args = { };
			scx_ops.cancel_enable(p, &args);
		}
		p->scx.flags &= ~SCX_TASK_OPS_PREPPED;
	} else if (p->scx.flags & SCX_TASK_OPS_ENABLED) {
		if (SCX_HAS_OP(disable))
			scx_ops.disable(p);
		p->scx.flags &= ~SCX_TASK_OPS_ENABLED;
	}
}

/**
 * refresh_scx_weight - Refresh a task's ext weight
 * @p: task to refresh ext weight for
 *
 * @p->scx.weight carries the task's static priority in cgroup weight scale to
 * enable easy access from the BPF scheduler. To keep it synchronized with the
 * current task priority, this function should be called when a new task is
 * created, priority is changed for a task on sched_ext, and a task is switched
 * to sched_ext from other classes.
 */
static void refresh_scx_weight(struct task_struct *p)
{
	u32 weight = sched_prio_to_weight[p->static_prio - MAX_RT_PRIO];

	p->scx.weight = sched_weight_to_cgroup(weight);
}

void scx_pre_fork(struct task_struct *p)
{
	/*
	 * BPF scheduler enable/disable paths want to be able to iterate and
	 * update all tasks which can become complex when racing forks. As
	 * enable/disable are very cold paths, let's use a percpu_rwsem to
	 * exclude forks.
	 */
	percpu_down_read(&scx_fork_rwsem);
}

int scx_fork(struct task_struct *p)
{
	percpu_rwsem_assert_held(&scx_fork_rwsem);

	if (scx_enabled())
		return scx_ops_prepare_task(p, task_group(p));
	else
		return 0;
}

void scx_post_fork(struct task_struct *p)
{
	refresh_scx_weight(p);

	if (scx_enabled()) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		scx_ops_enable_task(p);
		task_rq_unlock(rq, p, &rf);
	}

	spin_lock_irq(&scx_tasks_lock);
	list_add_tail(&p->scx.tasks_node, &scx_tasks);
	spin_unlock_irq(&scx_tasks_lock);

	percpu_up_read(&scx_fork_rwsem);
}

void scx_cancel_fork(struct task_struct *p)
{
	if (scx_enabled())
		scx_ops_disable_task(p);
	percpu_up_read(&scx_fork_rwsem);
}

void sched_ext_free(struct task_struct *p)
{
	unsigned long flags;

	spin_lock_irqsave(&scx_tasks_lock, flags);
	list_del_init(&p->scx.tasks_node);
	spin_unlock_irqrestore(&scx_tasks_lock, flags);

	/*
	 * @p is off scx_tasks and wholly ours. scx_ops_enable()'s PREPPED ->
	 * ENABLED transitions can't race us. Disable ops for @p.
	 */
	if (p->scx.flags & (SCX_TASK_OPS_PREPPED | SCX_TASK_OPS_ENABLED)) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		scx_ops_disable_task(p);
		task_rq_unlock(rq, p, &rf);
	}
}

static void reweight_task_scx(struct rq *rq, struct task_struct *p, int newprio)
{
	refresh_scx_weight(p);
}

static void prio_changed_scx(struct rq *rq, struct task_struct *p, int oldprio)
{
}

static void switching_to_scx(struct rq *rq, struct task_struct *p)
{
	refresh_scx_weight(p);

	/*
	 * set_cpus_allowed_scx() is not called while @p is associated with a
	 * different scheduler class. Keep the BPF scheduler up-to-date.
	 */
	if (SCX_HAS_OP(set_cpumask))
		scx_ops.set_cpumask(p, (struct cpumask *)p->cpus_ptr);
}

static void check_preempt_curr_scx(struct rq *rq, struct task_struct *p,int wake_flags) {}
static void switched_to_scx(struct rq *rq, struct task_struct *p) {}

/*
 * Omitted operations:
 *
 * - check_preempt_curr: NOOP as it isn't useful in the wakeup path because the
 *   task isn't tied to the CPU at that point.
 *
 * - migrate_task_rq: Unncessary as task to cpu mapping is transient.
 *
 * - task_fork/dead: We need fork/dead notifications for all tasks regardless of
 *   their current sched_class. Call them directly from sched core instead.
 *
 * - task_woken, switched_from: Unnecessary.
 */
DEFINE_SCHED_CLASS(ext) = {
	.enqueue_task		= enqueue_task_scx,
	.dequeue_task		= dequeue_task_scx,
	.yield_task		= yield_task_scx,
	.yield_to_task		= yield_to_task_scx,

	.check_preempt_curr	= check_preempt_curr_scx,

	.pick_next_task		= pick_next_task_scx,

	.put_prev_task		= put_prev_task_scx,
	.set_next_task          = set_next_task_scx,

#ifdef CONFIG_SMP
	.balance		= balance_scx,
	.select_task_rq		= select_task_rq_scx,

	.pick_task		= pick_task_scx,

	.set_cpus_allowed	= set_cpus_allowed_scx,
#endif

	.task_tick		= task_tick_scx,

	.switching_to		= switching_to_scx,
	.switched_to		= switched_to_scx,
	.reweight_task		= reweight_task_scx,
	.prio_changed		= prio_changed_scx,

	.update_curr		= update_curr_scx,

#ifdef CONFIG_UCLAMP_TASK
	.uclamp_enabled		= 0,
#endif
};

static void init_dsq(struct scx_dispatch_q *dsq, u64 dsq_id)
{
	memset(dsq, 0, sizeof(*dsq));

	raw_spin_lock_init(&dsq->lock);
	INIT_LIST_HEAD(&dsq->fifo);
	dsq->id = dsq_id;
}

static struct scx_dispatch_q *create_dsq(u64 dsq_id, int node)
{
	struct scx_dispatch_q *dsq;
	int ret;

	if (dsq_id & SCX_DSQ_FLAG_BUILTIN)
		return ERR_PTR(-EINVAL);

	dsq = kmalloc_node(sizeof(*dsq), GFP_KERNEL, node);
	if (!dsq)
		return ERR_PTR(-ENOMEM);

	init_dsq(dsq, dsq_id);

	raw_spin_lock_irq(&all_dsqs_lock);
	ret = rhashtable_insert_fast(&dsq_hash, &dsq->hash_node,
				     dsq_hash_params);
	if (!ret) {
		list_add_tail_rcu(&dsq->all_node, &all_dsqs);
	} else {
		kfree(dsq);
		dsq = ERR_PTR(ret);
	}
	raw_spin_unlock_irq(&all_dsqs_lock);
	return dsq;
}

static void free_dsq_irq_workfn(struct irq_work *irq_work)
{
	struct llist_node *to_free = llist_del_all(&dsqs_to_free);
	struct scx_dispatch_q *dsq, *tmp_dsq;

	llist_for_each_entry_safe(dsq, tmp_dsq, to_free, free_node)
		kfree_rcu(dsq);
}

static DEFINE_IRQ_WORK(free_dsq_irq_work, free_dsq_irq_workfn);

static void destroy_dsq(u64 dsq_id)
{
	struct scx_dispatch_q *dsq;
	unsigned long flags;

	rcu_read_lock();

	dsq = rhashtable_lookup_fast(&dsq_hash, &dsq_id, dsq_hash_params);
	if (!dsq)
		goto out_unlock_rcu;

	raw_spin_lock_irqsave(&all_dsqs_lock, flags);
	raw_spin_lock(&dsq->lock);

	if (dsq->nr) {
		scx_ops_error("attempting to destroy in-use dsq 0x%016llx (nr=%u)",
			      dsq->id, dsq->nr);
		goto out_unlock_dsq;
	}

	if (rhashtable_remove_fast(&dsq_hash, &dsq->hash_node, dsq_hash_params))
		goto out_unlock_dsq;

	/*
	 * Mark dead by invalidating ->id to prevent dispatch_enqueue() from
	 * queueing more tasks. As this function can be called from anywhere,
	 * freeing is bounced through an irq work to avoid nesting RCU
	 * operations inside scheduler locks.
	 */
	dsq->id = SCX_DSQ_INVALID;
	list_del_rcu(&dsq->all_node);
	llist_add(&dsq->free_node, &dsqs_to_free);
	irq_work_queue(&free_dsq_irq_work);

out_unlock_dsq:
	raw_spin_unlock(&dsq->lock);
	raw_spin_unlock_irqrestore(&all_dsqs_lock, flags);
out_unlock_rcu:
	rcu_read_unlock();
}

/*
 * Used by sched_fork() and __setscheduler_prio() to pick the matching
 * sched_class. dl/rt are already handled.
 */
bool task_on_scx(struct task_struct *p)
{
	if (!scx_enabled() || scx_ops_disabling())
		return false;
	return p->policy == SCHED_EXT;
}

static void scx_ops_fallback_enqueue(struct task_struct *p, u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_LAST)
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
	else
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

static void scx_ops_fallback_consume(s32 cpu)
{
	struct consume_ctx *cctx = this_cpu_ptr(&consume_ctx);

	consume_dispatch_q(cctx->rq, cctx->rf, &scx_dsq_global);
}

static void reset_dispatch_free_dsq_fn(void *ptr, void *arg)
{
	struct scx_dispatch_q *dsq = ptr;

	WARN_ON_ONCE(dsq->nr || !list_empty(&dsq->fifo));
	kfree(dsq);
}

static void scx_ops_disable_workfn(struct kthread_work *work)
{
	struct scx_exit_info *ei = &scx_exit_info;
	struct scx_task_iter sti;
	struct task_struct *p;
	const char *reason;
	int i, type;

	type = atomic_read(&scx_exit_type);
	while (true) {
		/*
		 * NONE indicates that a new scx_ops has been registered since
		 * disable was scheduled - don't kill the new ops. DONE
		 * indicates that the ops has already been disabled.
		 */
		if (type == SCX_EXIT_NONE || type == SCX_EXIT_DONE)
			return;
		if (atomic_try_cmpxchg(&scx_exit_type, &type, SCX_EXIT_DONE))
			break;
	}

	switch (type) {
	case SCX_EXIT_UNREG:
		reason = "BPF scheduler unregistered";
		break;
	case SCX_EXIT_SYSRQ:
		reason = "disabled by sysrq-S";
		break;
	case SCX_EXIT_ERROR:
		reason = "runtime error";
		break;
	case SCX_EXIT_ERROR_BPF:
		reason = "scx_bpf_error";
		break;
	default:
		reason = "<UNKNOWN>";
	}

	ei->type = type;
	strlcpy(ei->reason, reason, sizeof(ei->reason));

	switch (scx_ops_set_enable_state(SCX_OPS_DISABLING)) {
	case SCX_OPS_DISABLED:
		pr_warn("sched_ext: ops error detected without ops (%s)\n",
			scx_exit_info.msg);
		WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_DISABLED) !=
			     SCX_OPS_DISABLING);
		return;
	case SCX_OPS_PREPPING:
		goto forward_progress_guaranteed;
	case SCX_OPS_DISABLING:
		/* shouldn't happen but handle it like ENABLING if it does */
		WARN_ONCE(true, "sched_ext: duplicate disabling instance?");
		fallthrough;
	case SCX_OPS_ENABLING:
	case SCX_OPS_ENABLED:
		break;
	}

	/*
	 * DISABLING is set and ops was either ENABLING or ENABLED indicating
	 * that the ops and static branches are set.
	 *
	 * We must guarantee that all runnable tasks make forward progress
	 * without trusting the BPF scheduler. We can't grab any mutexes or
	 * rwsems as they might be held by tasks that the BPF scheduler is
	 * forgetting to run, which unfortunately also excludes toggling the
	 * static branches.
	 *
	 * Let's work around by overriding a couple ops and modifying behaviors
	 * based on the DISABLING state and then cycling the tasks through
	 * dequeue/enqueue to force global FIFO scheduling.
	 *
	 * a. ops.enqueue() and .consume() are overridden for simple global FIFO
	 *    scheduling.
	 *
	 * b. balance_scx() never sets %SCX_TASK_BAL_KEEP as the slice value
	 *    can't be trusted. Whenever a tick triggers, the running task is
	 *    rotated to the tail of the queue.
	 *
	 * c. pick_next_task() suppresses zero slice warning.
	 */
	scx_ops.enqueue = scx_ops_fallback_enqueue;
	scx_ops.consume = scx_ops_fallback_consume;

	spin_lock_irq(&scx_tasks_lock);
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		if (READ_ONCE(p->__state) != TASK_DEAD) {
			struct sched_enq_and_set_ctx ctx;

			sched_deq_and_put_task(p, DEQUEUE_SAVE | DEQUEUE_MOVE,
					       &ctx);
			sched_enq_and_set_task(&ctx);
		}
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);

forward_progress_guaranteed:
	/*
	 * Here, every runnable task is guaranteed to make forward progress and
	 * we can safely use blocking synchronization constructs. Actually
	 * disable ops.
	 */
	mutex_lock(&scx_ops_enable_mutex);

	/* avoid racing against fork */
	cpus_read_lock();
	percpu_down_write(&scx_fork_rwsem);

	spin_lock_irq(&scx_tasks_lock);
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		const struct sched_class *old_class = p->sched_class;
		struct sched_enq_and_set_ctx ctx;
		bool alive = READ_ONCE(p->__state) != TASK_DEAD;

		sched_deq_and_put_task(p, DEQUEUE_SAVE | DEQUEUE_MOVE, &ctx);
		p->scx.slice = min_t(u64, p->scx.slice, SCX_SLICE_DFL);

		__setscheduler_prio(p, p->prio);
		if (alive)
			check_class_changing(task_rq(p), p, old_class);

		sched_enq_and_set_task(&ctx);

		if (alive)
			check_class_changed(task_rq(p), p, old_class, p->prio);

		scx_ops_disable_task(p);
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);

	/* no task is on scx, turn off all the switches and flush in-progress calls */
	static_branch_disable_cpuslocked(&__scx_ops_enabled);
	for (i = 0; i < SCX_NR_ONLINE_OPS; i++)
		static_branch_disable_cpuslocked(&scx_has_op[i]);
	static_branch_disable_cpuslocked(&scx_ops_enq_last);
	static_branch_disable_cpuslocked(&scx_ops_enq_exiting);
	static_branch_disable_cpuslocked(&scx_builtin_idle_enabled);
	synchronize_rcu();

	percpu_up_write(&scx_fork_rwsem);
	cpus_read_unlock();

	if (ei->type >= SCX_EXIT_ERROR) {
		printk(KERN_ERR "sched_ext: BPF scheduler \"%s\" errored, disabling\n", scx_ops.name);

		if (ei->msg[0] == '\0')
			printk(KERN_ERR "sched_ext: %s\n", ei->reason);
		else
			printk(KERN_ERR "sched_ext: %s (%s)\n", ei->reason, ei->msg);

		stack_trace_print(ei->bt, ei->bt_len, 2);
	}

	if (scx_ops.exit)
		scx_ops.exit(ei);

	memset(&scx_ops, 0, sizeof(scx_ops));

	rhashtable_free_and_destroy(&dsq_hash, reset_dispatch_free_dsq_fn, NULL);
	INIT_LIST_HEAD(&all_dsqs);
	free_percpu(dispatch_buf);
	dispatch_buf = NULL;
	dispatch_max_batch = 0;

	mutex_unlock(&scx_ops_enable_mutex);

	WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_DISABLED) !=
		     SCX_OPS_DISABLING);
}

static DEFINE_KTHREAD_WORK(scx_ops_disable_work, scx_ops_disable_workfn);

static void schedule_scx_ops_disable_work(void)
{
	struct kthread_worker *helper = READ_ONCE(scx_ops_helper);

	/*
	 * We may be called spuriously before the first bpf_sched_ext_reg(). If
	 * scx_ops_helper isn't set up yet, there's nothing to do.
	 */
	if (helper)
		kthread_queue_work(helper, &scx_ops_disable_work);
}

static void scx_ops_disable(enum scx_exit_type type)
{
	int none = SCX_EXIT_NONE;

	if (WARN_ON_ONCE(type == SCX_EXIT_NONE || type == SCX_EXIT_DONE))
		type = SCX_EXIT_ERROR;

	atomic_try_cmpxchg(&scx_exit_type, &none, type);

	schedule_scx_ops_disable_work();
}

static void scx_ops_error_irq_workfn(struct irq_work *irq_work)
{
	schedule_scx_ops_disable_work();
}

static DEFINE_IRQ_WORK(scx_ops_error_irq_work, scx_ops_error_irq_workfn);

__printf(2, 3) static void scx_ops_error_type(enum scx_exit_type type,
					      const char *fmt, ...)
{
	struct scx_exit_info *ei = &scx_exit_info;
	int none = SCX_EXIT_NONE;
	va_list args;

	if (!atomic_try_cmpxchg(&scx_exit_type, &none, type))
		return;

	ei->bt_len = stack_trace_save(ei->bt, ARRAY_SIZE(ei->bt), 1);

	va_start(args, fmt);
	vscnprintf(ei->msg, ARRAY_SIZE(ei->msg), fmt, args);
	va_end(args);

	irq_work_queue(&scx_ops_error_irq_work);
}

static struct kthread_worker *scx_create_rt_helper(const char *name)
{
	struct kthread_worker *helper;

	helper = kthread_create_worker(0, name);
	if (helper)
		sched_set_fifo(helper->task);
	return helper;
}

static int scx_ops_enable(struct sched_ext_ops *ops)
{
	struct scx_task_iter sti;
	struct task_struct *p;
	int i, ret;

	mutex_lock(&scx_ops_enable_mutex);

	if (!scx_ops_helper) {
		WRITE_ONCE(scx_ops_helper,
			   scx_create_rt_helper("sched_ext_ops_helper"));
		if (!scx_ops_helper) {
			ret = -ENOMEM;
			goto err_unlock;
		}
	}

	if (scx_ops_enable_state() != SCX_OPS_DISABLED) {
		ret = -EBUSY;
		goto err_unlock;
	}

	ret = rhashtable_init(&dsq_hash, &dsq_hash_params);
	if (ret)
		goto err_unlock;

	/*
	 * Set scx_ops, transition to PREPPING and clear exit info to arm the
	 * disable path. Failure triggers full disabling from here on.
	 */
	scx_ops = *ops;

	WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_PREPPING) !=
		     SCX_OPS_DISABLED);

	memset(&scx_exit_info, 0, sizeof(scx_exit_info));
	atomic_set(&scx_exit_type, SCX_EXIT_NONE);
	warned_zero_slice = false;

	atomic64_set(&scx_nr_rejected, 0);

	/*
	 * Keep CPUs stable during enable so that the BPF scheduler can track
	 * online CPUs by watching ->on/offline_cpu() after ->init().
	 */
	cpus_read_lock();

	if (scx_ops.init) {
		ret = scx_ops.init();

		if (ret) {
			ret = ops_sanitize_err("init", ret);
			goto err_disable;
		}

		/*
		 * Exit early if ops.init() triggered scx_bpf_error(). Not
		 * strictly necessary as we'll fail transitioning into ENABLING
		 * later but that'd be after calling ops.prep_enable() on all
		 * tasks and with -EBUSY which isn't very intuitive. Let's exit
		 * early with success so that the condition is notified through
		 * ops.exit() like other scx_bpf_error() invocations.
		 */
		if (atomic_read(&scx_exit_type) != SCX_EXIT_NONE)
			goto err_disable;
	}

	WARN_ON_ONCE(dispatch_buf);
	dispatch_max_batch = ops->dispatch_max_batch ?: SCX_DSP_DFL_MAX_BATCH;
	dispatch_buf = __alloc_percpu(sizeof(dispatch_buf[0]) * dispatch_max_batch,
				      __alignof__(dispatch_buf[0]));
	if (!dispatch_buf) {
		ret = -ENOMEM;
		goto err_disable;
	}

	/*
	 * Lock out forks before opening the floodgate so that they don't wander
	 * into the operations prematurely.
	 */
	percpu_down_write(&scx_fork_rwsem);

	for (i = 0; i < SCX_NR_ONLINE_OPS; i++)
		if (((void (**)(void))ops)[i])
			static_branch_enable_cpuslocked(&scx_has_op[i]);

	if (ops->flags & SCX_OPS_ENQ_LAST)
		static_branch_enable_cpuslocked(&scx_ops_enq_last);

	if (ops->flags & SCX_OPS_ENQ_EXITING)
		static_branch_enable_cpuslocked(&scx_ops_enq_exiting);

	if (!ops->update_idle || (ops->flags & SCX_OPS_KEEP_BUILTIN_IDLE)) {
		reset_idle_masks();
		static_branch_enable_cpuslocked(&scx_builtin_idle_enabled);
	} else {
		static_branch_disable_cpuslocked(&scx_builtin_idle_enabled);
	}

	static_branch_enable_cpuslocked(&__scx_ops_enabled);

	/*
	 * Enable ops for every task. Fork is excluded by scx_fork_rwsem
	 * preventing new tasks from being added. No need to exclude tasks
	 * leaving as sched_ext_free() can handle both prepped and enabled
	 * tasks. Prep all tasks first and then enable them with preemption
	 * disabled.
	 */
	spin_lock_irq(&scx_tasks_lock);

	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered(&sti))) {
		get_task_struct(p);
		spin_unlock_irq(&scx_tasks_lock);

		ret = scx_ops_prepare_task(p, task_group(p));
		if (ret) {
			put_task_struct(p);
			spin_lock_irq(&scx_tasks_lock);
			scx_task_iter_exit(&sti);
			spin_unlock_irq(&scx_tasks_lock);
			pr_err("sched_ext: ops.prep_enable() failed (%d) for %s[%d] while loading\n",
			       ret, p->comm, p->pid);
			goto err_disable_unlock;
		}

		put_task_struct(p);
		spin_lock_irq(&scx_tasks_lock);
	}
	scx_task_iter_exit(&sti);

	/*
	 * All tasks are prepped but are still ops-disabled. Ensure that
	 * %current can't be scheduled out and switch everyone.
	 * preempt_disable() is necessary because we can't guarantee that
	 * %current won't be starved if scheduled out while switching.
	 */
	preempt_disable();

	/*
	 * From here on, the disable path must assume that tasks have ops
	 * enabled and need to be recovered.
	 */
	if (!scx_ops_tryset_enable_state(SCX_OPS_ENABLING, SCX_OPS_PREPPING)) {
		preempt_enable();
		spin_unlock_irq(&scx_tasks_lock);
		ret = -EBUSY;
		goto err_disable_unlock;
	}

	/*
	 * We're fully committed and can't fail. The PREPPED -> ENABLED
	 * transitions here are synchronized against sched_ext_free() through
	 * scx_tasks_lock.
	 */
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		if (READ_ONCE(p->__state) != TASK_DEAD) {
			const struct sched_class *old_class = p->sched_class;
			struct sched_enq_and_set_ctx ctx;

			sched_deq_and_put_task(p, DEQUEUE_SAVE | DEQUEUE_MOVE,
					       &ctx);
			scx_ops_enable_task(p);

			__setscheduler_prio(p, p->prio);
			check_class_changing(task_rq(p), p, old_class);

			sched_enq_and_set_task(&ctx);

			check_class_changed(task_rq(p), p, old_class, p->prio);
		} else {
			scx_ops_disable_task(p);
		}
	}
	scx_task_iter_exit(&sti);

	spin_unlock_irq(&scx_tasks_lock);
	preempt_enable();
	percpu_up_write(&scx_fork_rwsem);

	if (!scx_ops_tryset_enable_state(SCX_OPS_ENABLED, SCX_OPS_ENABLING)) {
		ret = -EBUSY;
		goto err_disable_unlock;
	}

	cpus_read_unlock();
	mutex_unlock(&scx_ops_enable_mutex);

	return 0;

err_unlock:
	mutex_unlock(&scx_ops_enable_mutex);
	return ret;

err_disable_unlock:
	percpu_up_write(&scx_fork_rwsem);
err_disable:
	cpus_read_unlock();
	mutex_unlock(&scx_ops_enable_mutex);
	/* must be fully disabled before returning */
	scx_ops_disable(SCX_EXIT_ERROR);
	kthread_flush_work(&scx_ops_disable_work);
	return ret;
}

#ifdef CONFIG_SCHED_DEBUG
static const char *scx_ops_enable_state_str[] = {
	[SCX_OPS_PREPPING]	= "prepping",
	[SCX_OPS_ENABLING]	= "enabling",
	[SCX_OPS_ENABLED]	= "enabled",
	[SCX_OPS_DISABLING]	= "disabling",
	[SCX_OPS_DISABLED]	= "disabled",
};

static int scx_debug_show(struct seq_file *m, void *v)
{
	mutex_lock(&scx_ops_enable_mutex);
	seq_printf(m, "%-30s: %s\n", "ops", scx_ops.name);
	seq_printf(m, "%-30s: %ld\n", "enabled", scx_enabled());
	seq_printf(m, "%-30s: %s\n", "enable_state",
		   scx_ops_enable_state_str[scx_ops_enable_state()]);
	seq_printf(m, "%-30s: %llu\n", "nr_rejected",
		   atomic64_read(&scx_nr_rejected));
	mutex_unlock(&scx_ops_enable_mutex);
	return 0;
}

static int scx_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, scx_debug_show, NULL);
}

const struct file_operations sched_ext_fops = {
	.open		= scx_debug_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

/********************************************************************************
 * bpf_struct_ops plumbing.
 */
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>

extern struct btf *btf_vmlinux;
static const struct btf_type *task_struct_type;

static bool bpf_scx_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_scx_btf_struct_access(struct bpf_verifier_log *log,
				     const struct btf *btf,
				     const struct btf_type *t, int off,
				     int size, enum bpf_access_type atype,
				     u32 *next_btf_id, enum bpf_type_flag *flag)
{
	if (t == task_struct_type) {
		if (off >= offsetof(struct task_struct, scx.slice) &&
		    off + size <= offsetofend(struct task_struct, scx.slice))
			return SCALAR_VALUE;
	}

	if (atype == BPF_READ)
		return btf_struct_access(log, btf, t, off, size, atype,
					 next_btf_id, flag);

	bpf_log(log, "only read is supported\n");
	return -EACCES;
}

static const struct bpf_func_proto *
bpf_scx_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_task_storage_get:
		return &bpf_task_storage_get_proto;
	case BPF_FUNC_task_storage_delete:
		return &bpf_task_storage_delete_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

const struct bpf_verifier_ops bpf_scx_verifier_ops = {
	.get_func_proto = bpf_scx_get_func_proto,
	.is_valid_access = bpf_scx_is_valid_access,
	.btf_struct_access = bpf_scx_btf_struct_access,
};

static int bpf_scx_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	const struct sched_ext_ops *uops = udata;
	struct sched_ext_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	switch (moff) {
	case offsetof(struct sched_ext_ops, dispatch_max_batch):
		if (*(u32 *)(udata + moff) > INT_MAX)
			return -E2BIG;
		ops->dispatch_max_batch = *(u32 *)(udata + moff);
		return 1;
	case offsetof(struct sched_ext_ops, flags):
		if (*(u64 *)(udata + moff) & ~SCX_OPS_ALL_FLAGS)
			return -EINVAL;
		ops->flags = *(u64 *)(udata + moff);
		return 1;
	case offsetof(struct sched_ext_ops, name):
		ret = bpf_obj_name_cpy(ops->name, uops->name,
				       sizeof(ops->name));
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_scx_check_member(const struct btf_type *t,
				const struct btf_member *member,
				struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct sched_ext_ops, prep_enable):
	case offsetof(struct sched_ext_ops, init):
	case offsetof(struct sched_ext_ops, exit):
		/*
		 * FIXME - libbpf should be updated to support struct_ops
		 * operations to be marked as sleepable and this function should
		 * verify that the sleepable states match the expectations. For
		 * now, force-set sleepable here.
		 */
		prog->aux->sleepable = true;
		break;
	}

	return 0;
}

static int bpf_scx_reg(void *kdata)
{
	return scx_ops_enable(kdata);
}

static void bpf_scx_unreg(void *kdata)
{
	scx_ops_disable(SCX_EXIT_UNREG);
	kthread_flush_work(&scx_ops_disable_work);
}

static int bpf_scx_init(struct btf *btf)
{
	u32 type_id;

	type_id = btf_find_by_name_kind(btf, "task_struct", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	task_struct_type = btf_type_by_id(btf, type_id);

	return 0;
}

/* "extern" to avoid sparse warning, only used in this file */
extern struct bpf_struct_ops bpf_sched_ext_ops;

struct bpf_struct_ops bpf_sched_ext_ops = {
	.verifier_ops = &bpf_scx_verifier_ops,
	.reg = bpf_scx_reg,
	.unreg = bpf_scx_unreg,
	.check_member = bpf_scx_check_member,
	.init_member = bpf_scx_init_member,
	.init = bpf_scx_init,
	.name = "sched_ext_ops",
};

static void sysrq_handle_sched_ext_reset(int key)
{
	if (scx_ops_helper)
		scx_ops_disable(SCX_EXIT_SYSRQ);
	else
		pr_info("sched_ext: BPF scheduler not yet used\n");
}

static const struct sysrq_key_op sysrq_sched_ext_reset_op = {
	.handler	= sysrq_handle_sched_ext_reset,
	.help_msg	= "reset-sched-ext(S)",
	.action_msg	= "Disable sched_ext and revert all tasks to CFS",
	.enable_mask	= SYSRQ_ENABLE_RTNICE,
};

void __init init_sched_ext_class(void)
{
	int cpu;
	u32 v;

	/*
	 * The following is to prevent the compiler from optimizing out the enum
	 * definitions so that BPF scheduler implementations can use them
	 * through the generated vmlinux.h.
	 */
	WRITE_ONCE(v, SCX_DEQ_SLEEP);

	init_dsq(&scx_dsq_global, SCX_DSQ_GLOBAL);
#ifdef CONFIG_SMP
	BUG_ON(!alloc_cpumask_var(&idle_masks.cpu, GFP_KERNEL));
	BUG_ON(!alloc_cpumask_var(&idle_masks.smt, GFP_KERNEL));
#endif
	for_each_possible_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);

		init_dsq(&rq->scx.local_dsq, SCX_DSQ_LOCAL);
		rq->scx.nr_running = 0;
	}

	register_sysrq_key('S', &sysrq_sched_ext_reset_op);
}


/********************************************************************************
 * Helpers that can be called from the BPF scheduler.
 */
#include <linux/btf_ids.h>

/* Disables missing prototype warnings for kfuncs */
__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in vmlinux BTF");

/**
 * scx_bpf_create_dsq - Create a dsq
 * @dsq_id: dsq to attach
 * @node: NUMA node to allocate from
 *
 * Create a dsq identified by @dsq_id. Can be called from sleepable operations
 * including ops.init() and .prep_enable().
 */
s32 scx_bpf_create_dsq(u64 dsq_id, s32 node)
{
	if (unlikely(node >= (int)nr_node_ids ||
		     (node < 0 && node != NUMA_NO_NODE)))
		return -EINVAL;
	return PTR_ERR_OR_ZERO(create_dsq(dsq_id, node));
}

BTF_SET8_START(scx_kfunc_ids_sleepable)
BTF_ID_FLAGS(func, scx_bpf_create_dsq)
BTF_SET8_END(scx_kfunc_ids_sleepable)

static const struct btf_kfunc_id_set scx_kfunc_set_sleepable = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_sleepable,
};

/**
 * scx_bpf_dispatch_nr_slots - Return the number of remaining dispatch slots
 */
u32 scx_bpf_dispatch_nr_slots(void)
{
	return dispatch_max_batch - __this_cpu_read(dispatch_buf_cursor);
}

/**
 * scx_bpf_dispatch - Dispatch a task to a dsq
 * @p: task_struct to dispatch
 * @dsq_id: dsq to dispatch to
 * @slice: duration @p can run for in nsecs
 * @enq_flags: SCX_ENQ_*
 *
 * Dispatch @p to the dsq identified by @dsq_id. It is safe to call this
 * function spuriously. Can be called from ops.enqueue() and ops.dispatch().
 *
 * When called from ops.enqueue(), it's for direct dispatch and @p must match
 * the task being enqueued. Also, %SCX_DSQ_LOCAL_ON can't be used to target the
 * local dsq of a CPU other than the enqueueing one. Use ops.select_cpu() to be
 * on the target CPU in the first place.
 *
 * When called from ops.dispatch(), there are no restrictions on @p or @dsq_id
 * and this function can be called upto ops.dispatch_max_batch times to dispatch
 * multiple tasks. scx_bpf_dispatch_nr_slots() returns the number of the
 * remaining slots.
 *
 * @p is allowed to run for @slice. The scheduling path is triggered on slice
 * exhaustion. If zero, the current residual slice is maintained. If
 * %SCX_SLICE_INF, @p never expires and the BPF scheduler must kick the CPU with
 * scx_bpf_kick_cpu() to trigger scheduling.
 */
void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice,
		      u64 enq_flags)
{
	struct task_struct *ddsp_task;
	int idx;

	lockdep_assert_irqs_disabled();

	if (unlikely(!p)) {
		scx_ops_error("called with NULL task");
		return;
	}

	if (unlikely(enq_flags & __SCX_ENQ_INTERNAL_MASK)) {
		scx_ops_error("invalid enq_flags 0x%llx", enq_flags);
		return;
	}

	if (slice)
		p->scx.slice = slice;
	else
		p->scx.slice = p->scx.slice ?: 1;

	ddsp_task = __this_cpu_read(direct_dispatch_task);
	if (ddsp_task) {
		direct_dispatch(ddsp_task, p, dsq_id, enq_flags);
		return;
	}

	idx = __this_cpu_read(dispatch_buf_cursor);
	if (unlikely(idx >= dispatch_max_batch)) {
		scx_ops_error("dispatch buffer overflow");
		return;
	}

	this_cpu_ptr(dispatch_buf)[idx] = (struct dispatch_buf_ent){
		.task = p,
		.qseq = atomic64_read(&p->scx.ops_state) & SCX_OPSS_QSEQ_MASK,
		.dsq_id = dsq_id,
		.enq_flags = enq_flags,
	};
	__this_cpu_inc(dispatch_buf_cursor);
}

BTF_SET8_START(scx_kfunc_ids_dispatch)
BTF_ID_FLAGS(func, scx_bpf_dispatch_nr_slots)
BTF_ID_FLAGS(func, scx_bpf_dispatch)
BTF_SET8_END(scx_kfunc_ids_dispatch)

static const struct btf_kfunc_id_set scx_kfunc_set_dispatch = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_dispatch,
};

/**
 * scx_bpf_consume - Transfer a task from a dsq to the current CPU's local dsq
 * @dsq_id: dsq to consume
 *
 * Consume a task from the dsq identified by @dsq_id and transfer it to the
 * current CPU's local dsq for execution. Can only be called from
 * ops.consume[_final]().
 *
 * Returns %true if a task has been consumed, %false if there isn't any task to
 * consume.
 */
bool scx_bpf_consume(u64 dsq_id)
{
	struct consume_ctx *cctx = this_cpu_ptr(&consume_ctx);
	struct scx_dispatch_q *dsq;

	dsq = find_non_local_dsq(dsq_id);
	if (unlikely(!dsq)) {
		scx_ops_error("invalid dsq_id 0x%016llx", dsq_id);
		return false;
	}

	return consume_dispatch_q(cctx->rq, cctx->rf, dsq);
}

BTF_SET8_START(scx_kfunc_ids_consume)
BTF_ID_FLAGS(func, scx_bpf_consume)
BTF_SET8_END(scx_kfunc_ids_consume)

static const struct btf_kfunc_id_set scx_kfunc_set_consume = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_consume,
};

/**
 * scx_bpf_dsq_nr_queued - Return the number of queued tasks
 * @dsq_id: id of the dsq
 *
 * Return the number of tasks in the dsq matching @dsq_id. If not found,
 * -%ENOENT is returned. Can be called from any non-sleepable online scx_ops
 * operations.
 */
s32 scx_bpf_dsq_nr_queued(u64 dsq_id)
{
	struct scx_dispatch_q *dsq;

	lockdep_assert(rcu_read_lock_any_held());

	if (dsq_id == SCX_DSQ_LOCAL) {
		return this_rq()->scx.local_dsq.nr;
	} else if ((dsq_id & SCX_DSQ_LOCAL_ON) == SCX_DSQ_LOCAL_ON) {
		s32 cpu = dsq_id & SCX_DSQ_LOCAL_CPU_MASK;

		if (ops_cpu_valid(cpu))
			return cpu_rq(cpu)->scx.local_dsq.nr;
	} else {
		dsq = find_non_local_dsq(dsq_id);
		if (dsq)
			return dsq->nr;
	}
	return -ENOENT;
}

/**
 * scx_bpf_test_and_clear_cpu_idle - Test and clear @cpu's idle state
 * @cpu: cpu to test and clear idle for
 *
 * Returns %true if @cpu was idle and its idle state was successfully cleared.
 * %false otherwise.
 *
 * Unavailable if ops.update_idle() is implemented and
 * %SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
bool scx_bpf_test_and_clear_cpu_idle(s32 cpu)
{
	if (!static_branch_likely(&scx_builtin_idle_enabled)) {
		scx_ops_error("built-in idle tracking is disabled");
		return false;
	}

	if (ops_cpu_valid(cpu))
		return test_and_clear_cpu_idle(cpu);
	else
		return 0;
}

/**
 * scx_bpf_pick_idle_cpu - Pick and claim an idle cpu
 * @cpus_allowed: Allowed cpumask
 *
 * Pick and claim an idle cpu which is also in @cpus_allowed. Returns the picked
 * idle cpu number on success. -%EBUSY if no matching cpu was found.
 *
 * Unavailable if ops.update_idle() is implemented and
 * %SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
s32 scx_bpf_pick_idle_cpu(const struct cpumask *cpus_allowed)
{
	if (!static_branch_likely(&scx_builtin_idle_enabled)) {
		scx_ops_error("built-in idle tracking is disabled");
		return -EBUSY;
	}

	return scx_pick_idle_cpu(cpus_allowed);
}

BTF_SET8_START(scx_kfunc_ids_online)
BTF_ID_FLAGS(func, scx_bpf_dsq_nr_queued)
BTF_ID_FLAGS(func, scx_bpf_test_and_clear_cpu_idle)
BTF_ID_FLAGS(func, scx_bpf_pick_idle_cpu)
BTF_SET8_END(scx_kfunc_ids_online)

static const struct btf_kfunc_id_set scx_kfunc_set_online = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_online,
};

struct scx_bpf_error_bstr_bufs {
	u64			data[MAX_BPRINTF_VARARGS];
	char			msg[SCX_EXIT_MSG_LEN];
};

static DEFINE_PER_CPU(struct scx_bpf_error_bstr_bufs, scx_bpf_error_bstr_bufs);

/**
 * scx_bpf_error_bstr - Indicate fatal error
 * @fmt: error message format string
 * @data: format string parameters packaged using ___bpf_fill() macro
 * @data_len: @data len
 *
 * Indicate that the BPF scheduler encountered a fatal error and initiate ops
 * disabling.
 */
void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data_len)
{
	struct scx_bpf_error_bstr_bufs *bufs;
	unsigned long flags;
	u32 *bin_args;
	int ret;

	local_irq_save(flags);
	bufs = this_cpu_ptr(&scx_bpf_error_bstr_bufs);

	if (data_len % 8 || data_len > MAX_BPRINTF_VARARGS * 8 ||
	    (data_len && !data)) {
		scx_ops_error("invalid data=%p and data_len=%u",
			      (void *)data, data_len);
		goto out_restore;
	}

	ret = copy_from_kernel_nofault(bufs->data, data, data_len);
	if (ret) {
		scx_ops_error("failed to read data fields (%d)", ret);
		goto out_restore;
	}

	ret = bpf_bprintf_prepare(fmt, UINT_MAX, bufs->data, &bin_args,
				  data_len / 8);
	if (ret < 0) {
		scx_ops_error("failed to format prepration (%d)", ret);
		goto out_restore;
	}

	ret = bstr_printf(bufs->msg, sizeof(bufs->msg), fmt, bin_args);
	bpf_bprintf_cleanup();
	if (ret < 0) {
		scx_ops_error("scx_ops_error(\"%s\", %p, %u) failed to format",
			      fmt, data, data_len);
		goto out_restore;
	}

	scx_ops_error_type(SCX_EXIT_ERROR_BPF, "%s", bufs->msg);
out_restore:
	local_irq_restore(flags);
}

/**
 * scx_bpf_destroy_dsq - Destroy a dsq
 * @dsq_id: dsq to destroy
 *
 * Destroy the dsq identified by @dsq_id. Only dsqs created with
 * scx_bpf_create_dsq() can be destroyed. The caller must ensure that the dsq is
 * empty and no further tasks are dispatched to it. Ignored if called on a dsq
 * which doesn't exist. Can be called from any online scx_ops operations.
 */
void scx_bpf_destroy_dsq(u64 dsq_id)
{
	destroy_dsq(dsq_id);
}

/**
 * scx_bpf_task_running - Is task currently running?
 * @p: task of interest
 */
bool scx_bpf_task_running(const struct task_struct *p)
{
	return task_rq(p)->curr == p;
}

/**
 * scx_bpf_task_cpu - CPU a task is currently associated with
 * @p: task of interest
 */
s32 scx_bpf_task_cpu(const struct task_struct *p)
{
	return task_cpu(p);
}

BTF_SET8_START(scx_kfunc_ids_any)
BTF_ID_FLAGS(func, scx_bpf_error_bstr)
BTF_ID_FLAGS(func, scx_bpf_destroy_dsq)
BTF_ID_FLAGS(func, scx_bpf_task_running)
BTF_ID_FLAGS(func, scx_bpf_task_cpu)
BTF_SET8_END(scx_kfunc_ids_any)

static const struct btf_kfunc_id_set scx_kfunc_set_any = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_any,
};

/********************************************************************************
 * Temporary BPF helpers to be replaced by generic non-scx-specific BPF helpers
 */

struct cgroup *scx_bpf_task_cgroup(const struct task_struct *p)
{
	struct task_group *tg = p->sched_task_group;

	if (tg && tg->css.cgroup)
		return tg->css.cgroup;
	else
		return &cgrp_dfl_root.cgrp;
}

struct task_struct *scx_bpf_find_task_by_pid(s32 pid)
{
	return find_task_by_pid_ns(pid, &init_pid_ns);
}

s32 scx_bpf_pick_idle_cpu_untyped(unsigned long cpus_allowed)
{
	return scx_bpf_pick_idle_cpu((const struct cpumask *)cpus_allowed);
}

bool scx_bpf_has_idle_cpus_among(const struct cpumask *cpus_allowed)
{
	if (!static_branch_likely(&scx_builtin_idle_enabled)) {
		scx_ops_error("built-in idle tracking is disabled");
		return false;
	}
#ifdef CONFIG_SMP
	return cpumask_any_and(idle_masks.cpu, cpus_allowed) < nr_cpu_ids;
#else
	return false;
#endif
}

s32 scx_bpf_has_idle_cpus_among_untyped(unsigned long cpus_allowed)
{
	return scx_bpf_has_idle_cpus_among((const struct cpumask *)cpus_allowed);
}

s32 scx_bpf_cpumask_test_cpu(s32 cpu, const struct cpumask *cpumask)
{
	return cpumask_test_cpu(cpu, cpumask);
}

s32 scx_bpf_cpumask_first(const struct cpumask *cpus_allowed)
{
	return cpumask_first(cpus_allowed);
}

s32 scx_bpf_cpumask_first_untyped(unsigned long cpus_allowed)
{
	return cpumask_first((const struct cpumask *)cpus_allowed);
}

bool scx_bpf_cpumask_intersects(const struct cpumask *src1p,
				const struct cpumask *src2p)
{
	return cpumask_intersects(src1p, src2p);
}

BTF_SET8_START(scx_kfunc_ids_xxx)
BTF_ID_FLAGS(func, scx_bpf_task_cgroup)
BTF_ID_FLAGS(func, scx_bpf_find_task_by_pid, KF_RET_NULL)
BTF_ID_FLAGS(func, scx_bpf_pick_idle_cpu_untyped)
BTF_ID_FLAGS(func, scx_bpf_has_idle_cpus_among)
BTF_ID_FLAGS(func, scx_bpf_has_idle_cpus_among_untyped)
BTF_ID_FLAGS(func, scx_bpf_cpumask_test_cpu)
BTF_ID_FLAGS(func, scx_bpf_cpumask_first)
BTF_ID_FLAGS(func, scx_bpf_cpumask_first_untyped)
BTF_ID_FLAGS(func, scx_bpf_cpumask_intersects)
BTF_SET8_END(scx_kfunc_ids_xxx)

static const struct btf_kfunc_id_set scx_kfunc_set_xxx = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_xxx,
};

__diag_pop();

/*
 * This can't be done from init_sched_ext_class() as register_btf_kfunc_id_set()
 * needs most of the system to be up.
 */
static int __init register_ext_kfuncs(void)
{
	int ret;

	/*
	 * FIXME - Many kfunc helpers are context-sensitive and can only be
	 * called from specific scx_ops operations. Unfortunately, we can't
	 * currently tell for which operation we're verifying for. For now,
	 * allow all kfuncs for everybody.
	 */
	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &scx_kfunc_set_sleepable)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					    &scx_kfunc_set_dispatch)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &scx_kfunc_set_consume)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &scx_kfunc_set_online)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &scx_kfunc_set_any)) ||
	    (ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &scx_kfunc_set_xxx))) {
		pr_err("sched_ext: failed to register kfunc sets (%d)\n", ret);
		return ret;
	}

	return 0;
}
__initcall(register_ext_kfuncs);
