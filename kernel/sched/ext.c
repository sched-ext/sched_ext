/* SPDX-License-Identifier: GPL-2.0 */
#define SCX_OP_IDX(op)		(offsetof(struct sched_ext_ops, op) / sizeof(void (*)(void)))

enum scx_internal_consts {
	SCX_NR_ONLINE_OPS	= SCX_OP_IDX(init),
	SCX_OPS_EXIT_MSG_LEN	= 128,
	SCX_DSP_DFL_MAX_BATCH	= 32,
};

enum scx_ops_enabled_flags {
	SCX_OPSEN_EXCLUDE_DISABLING	= 0x1,
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
 * Used to manage task ownership between the C and bpf parts of the scheduler.
 * State transitions look as follows:
 *
 * NONE -> QUEUEING -> QUEUED -> DISPATCHING -> NONE
 *   ^              |                 |
 *   |              v                 v
 *   \-------------------------------/
 *
 * QUEUEING and DISPATCHING states can be waited upon. Transitions out of them
 * into NONE or QUEUED must store_release and the waiters should load_acquire.
 *
 * Tracking scx_ops_state enables sched_ext core to reliably determine whether
 * any given task can be dispatched by the bpf scheduler at all times and thus
 * relaxes the requirements on the bpf scheduler. This allows the bpf scheduler
 * to try to dispatch any task anytime regardless of its state as sched_ext core
 * can safely reject invalid dispatches.
 */
enum scx_ops_state {
	SCX_OPSS_NONE,		/* owned by C */
	SCX_OPSS_QUEUEING,	/* in transit to bpf */
	SCX_OPSS_QUEUED,	/* owned by bpf */
	SCX_OPSS_DISPATCHING,	/* in transit back to C */

	/*
	 * QSEQ brands each QUEUED instance so that, when dispatch races
	 * dequeue/requeue, the dispatcher can tell whether it still has a claim
	 * on the task being dispatched.
	 */
	SCX_OPSS_QSEQ_SHIFT	= 2,
	SCX_OPSS_STATE_MASK	= (1LLU << SCX_OPSS_QSEQ_SHIFT) - 1,
	SCX_OPSS_QSEQ_MASK	= ~SCX_OPSS_STATE_MASK,
};

#ifdef CONFIG_SCHED_CLASS_EXT_DEFAULT
DEFINE_STATIC_KEY_TRUE(__sched_ext_enabled);
DEFINE_STATIC_KEY_FALSE(__sched_fair_enabled);
const struct sched_class *__normal_sched_class = &ext_sched_class;
#else
DEFINE_STATIC_KEY_FALSE(__sched_ext_enabled);
DEFINE_STATIC_KEY_TRUE(__sched_fair_enabled);
const struct sched_class *__normal_sched_class = &fair_sched_class;
#endif

static DEFINE_SPINLOCK(scx_tasks_lock);
static LIST_HEAD(scx_tasks);

/* ops enable/disable */
DEFINE_STATIC_PERCPU_RWSEM(scx_ops_rwsem);

static DEFINE_STATIC_KEY_FALSE(scx_ops_all_enabled);
static DEFINE_STATIC_KEY_TRUE(scx_ops_all_disabled);
static atomic_t scx_ops_enable_state_var = ATOMIC_INIT(SCX_OPS_DISABLED);
static struct sched_ext_ops scx_ops;
static bool warned_zero_slice;

static DEFINE_STATIC_KEY_FALSE(scx_ops_enq_last);
static DEFINE_STATIC_KEY_FALSE(scx_ops_enq_exiting);
/*
 * Give this static key global visibility so that it can be used in the
 * scx_notify_pick_next_task() wrapper function exposed to the core scheduler.
 */
DEFINE_STATIC_KEY_FALSE(scx_ops_cpu_preempt);
static DEFINE_STATIC_KEY_TRUE(scx_builtin_idle_enabled);

struct static_key_false scx_has_op[SCX_NR_ONLINE_OPS] =
	{ [0 ... SCX_NR_ONLINE_OPS-1] = STATIC_KEY_FALSE_INIT };

static atomic_t scx_ops_exit_type = ATOMIC_INIT(SCX_OPS_EXIT_DONE);
static struct scx_ops_exit_info scx_ops_exit_info;
static struct kthread_worker *scx_ops_helper;

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
static u64 __percpu *rq_generation;
#endif

/* dispatch queues */
static struct scx_dispatch_q __cacheline_aligned_in_smp scx_dq_global;

static const struct rhashtable_params dq_hash_params = {
	.key_len		= 8,
	.key_offset		= offsetof(struct scx_dispatch_q, id),
	.head_offset		= offsetof(struct scx_dispatch_q, hash_node),
};

static struct rhashtable dq_hash;
static DEFINE_RAW_SPINLOCK(all_dqs_lock);
static LIST_HEAD(all_dqs);
static LLIST_HEAD(dqs_to_free);

/* dispatch buf */
struct dispatch_buf_ent {
	struct task_struct	*task;
	u64			qseq;
	s64			dq_id;
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

static __always_inline bool scx_ops_enabled(struct task_struct *p, u32 en_flags)
{
	if (static_branch_likely(&scx_ops_all_enabled))
		return true;
	if (static_branch_likely(&scx_ops_all_disabled))
		return false;

	if ((en_flags & SCX_OPSEN_EXCLUDE_DISABLING) &&
	    scx_ops_enable_state() == SCX_OPS_DISABLING)
		return false;
	return p && (p->scx.flags & SCX_TASK_OPS_ENABLED);
}

static __always_inline bool scx_ops_any_enabled(u32 en_flags)
{
	if (static_branch_likely(&scx_ops_all_enabled))
		return true;
	if (static_branch_likely(&scx_ops_all_disabled))
		return false;

	if ((en_flags & SCX_OPSEN_EXCLUDE_DISABLING) &&
	    scx_ops_enable_state() == SCX_OPS_DISABLING)
		return false;
	return true;
}

static bool scx_ops_disabling(void)
{
	/*
	 * This function can't use the static branches as it should return %true
	 * as soon as DISABLING is asserted. Otherwise, the disabling path may
	 * stall e.g. waiting for RCU before turning off scx_ops_all_enabled.
	 */
	return unlikely(scx_ops_enable_state() == SCX_OPS_DISABLING);
}

#define SCX_HAS_OP(op)						\
	static_branch_likely(&scx_has_op[SCX_OP_IDX(op)])

#define SCX_OP_ENABLED(op, p, en_flags)				\
	(SCX_HAS_OP(op) && scx_ops_enabled((p), (en_flags)))

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
 * scx_tasks_lock may be released between this and the first next call or
 * between any two next calls. If scx_tasks_lock is released between two next
 * calls, the caller is responsible for ensuring that the task being iterated
 * remains accessible either through RCU read lock or obtaining a reference
 * count.
 *
 * No task can escape an scx_task_iter iteration. All tasks which existed when
 * the iteration started are guaranteed to be visited as long as they still
 * exist, unless the iterator is exit prematurely with scx_task_iter_exit().
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
 * Exit a previously initialized @iter. Must be called with scx_tasks_lock
 * held. If the iterator holds a task's rq lock, that rq lock is released.
 *
 * Once exited, @iter may not be used in any further calls to scx_task_iter*().
 * See scx_task_iter_init() for details.
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
 * scx_task_iter_next_filtered_locked - Next alive non-idle task with rq locked
 * @iter: iterator to walk
 *
 * Visit the next alive non-idle task with its rq lock held. See
 * scx_task_iter_init() for details.
 */
static struct task_struct *
scx_task_iter_next_filtered_locked(struct scx_task_iter *iter)
{
	struct task_struct *p;

	if (iter->locked) {
		task_rq_unlock(iter->rq, iter->locked, &iter->rf);
		iter->locked = NULL;
	}

	while ((p = scx_task_iter_next_filtered(iter))) {
		iter->rq = task_rq_lock(p, &iter->rf);
		if (READ_ONCE(p->__state) != TASK_DEAD) {
			iter->locked = p;
			return p;
		}
		task_rq_unlock(iter->rq, p, &iter->rf);
	}

	return NULL;
}

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
 * @cpu: cpu number which came from a bpf ops
 *
 * @cpu is a cpu number which came from a bpf ops and can be any value. Verify
 * that it is in range and one of the possible cpus.
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
 * cause misbehaviors. For example, a large negative return from .prep_enable()
 * triggers an oops when passed up the call chain. The value gets encoded with
 * ERR_PTR() but would fail IS_ERR() test and thus be interpreted and
 * dereferenced as a pointer.
 */
static int ops_sanitize_err(const char *ops_name, s32 err)
{
	if (err < 0 && err >= -MAX_ERRNO)
		return err;

	scx_ops_error(".%s() returned an invalid errno %d", ops_name, err);
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

	if (curr->scx.slice != SCX_SLICE_INF)
		curr->scx.slice -= min(curr->scx.slice, delta_exec);
}

static void dispatch_enqueue(struct scx_dispatch_q *dq, struct task_struct *p,
			     u64 enq_flags)
{
	bool is_local = dq->id == SCX_DQ_LOCAL;

	WARN_ON_ONCE(p->scx.dq || !list_empty(&p->scx.dq_node));

	if (!is_local) {
		raw_spin_lock(&dq->lock);
		if (unlikely(dq->id < 0)) {
			scx_ops_error("attempting to dispatch to destroyed dq 0x%016llx",
				      -dq->id);
			raw_spin_unlock(&dq->lock);
			return;
		}
	}

	if (enq_flags & SCX_ENQ_HEAD)
		list_add(&p->scx.dq_node, &dq->fifo);
	else
		list_add_tail(&p->scx.dq_node, &dq->fifo);
	dq->nr++;
	p->scx.dq = dq;

	/*
	 * We're transitioning out of QUEUEING or DISPATCHING. store_release to
	 * match waiters' load_acquire.
	 */
	if (enq_flags & SCX_ENQ_CLEAR_OPSS)
		atomic64_set_release(&p->scx.ops_state, SCX_OPSS_NONE);

	if (is_local) {
		struct rq *rq = task_rq(p);
		bool preempt = false;

		if ((enq_flags & SCX_ENQ_LOCAL_PREEMPT) && p != rq->curr &&
		    rq->curr->sched_class == &ext_sched_class) {
			rq->curr->scx.slice = 0;
			preempt = true;
		}

		if (preempt || sched_class_above(&ext_sched_class,
						 rq->curr->sched_class))
			resched_curr(rq);
	} else {
		raw_spin_unlock(&dq->lock);
	}
}

static void dispatch_dequeue(struct scx_rq *scx_rq, struct task_struct *p)
{
	struct scx_dispatch_q *dq = p->scx.dq;
	bool is_local = dq == &scx_rq->local_dq;

	if (!dq) {
		WARN_ON_ONCE(!list_empty(&p->scx.dq_node));
		/*
		 * When dispatching directly from the bpf scheduler to LOCAL_DQ,
		 * the task isn't associated with any dq but @p->scx.holding_cpu
		 * may be set under the protection of %SCX_OPSS_DISPATCHING.
		 */
		if (p->scx.holding_cpu >= 0)
			p->scx.holding_cpu = -1;
		return;
	}

	if (!is_local)
		raw_spin_lock(&dq->lock);

	/*
	 * Now that we hold @dq->lock, @p->holding_cpu and @p->scx.dq_node
	 * can't change underneath us.
	*/
	if (p->scx.holding_cpu < 0) {
		/*
		 * @p must still be on @dq, dequeue.
		 */
		WARN_ON_ONCE(list_empty(&p->scx.dq_node));
		list_del_init(&p->scx.dq_node);
		dq->nr--;
	} else {
		/*
		 * We're racing against pull_task() which already removed @p
		 * from @dq and set @p->scx.holding_cpu. Clear the holding_cpu
		 * which tells pull_task() that it lost the race.
		 */
		WARN_ON_ONCE(!list_empty(&p->scx.dq_node));
		p->scx.holding_cpu = -1;
	}
	p->scx.dq = NULL;

	if (!is_local)
		raw_spin_unlock(&dq->lock);
}

static struct scx_dispatch_q *find_non_local_dq(s64 dq_id)
{
	lockdep_assert(rcu_read_lock_any_held());

	if (dq_id == SCX_DQ_GLOBAL)
		return &scx_dq_global;
	else
		return rhashtable_lookup_fast(&dq_hash, &dq_id, dq_hash_params);
}

static struct scx_dispatch_q *find_dq_for_dispatch(struct rq *rq, s64 dq_id,
						   struct task_struct *p)
{
	struct scx_dispatch_q *dq;

	if (dq_id == SCX_DQ_LOCAL)
		return &rq->scx.local_dq;

	dq = find_non_local_dq(dq_id);
	if (unlikely(!dq)) {
		if (dq_id < 0)
			scx_ops_error("got error verdict %lld for %s[%d]",
				      dq_id, p->comm, p->pid);
		else
			scx_ops_error("non-existent dq 0x%llx for %s[%d]",
				      dq_id, p->comm, p->pid);
		return &scx_dq_global;
	}

	return dq;
}

static void dq_id_pull_enq_flags(s64 *dq_id, u64 *enq_flags)
{
	if (unlikely(*dq_id < 0)) {
		scx_ops_error("->enqueue() failed with %lld", *dq_id);
		*dq_id = SCX_DQ_GLOBAL;
		return;
	}

	switch (*dq_id & __SCX_DQ_POS_MASK) {
	case SCX_DQ_PREEMPT:
		*enq_flags |= SCX_ENQ_HEAD | SCX_ENQ_LOCAL_PREEMPT;
		break;
	case SCX_DQ_HEAD:
		*enq_flags |= SCX_ENQ_HEAD;
		break;
	case SCX_DQ_TAIL:
		*enq_flags &= ~SCX_ENQ_HEAD;
		break;
	}

	*dq_id &= ~__SCX_DQ_POS_MASK;
}

static void do_enqueue_task(struct rq *rq, struct task_struct *p, u64 enq_flags,
			    int sticky_cpu)
{
	struct scx_dispatch_q *dq;
	s64 dq_id;
	u64 qseq;

	WARN_ON_ONCE(!(p->scx.flags & SCX_TASK_QUEUED));

	if (scx_ops_enabled(p, SCX_OPSEN_EXCLUDE_DISABLING)) {
		if (sticky_cpu == cpu_of(rq)) {
			dq_id = SCX_DQ_LOCAL;
		} else if (unlikely(!rq->online) ||
			   (!static_branch_unlikely(&scx_ops_enq_exiting) &&
			    unlikely(p->flags & PF_EXITING))) {
			p->scx.slice = SCX_SLICE_DFL;
			dq_id = SCX_DQ_LOCAL;
		} else {
			qseq = rq->scx.ops_qseq++ << SCX_OPSS_QSEQ_SHIFT;

			WARN_ON_ONCE(atomic64_read(&p->scx.ops_state) !=
				     SCX_OPSS_NONE);
			atomic64_set(&p->scx.ops_state,
				     SCX_OPSS_QUEUEING | qseq);

			extl_enqueue_pre(p);

			if (SCX_HAS_OP(enqueue) &&
			    (static_branch_unlikely(&scx_ops_enq_last) ||
			     !(enq_flags & SCX_ENQ_LAST))) {
				dq_id = scx_ops.enqueue(p, enq_flags);
				dq_id_pull_enq_flags(&dq_id, &enq_flags);
			} else {
				p->scx.slice = SCX_SLICE_DFL;
				if ((enq_flags & SCX_ENQ_LAST) ||
				    (p->scx.flags & SCX_TASK_SCD_ENQ_LOCAL))
					dq_id = SCX_DQ_LOCAL;
				else
					dq_id = SCX_DQ_GLOBAL;
			}

			extl_enqueue_post(p, dq_id);

			enq_flags |= SCX_ENQ_CLEAR_OPSS;
		}
	} else {
		if (sticky_cpu == cpu_of(rq)) {
			dq_id = SCX_DQ_LOCAL;
		} else if ((enq_flags & SCX_ENQ_LAST) ||
			   (p->scx.flags & SCX_TASK_SCD_ENQ_LOCAL)) {
			p->scx.slice = SCX_SLICE_DFL;
			dq_id = SCX_DQ_LOCAL;
		} else {
			dq_id = SCX_DQ_GLOBAL;
		}
	}

	p->scx.flags &= ~SCX_TASK_SCD_ENQ_LOCAL;

	// XXX - handle SCX_ENQ_WAKE_IDLE

	if (dq_id == SCX_DQ_NONE) {
		/*
		 * Queued on the bpf side. Dispatch and/or dequeue may be
		 * waiting on QUEUEING. The store_release matches their
		 * load_acquire.
		 */
		atomic64_set_release(&p->scx.ops_state, SCX_OPSS_QUEUED | qseq);
		return;
	}

	if (unlikely((dq_id & SCX_DQ_LOCAL_ON) == SCX_DQ_LOCAL_ON)) {
		scx_ops_error("SCX_DQ_LOCAL_ON not supported on ->enqueue(), use ->select_cpu() to target a specific CPU");
		dq_id = SCX_DQ_GLOBAL;
	}

	dq = find_dq_for_dispatch(rq, dq_id, p);
	dispatch_enqueue(dq, p, enq_flags);
}

static void enqueue_task_scx(struct rq *rq, struct task_struct *p, int enq_flags)
{
	int sticky_cpu = p->scx.sticky_cpu;

	if (sticky_cpu >= 0)
		p->scx.sticky_cpu = -1;

	if ((enq_flags & ENQUEUE_RESTORE) && task_current(rq, p)) {
		/*
		 * pick_next_task_scx() warns on zero slices to ensure that ops
		 * is comprehensively managing slices. On RESTORE, we bypass the
		 * usual enqueue path and can end up putting a task which
		 * exhausted its slice back on the rq triggering the warning
		 * spuriously. Let's avoid that.
		 */
		if (!p->scx.slice)
			p->scx.slice = 1;
		sticky_cpu = cpu_of(rq);
	}

	if (p->scx.flags & SCX_TASK_QUEUED)
		return;

	p->scx.flags |= SCX_TASK_QUEUED;
	rq->scx.nr_running++;
	add_nr_running(rq, 1);

	if (SCX_OP_ENABLED(runnable, p, 0))
		scx_ops.runnable(p, enq_flags);

	do_enqueue_task(rq, p, enq_flags, sticky_cpu);
}

static void dequeue_task_scx(struct rq *rq, struct task_struct *p, int deq_flags)
{
	struct scx_rq *scx_rq = &rq->scx;

	if (!(p->scx.flags & SCX_TASK_QUEUED))
		return;

	if (scx_ops_enabled(p, 0)) {
		u64 opss;

		/* acquire ensures that we see the preceding updates on QUEUED */
		opss = atomic64_read_acquire(&p->scx.ops_state);

		switch (opss & SCX_OPSS_STATE_MASK) {
		case SCX_OPSS_NONE:
			break;
		case SCX_OPSS_QUEUEING:
			BUG();
		case SCX_OPSS_QUEUED:
			extl_dequeue_pre(p);
			if (SCX_HAS_OP(dequeue))
				scx_ops.dequeue(p, deq_flags);
			extl_dequeue_post(p, deq_flags);

			if (atomic64_try_cmpxchg(&p->scx.ops_state, &opss,
						 SCX_OPSS_NONE))
				break;
			fallthrough;
		case SCX_OPSS_DISPATCHING:
			/*
			 * If @p is being dispatched from its sq to dq, wait for
			 * the transfer to complete so that @p doesn't get added
			 * to its dq after dequeueing is complete.
			 *
			 * As we're waiting on DISPATCHING with @rq locked, the
			 * dispatching side shouldn't try to lock @rq while
			 * DISPATCHING is set.
			 */
			wait_ops_state(p, SCX_OPSS_DISPATCHING);
			BUG_ON(atomic64_read(&p->scx.ops_state) != SCX_OPSS_NONE);
			break;
		}

		/*
		 * A currently running task which is going off @rq first gets
		 * dequeued and then stops running. As we want running <->
		 * stopping transitions to be contained within runnable <->
		 * quiescent transitions, trigger ->stopping() early here
		 * instead of in put_prev_task_scx().
		 *
		 * @p may go through multiple stopping <-> running transitions
		 * between here and put_prev_task_scx() if task attribute
		 * changes occur while balance_scx() leaves @rq unlocked.
		 * However, they don't contain any information meaningful to the
		 * bpf scheduler and can be suppressed by skipping the callbacks
		 * if the task is !QUEUED.
		 */
		if (SCX_HAS_OP(stopping) && task_current(rq, p)) {
			update_curr_scx(rq);
			scx_ops.stopping(p, false);
		}

		if (SCX_HAS_OP(quiescent))
			scx_ops.quiescent(p, deq_flags);
	}

	p->scx.flags &= ~SCX_TASK_QUEUED;
	scx_rq->nr_running--;
	sub_nr_running(rq, 1);

	dispatch_dequeue(scx_rq, p);
}

static void yield_task_scx(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (SCX_OP_ENABLED(yield, p, 0))
		scx_ops.yield(p, NULL);
	else
		p->scx.slice = 0;
}

static bool yield_to_task_scx(struct rq *rq, struct task_struct *to)
{
	struct task_struct *from = rq->curr;

	if (SCX_OP_ENABLED(yield, from, 0) && scx_ops_enabled(to, 0))
		return scx_ops.yield(from, to);
	else
		return false;
}

static void check_preempt_curr_scx(struct rq *rq, struct task_struct *p, int wake_flags) {}

#ifdef CONFIG_SMP
/**
 * move_task_to_local_dq - Move a task from a different rq to a local dq
 * @rq: rq to move the task into, currently locked
 * @p: task to move
 *
 * Move @p which is currently on a different rq to @rq's local dq. The caller
 * must:
 *
 * 1. Start with exclusive access to @p either through its dq lock or
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
static bool move_task_to_local_dq(struct rq *rq, struct task_struct *p)
{
	struct rq *task_rq;

	lockdep_assert_rq_held(rq);

	/*
	 * If dequeue got to @p while we were trying to lock both rq's, it'd
	 * have cleared @p->scx.holding_cpu to -1. While other cpu's may have
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
 * dispatch_to_local_dq_lock - Ensure source and desitnation rq's are locked
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @src_rq: rq to move task from
 * @dst_rq: rq to move task to
 *
 * We're holding @rq lock and trying to dispatch a task from @src_rq to
 * @dst_rq's local dq and thus need to lock both @src_rq and @dst_rq. Whether
 * @rq stays locked isn't important as long as the state is restored after
 * dispatch_to_local_dq_unlock().
 */
static void dispatch_to_local_dq_lock(struct rq *rq, struct rq_flags *rf,
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
 * dispatch_to_local_dq_unlock - Undo dispatch_to_local_dq_lock()
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @src_rq: rq to move task from
 * @dst_rq: rq to move task to
 *
 * Unlock @src_rq and @dst_rq and ensure that @rq is locked on return.
 */
static void dispatch_to_local_dq_unlock(struct rq *rq, struct rq_flags *rf,
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

enum dispatch_to_local_dq_ret {
	DTL_DISPATCHED,	/* successfully dispatched */
	DTL_LOST,	/* lost race to dequeue */
	DTL_NOT_LOCAL,	/* destination is not a local dq */
	DTL_INVALID,	/* invalid local dq_id */
};

/**
 * dispatch_to_local_dq - Dispatch a task to a local dq
 * @rq: current rq which is locked
 * @rf: rq_flags to use when unlocking @rq
 * @dq_id: destination dq ID
 * @p: task to dispatch
 * @enq_flags: SCX_ENQ_*
 *
 * We're holding @rq lock and want to dispatch @p to the local dq identified by
 * @dq_id. This function performs all the synchronization dancing needed because
 * local dq's are protected with rq locks.
 *
 * The caller must have exclusive ownership of @p (e.g. through
 * %SCX_OPSS_DISPATCHING).
 */
static enum dispatch_to_local_dq_ret
dispatch_to_local_dq(struct rq *rq, struct rq_flags *rf, s64 dq_id,
		     struct task_struct *p, u64 enq_flags)
{
	struct rq *src_rq = task_rq(p);
	struct rq *dst_rq;

	/*
	 * We're synchronized against dequeue either through DISPATCHING. As @p
	 * can't be dequeued, its task_rq and cpus_allowed are stable too.
	 */
	if (dq_id == SCX_DQ_LOCAL) {
		dst_rq = rq;
	} else if ((dq_id & SCX_DQ_LOCAL_ON) == SCX_DQ_LOCAL_ON) {
		s32 cpu = dq_id & SCX_DQ_LOCAL_CPU_MASK;

		if (!ops_cpu_valid(cpu)) {
			scx_ops_error("invalid cpu %d in SCX_DQ_LOCAL_ON verdict for %s[%d]",
				      cpu, p->comm, p->pid);
			return DTL_INVALID;
		}
		dst_rq = cpu_rq(cpu);
	} else {
		return DTL_NOT_LOCAL;
	}

	/* if dispatching to @rq that @p is already on, no lock dancing needed */
	if (rq == src_rq && rq == dst_rq) {
		dispatch_enqueue(&dst_rq->scx.local_dq, p,
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
		 * pretend that we're moving from a dq and use the same
		 * mechanism - mark the task under transfer with holding_cpu,
		 * release DISPATCHING and then follow the same protocol.
		 */
		p->scx.holding_cpu = raw_smp_processor_id();

		/* store_release ensures that dequeue sees the above */
		atomic64_set_release(&p->scx.ops_state, SCX_OPSS_NONE);

		dispatch_to_local_dq_lock(rq, rf, src_rq, locked_dst_rq);

		/*
		 * We don't require the bpf scheduler to avoid dispatching to
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
			 * move_task_to_local_dq().
			 */
			dsp = p->scx.holding_cpu == raw_smp_processor_id();
			if (likely(dsp)) {
				p->scx.holding_cpu = -1;
				dispatch_enqueue(&dst_rq->scx.local_dq, p,
						 enq_flags);
			}
		} else {
			dsp = move_task_to_local_dq(dst_rq, p);
		}

		/* if the destination CPU is idle, wake it up */
		if (dsp && p->sched_class > dst_rq->curr->sched_class)
			resched_curr(dst_rq);

		dispatch_to_local_dq_unlock(rq, rf, src_rq, locked_dst_rq);

		return dsp ? DTL_DISPATCHED : DTL_LOST;
	}
#endif /* CONFIG_SMP */

	scx_ops_error("SCX_DQ_LOCAL[_ON] verdict target cpu %d not allowed for %s[%d]",
		      cpu_of(dst_rq), p->comm, p->pid);
	return DTL_INVALID;
}

static bool consume_dispatch_q(struct rq *rq, struct rq_flags *rf,
			       struct scx_dispatch_q *dq)
{
	struct scx_rq *scx_rq = &rq->scx;
	struct task_struct *p;
	struct rq *task_rq;
	bool moved = false;
retry:
	if (list_empty(&dq->fifo))
		return false;

	raw_spin_lock(&dq->lock);
	list_for_each_entry(p, &dq->fifo, scx.dq_node) {
		task_rq = task_rq(p);
		if (rq == task_rq)
			goto this_rq;
		if (likely(rq->online) && !is_migration_disabled(p) &&
		    cpumask_test_cpu(cpu_of(rq), p->cpus_ptr))
			goto remote_rq;
	}
	raw_spin_unlock(&dq->lock);
	return false;

this_rq:
	/* @dq is locked and @p is on this rq */
	WARN_ON_ONCE(p->scx.holding_cpu >= 0);
	list_move_tail(&p->scx.dq_node, &scx_rq->local_dq.fifo);
	dq->nr--;
	scx_rq->local_dq.nr++;
	p->scx.dq = &scx_rq->local_dq;
	raw_spin_unlock(&dq->lock);
	return true;

remote_rq:
#ifdef CONFIG_SMP
	/*
	 * @dq is locked and @p is on a remote rq. @p is currently protected by
	 * @dq->lock. We want to pull @p to @rq but may deadlock if we grab
	 * @task_rq while holding @dq and @rq locks. As dequeue can't drop the
	 * rq lock or fail, do a little dancing from our side. See
	 * move_task_to_local_dq().
	 */
	WARN_ON_ONCE(p->scx.holding_cpu >= 0);
	list_del_init(&p->scx.dq_node);
	dq->nr--;
	p->scx.holding_cpu = raw_smp_processor_id();
	raw_spin_unlock(&dq->lock);

	rq_unpin_lock(rq, rf);
	double_lock_balance(rq, task_rq);
	rq_repin_lock(rq, rf);

	moved = move_task_to_local_dq(rq, p);

	double_unlock_balance(rq, task_rq);
#endif /* CONFIG_SMP */
	if (likely(moved))
		return true;
	goto retry;
}

static bool finish_dispatch(struct rq *rq, struct rq_flags *rf,
			    struct task_struct *p, u64 qseq_at_dispatch,
			    s64 dq_id)
{
	struct scx_dispatch_q *dq;
	u64 enq_flags = 0, opss;

	dq_id_pull_enq_flags(&dq_id, &enq_flags);
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
		 * it - sq's are allowed to dispatch tasks spuriously and there
		 * can be a racing dequeue attempt. Let's claim @p by atomically
		 * transitioning it from QUEUED to DISPATCHING.
		 */
		if (likely(atomic64_try_cmpxchg(&p->scx.ops_state, &opss,
						SCX_OPSS_DISPATCHING)))
			break;
		goto retry;
	case SCX_OPSS_QUEUEING:
		/* do_enqueue_task() still in progress, wait */
		wait_ops_state(p, opss);
		goto retry;
	}

	BUG_ON(!(p->scx.flags & SCX_TASK_QUEUED));

	switch (dispatch_to_local_dq(rq, rf, dq_id, p, enq_flags)) {
	case DTL_DISPATCHED:
		return true;
	case DTL_LOST:
		return false;
	case DTL_INVALID:
		dq_id = SCX_DQ_GLOBAL;
		break;
	case DTL_NOT_LOCAL:
		break;
	}

	dq = find_dq_for_dispatch(cpu_rq(raw_smp_processor_id()), dq_id, p);
	dispatch_enqueue(dq, p, enq_flags | SCX_ENQ_CLEAR_OPSS);
	return false;
}

static void set_consume_ctx(struct rq *rq, struct rq_flags *rf)
{
	*this_cpu_ptr(&consume_ctx) = (struct consume_ctx){ .rq = rq, .rf = rf };
}

static enum scx_cpu_preempt_reason
preempt_reason_from_class(const struct sched_class *class)
{
	if (class == &stop_sched_class)
		return SCX_CPU_PREEMPT_RT;
	else if (class == &dl_sched_class)
		return SCX_CPU_PREEMPT_DL;
	else if (class == &rt_sched_class)
		return SCX_CPU_PREEMPT_STOP;
	else
		return SCX_CPU_PREEMPT_UNKNOWN;
}

int balance_scx(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct scx_rq *scx_rq = &rq->scx;
	bool prev_on_scx = prev->sched_class == &ext_sched_class;
	int err;

	lockdep_assert_rq_held(rq);

	if (static_branch_unlikely(&scx_ops_cpu_preempt) &&
	    (rq->scx.prev_class != &ext_sched_class)) {
		/*
		 * If the previous sched_class for the current CPU was not SCX,
		 * notify the BPF scheduler that it again has control of the
		 * core. This callback complements ->cpu_release(), which is
		 * emitted in scx_notify_pick_next_task().
		 */
		if (SCX_HAS_OP(cpu_acquire))
			scx_ops.cpu_acquire(cpu_of(rq), NULL);
		rq->scx.prev_class = &ext_sched_class;
	}

	if (prev_on_scx) {
		WARN_ON_ONCE(prev->scx.flags & SCX_TASK_BAL_KEEP);
		update_curr_scx(rq);

		/*
		 * If @prev is runnable & has slice left, it has priority and
		 * fetching more just increases latency for the fetched task.
		 * Tell put_prev_task_scx() to put @prev on local_dq.
		 *
		 * See scx_ops_disable_workfn() for the explanation on the
		 * DISABLING test.
		 */
		if ((prev->scx.flags & SCX_TASK_QUEUED) &&
		    prev->scx.slice > 0 && !scx_ops_disabling()) {
			prev->scx.flags |= SCX_TASK_BAL_KEEP;
			return 1;
		}
	}
retry:
	/* if there already are tasks to run, nothing to do */
	if (scx_rq->local_dq.nr)
		return 1;

	if (SCX_HAS_OP(consume)) {
		set_consume_ctx(rq, rf);
		scx_ops.consume(cpu_of(rq));
		if (scx_rq->local_dq.nr)
			return 1;
	} else {
		if (consume_dispatch_q(rq, rf, &scx_dq_global))
			return 1;
	}

	if (SCX_HAS_OP(dispatch)) {
		int i, nr, nr_local = 0;

		*this_cpu_ptr(&dispatch_buf_cursor) = 0;

		extl_dispatch_pre();

		/*
		 * Passing in a task not initialized for ops can confuse it.
		 * Pass in NULL if @prev is not known to ops.
		 */
		if (prev_on_scx && scx_ops_enabled(prev, 0))
			err = scx_ops.dispatch(cpu_of(rq), prev);
		else
			err = scx_ops.dispatch(cpu_of(rq), NULL);

		extl_dispatch_post();

		if (unlikely(err)) {
			err = ops_sanitize_err("dispatch", err);
			scx_ops_error("dispatch failed with %d", err);
		}

		nr = this_cpu_read(dispatch_buf_cursor);
		if (!nr) {
			if (SCX_HAS_OP(consume_final)) {
				set_consume_ctx(rq, rf);
				scx_ops.consume_final(cpu_of(rq));
				return rq->scx.local_dq.nr > 0;
			}
			return 0;
		}

		for (i = 0; i < nr; i++) {
			struct dispatch_buf_ent *ent =
				&this_cpu_ptr(dispatch_buf)[i];

			if (finish_dispatch(rq, rf,
					    ent->task, ent->qseq, ent->dq_id))
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

	/* see dequeue_task_scx() on why we skip when !QUEUED */
	if (SCX_OP_ENABLED(running, p, 0) && (p->scx.flags & SCX_TASK_QUEUED))
		scx_ops.running(p);

	/*
	 * @p is getting newly scheduled or got kicked after someone updated its
	 * slice. Refresh whether tick can be stopped. See can_stop_tick_scx().
	 */
	if ((p->scx.slice == SCX_SLICE_INF) !=
	    (bool)(rq->scx.flags & SCX_RQ_CAN_STOP_TICK)) {
		if (p->scx.slice == SCX_SLICE_INF)
			rq->scx.flags |= SCX_RQ_CAN_STOP_TICK;
		else
			rq->scx.flags &= ~SCX_RQ_CAN_STOP_TICK;

		sched_update_tick_dependency(rq);
	}
}

static void put_prev_task_scx(struct rq *rq, struct task_struct *p)
{
	update_curr_scx(rq);

	/* see dequeue_task_scx() on why we skip when !QUEUED */
	if (SCX_OP_ENABLED(stopping, p, 0) && (p->scx.flags & SCX_TASK_QUEUED))
		scx_ops.stopping(p, true);

	/*
	 * If we're being called from put_prev_task_balance(), balance_scx()
	 * already updated @p's runtime and may also have decided that it should
	 * keep running.
	 */
	if (p->scx.flags & SCX_TASK_BAL_KEEP) {
		p->scx.flags &= ~SCX_TASK_BAL_KEEP;
		dispatch_enqueue(&rq->scx.local_dq, p, SCX_ENQ_HEAD);
		return;
	}

	if (p->scx.flags & SCX_TASK_QUEUED) {
		/*
		 * If @p still has slice left and balance_scx() didn't tag it
		 * for keeping, @p is getting preempted by a higher scheduling
		 * class task. Indicate that waking up an idle CPU to take over
		 * execution may be useful. We shouldn't refill the slice in
		 * this case.
		 */
		if (p->scx.slice > 0 && !scx_ops_disabling()) {
			do_enqueue_task(rq, p,
					SCX_ENQ_HEAD | SCX_ENQ_WAKE_IDLE, -1);
			return;
		}

		/*
		 * If we're in the pick_next_task path, balance_scx() should
		 * have already populated local_dq if there are any other
		 * available tasks. If local_dq is empty, tell enqueue() that @p
		 * is the only one available for this cpu. enqueue() should put
		 * it on local_dq so that the subsequent pick_next_task_scx()
		 * can find the task unless it wants to trigger a separate
		 * follow-up scheduling event.
		 */
		if (list_empty(&rq->scx.local_dq.fifo))
			do_enqueue_task(rq, p, SCX_ENQ_LAST, -1);
		else
			do_enqueue_task(rq, p, 0, -1);
	}

	/*
	 * If ops is not enabled, we can consider here as the start of the next
	 * dispatch cycle. Refill the slice.
	 */
	if (!scx_ops_enabled(p, 0))
		p->scx.slice = SCX_SLICE_DFL;
}

static struct task_struct *pick_task_scx(struct rq *rq)
{
	return list_first_entry_or_null(&rq->scx.local_dq.fifo,
					struct task_struct, scx.dq_node);
}

static struct task_struct *pick_next_task_scx(struct rq *rq)
{
	struct task_struct *p;

	p = pick_task_scx(rq);
	if (!p)
		return NULL;

	if (unlikely(!p->scx.slice)) {
		if (scx_ops_enable_state() != SCX_OPS_DISABLING &&
		    scx_ops_enabled(p, 0) && !warned_zero_slice) {
			printk_deferred(KERN_WARNING "sched_ext: %s[%d] has zero slice in pick_next_task_scx(), ops_enabled=%d\n",
					p->comm, p->pid, scx_ops_enabled(p, 0));
			warned_zero_slice = true;
		}
		p->scx.slice = SCX_SLICE_DFL;
	}

	set_next_task_scx(rq, p, true);

	return p;
}

void __scx_notify_pick_next_task(struct rq *rq,
				 const struct task_struct *task,
				 const struct sched_class *active)
{
	const struct sched_class *prev_class = rq->scx.prev_class;

	lockdep_assert_rq_held(rq);

	if (likely(prev_class == active))
		return;

	/*
	 * Don't invoke the callback if the CPU is going idle. The callback is
	 * conceptually meant to convey that the CPU is no longer under the
	 * control of SCX. If the CPU is going idle, SCX has decided not to
	 * schedule any tasks on it. If it was previously under the control of
	 * another scheduler, SCX will emit the ->cpu_acquire() callback in
	 * balance_scx().
	 */
	if (active == &idle_sched_class)
		return;

	if (prev_class == &ext_sched_class) {
		/*
		 * If the previous sched_class for the current CPU was SCX,
		 * notify the BPF scheduler that it no longer has control of
		 * the core. This callback complements ->cpu_acquire(), which
		 * is emitted the next time that balance_scx() is invoked.
		 */
		if (SCX_HAS_OP(cpu_release)) {
			struct scx_cpu_release_args args = {
				.reason = preempt_reason_from_class(active),
				.task = task,
			};

			scx_ops.cpu_release(cpu_of(rq), &args);
		}
		rq->scx.prev_class = active;
	}
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
	 * local dq of the waker.
	 */
	if ((wake_flags & SCX_WAKE_SYNC) && p->nr_cpus_allowed > 1 &&
	    has_idle_cpus && !(current->flags & PF_EXITING)) {
		cpu = smp_processor_id();
		if (cpumask_test_cpu(cpu, p->cpus_ptr)) {
			p->scx.flags |= SCX_TASK_SCD_ENQ_LOCAL;
			return cpu;
		}
	}

	/* if the previous CPU is idle, dispatch directly to it */
	if (test_and_clear_cpu_idle(prev_cpu)) {
		p->scx.flags |= SCX_TASK_SCD_ENQ_LOCAL;
		return prev_cpu;
	}

	if (p->nr_cpus_allowed == 1)
		return prev_cpu;

	cpu = scx_pick_idle_cpu(p->cpus_ptr);
	if (cpu >= 0) {
		p->scx.flags |= SCX_TASK_SCD_ENQ_LOCAL;
		return cpu;
	}

	return prev_cpu;
}

static int select_task_rq_scx(struct task_struct *p, int prev_cpu, int wake_flags)
{
	if (SCX_OP_ENABLED(select_cpu, p, 0)) {
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
	 * Fine grained memory write control is enforced by BPF making the const
	 * designation pointless. Cast it away when calling the operation.
	 */
	if (SCX_OP_ENABLED(set_cpumask, p, 0))
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
		if (!static_branch_likely(&scx_builtin_idle_enabled))
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

static void rq_online_scx(struct rq *rq, bool for_hotplug)
{
	if (SCX_HAS_OP(cpu_online) && for_hotplug)
		scx_ops.cpu_online(cpu_of(rq));
}

static void rq_offline_scx(struct rq *rq, bool for_hotplug)
{
	if (SCX_HAS_OP(cpu_offline) && for_hotplug)
		scx_ops.cpu_offline(cpu_of(rq));
}

#else /* !CONFIG_SMP */

static bool test_and_clear_cpu_idle(int cpu) { return false; }
static int scx_pick_idle_cpu(const struct cpumask *cpus_allowed) { return -EBUSY; }
static s32 scx_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags) { return 0; }
static void reset_idle_masks(void) {}

#endif /* CONFIG_SMP */

static void task_tick_scx(struct rq *rq, struct task_struct *curr, int queued)
{
	update_curr_scx(rq);

	/* always resched while disabling as we can't trust the slice */
	if (!curr->scx.slice || scx_ops_disabling())
		resched_curr(rq);
}

static struct cgroup *tg_cgrp(struct task_group *tg)
{
	/*
	 * If CGROUP_SCHED is disabled, @tg is NULL. If @tg is an autogroup,
	 * @tg->css.cgroup is NULL. In both cases, @tg can be treated as the
	 * root cgroup.
	 */
	if (tg && tg->css.cgroup)
		return tg->css.cgroup;
	else
		return &cgrp_dfl_root.cgrp;
}

static int scx_ops_prep_enable(struct task_struct *p, struct task_group *tg)
{
	int ret;

	ret = extl_prep_enable_pre(p, tg);
	if (ret)
		return ret;

	if (SCX_HAS_OP(prep_enable)) {
		struct scx_enable_args args = { .cgroup = tg_cgrp(tg) };

		ret = scx_ops.prep_enable(p, &args);
		if (unlikely(ret))
			ret = ops_sanitize_err("prep_enable", ret);
	}
	if (ret)
		extl_cancel_enable(p, tg);

	return ret;
}

static void scx_ops_enable_task(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));

	extl_enable_pre(p);

	if (SCX_HAS_OP(enable)) {
		struct scx_enable_args args =
			{ .cgroup = tg_cgrp(p->sched_task_group) };
		scx_ops.enable(p, &args);
	}
	p->scx.flags |= SCX_TASK_OPS_ENABLED;

	extl_enable_post(p);
}

static void scx_ops_cancel_enable(struct task_struct *p, struct task_group *tg)
{
	if (SCX_HAS_OP(cancel_enable)) {
		struct scx_enable_args args = { .cgroup = tg_cgrp(tg) };
		scx_ops.cancel_enable(p, &args);
	}
	extl_cancel_enable(p, tg);
}

static void scx_ops_disable_task(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));

	if (p->scx.flags & SCX_TASK_OPS_ENABLED) {
		if (SCX_HAS_OP(disable))
			scx_ops.disable(p);
		extl_disable(p);
		p->scx.flags &= ~SCX_TASK_OPS_ENABLED;
	}
}

/**
 * refresh_scx_weight - Refresh a task's ext weight
 * @p: task to refresh ext weight for
 *
 * @p->scx.weight carries the task's static priority in cgroup weight scale to
 * enable efficient access for the bpf scheduler. To keep it synchronized with
 * the current task priority, this function should be called when a new task is
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
	percpu_down_read(&scx_ops_rwsem);
}

int scx_fork(struct task_struct *p)
{
	percpu_rwsem_assert_held(&scx_ops_rwsem);

	if (scx_ops_any_enabled(SCX_OPSEN_EXCLUDE_DISABLING))
		return scx_ops_prep_enable(p, task_group(p));
	else
		return 0;
}

void scx_post_fork(struct task_struct *p)
{
	refresh_scx_weight(p);

	spin_lock_irq(&scx_tasks_lock);
	list_add_tail(&p->scx.tasks_node, &scx_tasks);
	spin_unlock_irq(&scx_tasks_lock);

	if (scx_ops_any_enabled(SCX_OPSEN_EXCLUDE_DISABLING)) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		scx_ops_enable_task(p);
		task_rq_unlock(rq, p, &rf);
	}

	percpu_up_read(&scx_ops_rwsem);
}

void scx_cancel_fork(struct task_struct *p)
{
	if (scx_ops_any_enabled(SCX_OPSEN_EXCLUDE_DISABLING))
		scx_ops_cancel_enable(p, p->sched_task_group);
	percpu_up_read(&scx_ops_rwsem);
}

void sched_ext_free(struct task_struct *p)
{
	unsigned long flags;

	if (p->scx.flags & SCX_TASK_OPS_ENABLED) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		scx_ops_disable_task(p);
		task_rq_unlock(rq, p, &rf);
	}

	spin_lock_irqsave(&scx_tasks_lock, flags);
	list_del_init(&p->scx.tasks_node);
	spin_unlock_irqrestore(&scx_tasks_lock, flags);
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
	 * different scheduler class. Keep the bpf scheduler up-to-date.
	 */
	if (SCX_OP_ENABLED(set_cpumask, p, 0))
		scx_ops.set_cpumask(p, (struct cpumask *)p->cpus_ptr);
}

static void switched_to_scx(struct rq *rq, struct task_struct *p)
{
}

#ifdef CONFIG_NO_HZ_FULL
bool can_stop_tick_scx(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (scx_ops_disabling())
		return false;

	if (p->sched_class != &ext_sched_class)
		return true;

	/*
	 * @rq can consume from different dq's, so we can't tell whether it
	 * needs the tick or not by looking at nr_running. Allow stopping ticks
	 * iff the bpf scheduler indicated so. See set_next_task_scx().
	 */
	return rq->scx.flags & SCX_RQ_CAN_STOP_TICK;
}
#endif

#ifdef CONFIG_EXT_GROUP_SCHED

int scx_tg_online(struct task_group *tg)
{
	int ret = 0;

	WARN_ON_ONCE(tg->scx_flags & (SCX_TG_ONLINE | SCX_TG_INITED));

	percpu_down_read(&scx_ops_rwsem);

	if (SCX_HAS_OP(cgroup_init)) {
		struct scx_cgroup_init_args args = { .weight = tg->scx_weight };

		ret = scx_ops.cgroup_init(tg->css.cgroup, &args);
		if (!ret)
			tg->scx_flags |= SCX_TG_ONLINE | SCX_TG_INITED;
		else
			ret = ops_sanitize_err("cgroup_init", ret);
	} else {
		tg->scx_flags |= SCX_TG_ONLINE;
	}

	percpu_up_read(&scx_ops_rwsem);
	return ret;
}

void scx_tg_offline(struct task_group *tg)
{
	WARN_ON_ONCE(!(tg->scx_flags & SCX_TG_ONLINE));

	percpu_down_read(&scx_ops_rwsem);

	if (SCX_HAS_OP(cgroup_exit) && (tg->scx_flags & SCX_TG_INITED))
		scx_ops.cgroup_exit(tg->css.cgroup);
	tg->scx_flags &= ~(SCX_TG_ONLINE | SCX_TG_INITED);

	percpu_up_read(&scx_ops_rwsem);
}

/*
 * There can only be one cgroup migration in progress at any given moment. We
 * can use a static variable to remember the old cgroup.
 */
static struct cgroup *cgroup_move_from;

int scx_can_attach(struct task_group *tg, struct task_struct *p)
{
	int ret;

	/* released in cgroup_move_scx() */
	percpu_down_read(&scx_ops_rwsem);

	if (SCX_OP_ENABLED(cgroup_prep_move, p, 0)) {
		WARN_ON_ONCE(cgroup_move_from);
		cgroup_move_from = tg_cgrp(p->sched_task_group);
		ret = scx_ops.cgroup_prep_move(p, cgroup_move_from, tg_cgrp(tg));
		if (!ret)
			return 0;
		else
			return ops_sanitize_err("cgroup_prep_move", ret);
	} else {
		return 0;
	}
}

void cgroup_move_scx(struct task_struct *p)
{
	/*
	 * This is where cgroup attach is committed. The up_read is
	 * paired with the down_write in sched_ext_can_attach().
	 */
	if (SCX_OP_ENABLED(cgroup_move, p, 0)) {
		WARN_ON_ONCE(!cgroup_move_from);
		scx_ops.cgroup_move(p, cgroup_move_from,
				    tg_cgrp(p->sched_task_group));
		cgroup_move_from = NULL;
	}

	/* acquired in scx_can_attach() */
	percpu_up_read(&scx_ops_rwsem);
}

void scx_cancel_attach(struct task_group *tg, struct task_struct *p)
{
	if (SCX_OP_ENABLED(cgroup_cancel_move, p, 0)) {
		WARN_ON_ONCE(!cgroup_move_from);
		scx_ops.cgroup_cancel_move(p, cgroup_move_from, tg_cgrp(tg));
		cgroup_move_from = NULL;
	}
	percpu_up_read(&scx_ops_rwsem);
}

void scx_group_set_weight(struct task_group *tg, unsigned long weight)
{
	percpu_down_read(&scx_ops_rwsem);

	if (tg->scx_weight != weight) {
		if (SCX_HAS_OP(cgroup_set_weight))
			scx_ops.cgroup_set_weight(tg_cgrp(tg), weight);
		tg->scx_weight = weight;
	}

	percpu_up_read(&scx_ops_rwsem);
}

#endif	/* CONFIG_EXT_GROUP_SCHED */

/*
 * Omitted operations:
 *
 * - check_preempt_curr: NOOP as it isn't useful in the wakeup path because the
 *   task isn't tied to the CPU at that point. Preemption can be implemented by
 *   resetting the victim task's slice to 0 and explicitly triggering reschedule
 *   on the target CPU with scx_bpf_kick_cpu().
 *
 * - migrate_task_rq: Task to cpu mapping is transparently transient on
 *   sched_ext making this operation unnecessary.
 *
 * - task_fork/dead: We need fork/dead operations for all tasks regardless of
 *   the task's sched_class. Call them directly from sched core instead.
 *
 * - task_woken, switched_from: Not needed.
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

	.rq_online		= rq_online_scx,
	.rq_offline		= rq_offline_scx,
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

static void init_dq(struct scx_dispatch_q *dq, s64 dq_id)
{
	memset(dq, 0, sizeof(*dq));

	raw_spin_lock_init(&dq->lock);
	INIT_LIST_HEAD(&dq->fifo);
	dq->id = dq_id;
}

int sched_ext_ops_handler(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	char val[SCX_OPS_NAME_LEN];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = sizeof(val),
	};

	percpu_down_read(&scx_ops_rwsem);
	strlcpy(val, scx_ops.name, sizeof(val));
	percpu_up_read(&scx_ops_rwsem);

	return proc_dostring(&tbl, false, buffer, lenp, ppos);
}

static struct scx_dispatch_q *create_dq(s64 dq_id, int node)
{
	struct scx_dispatch_q *dq;
	int ret;

	if (dq_id < 0 || (dq_id & ~SCX_DQ_ID_MASK))
		return ERR_PTR(-EINVAL);

	dq = kmalloc_node(sizeof(*dq), GFP_KERNEL, node);
	if (!dq)
		return ERR_PTR(-ENOMEM);

	init_dq(dq, dq_id);

	raw_spin_lock_irq(&all_dqs_lock);
	ret = rhashtable_insert_fast(&dq_hash, &dq->hash_node, dq_hash_params);
	if (!ret) {
		list_add_tail_rcu(&dq->all_node, &all_dqs);
	} else {
		kfree(dq);
		dq = ERR_PTR(ret);
	}
	raw_spin_unlock_irq(&all_dqs_lock);
	return dq;
}

static void free_dq_irq_workfn(struct irq_work *irq_work)
{
	struct llist_node *to_free = llist_del_all(&dqs_to_free);
	struct scx_dispatch_q *dq, *tmp_dq;

	llist_for_each_entry_safe(dq, tmp_dq, to_free, free_node)
		kfree_rcu(dq);
}

static DEFINE_IRQ_WORK(free_dq_irq_work, free_dq_irq_workfn);

static int destroy_dq(s64 dq_id)
{
	struct scx_dispatch_q *dq;
	unsigned long flags;
	int ret;

	rcu_read_lock();

	dq = rhashtable_lookup_fast(&dq_hash, &dq_id, dq_hash_params);
	if (!dq) {
		ret = -ENOENT;
		goto out_unlock_rcu;
	}

	raw_spin_lock_irqsave(&all_dqs_lock, flags);
	raw_spin_lock(&dq->lock);

	if (dq->nr) {
		scx_ops_error("attempting to destroy in-use dq 0x%016llx (nr=%u)",
			      dq->id, dq->nr);
		ret = -EBUSY;
		goto out_unlock_dq;
	}

	ret = rhashtable_remove_fast(&dq_hash, &dq->hash_node, dq_hash_params);
	if (ret)
		goto out_unlock_dq;

	/*
	 * Mark dead by flipping id negative to prevent dispatch_enqueue() from
	 * queueing more tasks. As this function can be called from anywhere,
	 * freeing is bounced through an irq work to avoid nesting RCU
	 * operations inside scheduler locks.
	 */
	dq->id = -dq->id;
	list_del_rcu(&dq->all_node);
	llist_add(&dq->free_node, &dqs_to_free);
	irq_work_queue(&free_dq_irq_work);

out_unlock_dq:
	raw_spin_unlock(&dq->lock);
	raw_spin_unlock_irqrestore(&all_dqs_lock, flags);
out_unlock_rcu:
	rcu_read_unlock();
	return ret;
}

#ifdef CONFIG_EXT_GROUP_SCHED
static void scx_cgroup_exit(void)
{
	struct cgroup_subsys_state *css;

	if (!scx_ops.cgroup_init)
		return;

	/*
	 * SCX_HAS_OP(cgroup_init) is %false and SCX_TG_* flag changes in
	 * scx_tg_on/offline() are excluded through scx_ops_rwsem. If we walk
	 * all cgroups and exit all the inited ones, it's guaranteed that all
	 * online cgroups are exited.
	 */
	rcu_read_lock();
	css_for_each_descendant_post(css, &root_task_group.css) {
		struct task_group *tg = css_tg(css);

		if (!(tg->scx_flags & SCX_TG_INITED))
			continue;
		tg->scx_flags &= ~SCX_TG_INITED;

		if (!scx_ops.cgroup_exit)
			continue;

		if (WARN_ON_ONCE(!css_tryget(css)))
			continue;
		rcu_read_unlock();

		scx_ops.cgroup_exit(css->cgroup);

		rcu_read_lock();
		css_put(css);
	}
	rcu_read_unlock();
}

static int scx_cgroup_init(void)
{
	struct cgroup_subsys_state *css;
	int ret;

	if (!scx_ops.cgroup_init)
		return 0;

	/*
	 * At this point, SCX_HAS_OP(cgroup_init) is %true and SCX_TG_* flag
	 * changes in scx_tg_on/offline() are excluded through scx_ops_rwsem. If
	 * we walk all cgroups and init all the uninited online ones, it's
	 * guaranteed that all online cgroups are initialized.
	 */
	rcu_read_lock();
	css_for_each_descendant_pre(css, &root_task_group.css) {
		struct task_group *tg = css_tg(css);
		struct scx_cgroup_init_args args = { .weight = tg->scx_weight };

		if ((tg->scx_flags &
		     (SCX_TG_ONLINE | SCX_TG_INITED)) != SCX_TG_ONLINE)
			continue;

		if (WARN_ON_ONCE(!css_tryget(css)))
			continue;
		rcu_read_unlock();

		ret = scx_ops.cgroup_init(css->cgroup, &args);
		if (ret) {
			css_put(css);
			return ret;
		}
		tg->scx_flags |= SCX_TG_INITED;

		rcu_read_lock();
		css_put(css);
	}
	rcu_read_unlock();

	return 0;
}

static void scx_cgroup_config_knobs(void)
{
	static DEFINE_MUTEX(cgintf_mutex);
	DECLARE_BITMAP(mask, CPU_CFTYPE_CNT) = { };
	u64 knob_flags;
	int i;

	/*
	 * Called from both class switch and ops enable/disable paths,
	 * synchronize internally.
	 */
	mutex_lock(&cgintf_mutex);

	/* if !ext, all knobs should be shown */
	if (normal_sched_class() != &ext_sched_class) {
		bitmap_fill(mask, CPU_CFTYPE_CNT);
		goto apply;
	}

	/*
	 * On ext, only show the supported knobs if ops is enabled. Otherwise,
	 * show all possible knobs so that configuration attempts succeed and
	 * the states are remembered while ops is not loaded.
	 */
	if (scx_ops_any_enabled(0))
		knob_flags = scx_ops.flags;
	else
		knob_flags = SCX_OPS_ALL_FLAGS;

	if (knob_flags & SCX_OPS_CGROUP_KNOB_WEIGHT) {
		__set_bit(CPU_CFTYPE_WEIGHT, mask);
		__set_bit(CPU_CFTYPE_WEIGHT_NICE, mask);
	}
apply:
	for (i = 0; i < CPU_CFTYPE_CNT; i++)
		cgroup_show_cftype(&cpu_cftypes[i], test_bit(i, mask));

	mutex_unlock(&cgintf_mutex);
}

#else
static void scx_cgroup_exit(void) {}
static int scx_cgroup_init(void) { return 0; }
static void scx_cgroup_config_knobs(void) {}
#endif

static void reset_dispatch_free_dq_fn(void *ptr, void *arg)
{
	struct scx_dispatch_q *dq = ptr;

	WARN_ON_ONCE(dq->nr || !list_empty(&dq->fifo));
	kfree(dq);
}

static void reset_dispatch(void)
{
	rhashtable_free_and_destroy(&dq_hash, reset_dispatch_free_dq_fn, NULL);
	INIT_LIST_HEAD(&all_dqs);
	free_percpu(dispatch_buf);
	dispatch_buf = NULL;
	dispatch_max_batch = 0;
}

static s64 scx_ops_fallback_enqueue(struct task_struct *p, u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_LAST)
		return SCX_DQ_LOCAL;
	else
		return SCX_DQ_GLOBAL;
}

static void scx_ops_fallback_consume(s32 cpu)
{
	struct consume_ctx *cctx = this_cpu_ptr(&consume_ctx);

	consume_dispatch_q(cctx->rq, cctx->rf, &scx_dq_global);
}

static void scx_ops_disable_workfn(struct kthread_work *work)
{
	struct scx_ops_exit_info *ei = &scx_ops_exit_info;
	struct scx_task_iter sti;
	struct task_struct *p;
	int i, cpu, type;

	type = atomic_read(&scx_ops_exit_type);
	while (true) {
		/*
		 * NONE indicates that a new scx_ops has been registered since
		 * disable was scheduled - don't kill the new ops. DONE
		 * indicates that the ops has already been disabled.
		 */
		if (type == SCX_OPS_EXIT_NONE || type == SCX_OPS_EXIT_DONE)
			return;
		if (atomic_try_cmpxchg(&scx_ops_exit_type, &type,
				       SCX_OPS_EXIT_DONE))
			break;
	}
	ei->type = type;

	switch (scx_ops_set_enable_state(SCX_OPS_DISABLING)) {
	case SCX_OPS_DISABLED:
		pr_warn("sched_ext: ops error detected without ops (%s)",
			scx_ops_exit_info.msg);
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
	 * that the ops and static branches are set and some tasks might already
	 * have ops enabled.
	 *
	 * We must guarantee that all runnable tasks make forward progress
	 * without trusting the bpf scheduler. We can't grab any mutexes or
	 * rwsems as they might be held by tasks that the bpf scheduler is
	 * forgetting to dispatch, which unfortunately also excludes toggling
	 * the static branches.
	 *
	 * Let's work around by overriding a couple ops and modifying behaviors
	 * based on the DISABLING state and then cycle the tasks through
	 * dequeue/enqueue to force global FIFO scheduling.
	 *
	 * a. scx_ops->enqueue() and ->consume() are overridden for simple global
	 *    FIFO scheduling.
	 *
	 * b. balance_scx() never sets %SCX_TASK_BAL_KEEP as the slice value
	 *    can't be trusted. Whenever a tick triggers, the running task is
	 *    rotated to the tail of the queue.
	 *
	 * c. pick_next_task() suppresses zero slice warning.
	 *
	 * Note that b. and c. must test scx_ops_enable_state() directly.
	 * scx_ops_enabled() or SCX_OP_ENABLED() won't work as
	 * scx_ops_all_enabled might be enabled.
	 */
	scx_ops.enqueue = scx_ops_fallback_enqueue;
	scx_ops.consume = scx_ops_fallback_consume;

	spin_lock_irq(&scx_tasks_lock);
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		struct sched_enq_and_set_ctx ctx;

		sched_deq_and_put_task(p, DEQUEUE_SAVE, &ctx);
		sched_enq_and_set_task(&ctx);
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);

	/* kick all CPUs to restore ticks */
	for_each_possible_cpu(cpu)
		resched_cpu(cpu);

forward_progress_guaranteed:
	/*
	 * Here, every runnable task is guaranteed to make forward progress and
	 * we can safely use blocking synchronization constructs. Turn off
	 * scx_ops_all_enabled and actually disable ops.
	 */
	cpus_read_lock();
	percpu_down_write(&scx_ops_rwsem);

	static_branch_disable_cpuslocked(&scx_ops_all_enabled);

	spin_lock_irq(&scx_tasks_lock);
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		struct sched_enq_and_set_ctx ctx;

		sched_deq_and_put_task(p, DEQUEUE_SAVE, &ctx);
		scx_ops_disable_task(p);
		p->scx.slice = min_t(u64, p->scx.slice, SCX_SLICE_DFL);
		sched_enq_and_set_task(&ctx);
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);

	/* no task is on scx, turn off all the switches and flush in-progress calls */
	static_branch_enable_cpuslocked(&scx_ops_all_disabled);

	for (i = 0; i < SCX_NR_ONLINE_OPS; i++)
		static_branch_disable_cpuslocked(&scx_has_op[i]);

	static_branch_disable_cpuslocked(&scx_ops_enq_last);
	static_branch_disable_cpuslocked(&scx_ops_enq_exiting);
	static_branch_disable_cpuslocked(&scx_ops_cpu_preempt);

	synchronize_rcu();

	/* cgroup cleanup */
	scx_cgroup_exit();

	/* restore builtin idle tracking */
	static_branch_enable_cpuslocked(&scx_builtin_idle_enabled);
	reset_idle_masks();

	if (ei->type == SCX_OPS_EXIT_ERROR) {
		printk(KERN_ERR "sched_ext: bpf ops %s errored, reverted to FIFO \"%s\"\n",
		       scx_ops.name, ei->msg);
		stack_trace_print(ei->bt, ei->bt_len, 2);

		if (scx_ops.exit)
			scx_ops.exit(ei);
	} else {
		if (scx_ops.exit)
			scx_ops.exit(ei);
	}

	memset(&scx_ops, 0, sizeof(scx_ops));
	reset_dispatch();
	extl_exit();

	percpu_up_write(&scx_ops_rwsem);
	cpus_read_unlock();

	WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_DISABLED) !=
		     SCX_OPS_DISABLING);

	scx_cgroup_config_knobs();
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

static void scx_ops_disable(enum scx_ops_exit_type type)
{
	int none = SCX_OPS_EXIT_NONE;

	if (WARN_ON_ONCE(type == SCX_OPS_EXIT_NONE ||
			 type == SCX_OPS_EXIT_DONE))
		type = SCX_OPS_EXIT_ERROR;

	atomic_try_cmpxchg(&scx_ops_exit_type, &none, type);

	schedule_scx_ops_disable_work();
}

static void scx_ops_disable_flush(void)
{
	kthread_flush_work(&scx_ops_disable_work);
}

static void scx_ops_error_irq_workfn(struct irq_work *irq_work)
{
	schedule_scx_ops_disable_work();
}

static DEFINE_IRQ_WORK(scx_ops_error_irq_work, scx_ops_error_irq_workfn);

__printf(1, 2) void scx_ops_error(const char *fmt, ...)
{
	struct scx_ops_exit_info *ei = &scx_ops_exit_info;
	int none = SCX_OPS_EXIT_NONE;
	va_list args;

	if (!atomic_try_cmpxchg(&scx_ops_exit_type, &none, SCX_OPS_EXIT_ERROR))
		return;

	ei->bt_len = stack_trace_save(ei->bt, ARRAY_SIZE(ei->bt), 1);

	va_start(args, fmt);
	vscnprintf(ei->msg, ARRAY_SIZE(ei->msg), fmt, args);
	va_end(args);

	irq_work_queue(&scx_ops_error_irq_work);
}

static int scx_ops_helper_init(void)
{
	static DEFINE_MUTEX(helper_mutex);
	struct kthread_worker *helper;
	int ret = 0;

	if (scx_ops_helper)
		return 0;

	mutex_lock(&helper_mutex);
	if (scx_ops_helper)
		goto out_unlock;

	helper = kthread_create_worker(0, "sched_ext_helper");
	if (!helper) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	sched_set_fifo(helper->task);
	WRITE_ONCE(scx_ops_helper, helper);
out_unlock:
	mutex_unlock(&helper_mutex);
	return ret;
}

static int scx_ops_enable(struct sched_ext_ops *ops)
{
	struct scx_task_iter sti;
	struct task_struct *p, *failed_p = NULL;
	int i, ret;

	ret = scx_ops_helper_init();
	if (ret)
		return ret;

	/*
	 * Keep CPUs stable during enable so that the bpf scheduler can track
	 * online CPUs by watching ->on/offline_cpu() after ->init().
	 */
	cpus_read_lock();

	/*
	 * Synchronization is tricky because the first phase of disabling can't
	 * grab any mutex. See scx_ops_disable_workfn() for details.
	 */
	percpu_down_write(&scx_ops_rwsem);

	if (scx_ops_enable_state() != SCX_OPS_DISABLED) {
		ret = -EBUSY;
		goto err_unlock;
	}

	ret = rhashtable_init(&dq_hash, &dq_hash_params);
	if (ret)
		goto err_unlock;

	if (ops->init) {
		ret = ops->init();
		if (ret) {
			ret = ops_sanitize_err("init", ret);
			goto err_reset;
		}
	}

	WARN_ON_ONCE(dispatch_buf);
	dispatch_max_batch = ops->dispatch_max_batch ?: SCX_DSP_DFL_MAX_BATCH;
	dispatch_buf = __alloc_percpu(sizeof(dispatch_buf[0]) * dispatch_max_batch,
				      __alignof__(dispatch_buf[0]));
	if (!dispatch_buf) {
		ret = -ENOMEM;
		goto err_reset;
	}

	/*
	 * Transition to PREPPING and clear exit info to arm the disable path.
	 * Failure requires full disabling from here on.
	 */
	if (!scx_ops_tryset_enable_state(SCX_OPS_PREPPING, SCX_OPS_DISABLED)) {
		ret = -EBUSY;
		goto err_reset;
	}

	memset(&scx_ops_exit_info, 0, sizeof(scx_ops_exit_info));
	atomic_set(&scx_ops_exit_type, SCX_OPS_EXIT_NONE);
	warned_zero_slice = false;

	/*
	 * Set ops and open the floodgate. This should be done while holding
	 * scx_ops_rwsem as we want multiple operations in the fork path to be
	 * enabled atomically.
	 */
	scx_ops = *ops;

	/*
	 * ->consume() may starve the global dq which can stall enabling. Use
	 * the fallback variant until we can atomically switch over.
	 */
	if (scx_ops.consume)
		scx_ops.consume = scx_ops_fallback_consume;

	static_branch_disable_cpuslocked(&scx_ops_all_disabled);

	for (i = 0; i < SCX_NR_ONLINE_OPS; i++)
		if (((void (**)(void))ops)[i])
			static_branch_enable_cpuslocked(&scx_has_op[i]);

	if (ops->flags & SCX_OPS_ENQ_LAST)
		static_branch_enable_cpuslocked(&scx_ops_enq_last);
	if (ops->flags & SCX_OPS_ENQ_EXITING)
		static_branch_enable_cpuslocked(&scx_ops_enq_exiting);
	if (scx_ops.cpu_acquire || scx_ops.cpu_release)
		static_branch_enable_cpuslocked(&scx_ops_cpu_preempt);

	if (ops->update_idle && !(ops->flags & SCX_OPS_KEEP_BUILTIN_IDLE))
		static_branch_disable_cpuslocked(&scx_builtin_idle_enabled);

	/*
	 * All cgroups should be initialized before letting in tasks. cgroups
	 * and task migrations are stabilized by scx_ops_rwsem.
	 */
	ret = scx_cgroup_init();
	if (ret)
		goto err_disable;

	/*
	 * Enable ops for each task. Fork is excluded by scx_ops_rwsem, so we
	 * can stabilize the list by pinning the tasks. Prep all tasks first and
	 * then enable them with preemption disabled.
	 */
	spin_lock_irq(&scx_tasks_lock);

	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered(&sti))) {
		get_task_struct(p);
		spin_unlock_irq(&scx_tasks_lock);

		ret = scx_ops_prep_enable(p, task_group(p));
		if (ret) {
			pr_err("sched_ext: prep_enable failed (%d) for %s[%d] while loading",
			       ret, p->comm, p->pid);
			spin_lock_irq(&scx_tasks_lock);
			scx_task_iter_exit(&sti);
			failed_p = p;
			goto err_cancel_enable;
		}
		spin_lock_irq(&scx_tasks_lock);
	}
	scx_task_iter_exit(&sti);

	/*
	 * All tasks are fully prepped but are still ops-disabled. Ensure that
	 * %current can't be scheduled out, enable ->consume() and then switch
	 * everyone. This is necessary because we can't guarantee that %current
	 * won't be starved if switched out in the middle of enabling.
	 */
	preempt_disable();
	if (scx_ops.consume)
		scx_ops.consume = ops->consume;

	/*
	 * From here on, the disable path must assume that some tasks already
	 * have ops enabled and may need to be recovered. As the disabling path
	 * may modify scx_ops.consume without grabbing scx_ops_rwsem once
	 * ENABLING is set, this must be done after we're done messing with
	 * scx_ops.consume.
	 */
	if (!scx_ops_tryset_enable_state(SCX_OPS_ENABLING, SCX_OPS_PREPPING)) {
		/* ENABLING was never set, we're protected by scx_ops_rwsem */
		if (scx_ops.consume)
			scx_ops.consume = scx_ops_fallback_consume;
		preempt_enable();
		ret = -EBUSY;
		goto err_cancel_enable;
	}

	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered(&sti))) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);

		if (!ret && READ_ONCE(p->__state) != TASK_DEAD) {
			struct sched_enq_and_set_ctx ctx;

			sched_deq_and_put_task(p, DEQUEUE_SAVE, &ctx);
			scx_ops_enable_task(p);
			sched_enq_and_set_task(&ctx);
		} else {
			scx_ops_cancel_enable(p, task_group(p));
		}

		task_rq_unlock(rq, p, &rf);
		put_task_struct(p);
	}
	scx_task_iter_exit(&sti);

	spin_unlock_irq(&scx_tasks_lock);
	preempt_enable();

	if (ret)
		goto err_disable;

	if (!scx_ops_tryset_enable_state(SCX_OPS_ENABLED, SCX_OPS_ENABLING)) {
		ret = -EBUSY;
		goto err_disable;
	}

	static_branch_enable_cpuslocked(&scx_ops_all_enabled);
	percpu_up_write(&scx_ops_rwsem);
	cpus_read_unlock();

	scx_cgroup_config_knobs();

	return 0;

err_reset:
	reset_dispatch();
	extl_exit();
err_unlock:
	percpu_up_write(&scx_ops_rwsem);
	cpus_read_unlock();
	return ret;

err_cancel_enable:
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered(&sti))) {
		struct rq_flags rf;
		struct rq *rq;

		if (p == failed_p) {
			put_task_struct(p);
			break;
		}

		rq = task_rq_lock(p, &rf);
		scx_ops_cancel_enable(p, task_group(p));
		task_rq_unlock(rq, p, &rf);
		put_task_struct(p);
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);
err_disable:
	percpu_up_write(&scx_ops_rwsem);
	cpus_read_unlock();
	/* must be fully disabled before returning */
	scx_ops_disable(SCX_OPS_EXIT_ERROR);
	scx_ops_disable_flush();
	return ret;
}


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
	int ret;

	ret = bpf_sched_extl_btf_struct_access(log, btf, t, off, size, atype,
					       next_btf_id);
	if (ret != -EAGAIN)
		return ret;

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
	case offsetof(struct sched_ext_ops, cgroup_init):
	case offsetof(struct sched_ext_ops, cgroup_exit):
	case offsetof(struct sched_ext_ops, cgroup_prep_move):
	case offsetof(struct sched_ext_ops, init):
	case offsetof(struct sched_ext_ops, exit):
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
	scx_ops_disable(SCX_OPS_EXIT_UNREG);
	scx_ops_disable_flush();
}

static int bpf_scx_init(struct btf *btf)
{
	u32 type_id;

	type_id = btf_find_by_name_kind(btf, "task_struct",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	task_struct_type = btf_type_by_id(btf, type_id);

	return bpf_sched_extl_init(btf);
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

static void switch_normal_class(const struct sched_class *old_class,
			       const struct sched_class *new_class)
{
	struct scx_task_iter sti;
	struct task_struct *p;

	/*
	 * While switching, keep both ext and fair running. This is necessary
	 * because self-reaping dying tasks may not be iterable and have to be
	 * drained from the current class.
	 */
	if (new_class == &ext_sched_class) {
		static_branch_enable(&__sched_ext_enabled);
		reset_idle_masks();
	} else {
		static_branch_enable(&__sched_fair_enabled);
	}

	/*
	 * Exclude the fork path so that we only need to iterate through the
	 * tasks once. While this can be made finer-grained by adding tasks
	 * earlier to the tasks list, it makes things more complicated as we
	 * then have to deal with tasks which aren't fully initialized. This is
	 * a cold path. Let's keep it simple.
	 */
	percpu_down_write(&scx_ops_rwsem);

	/*
	 * Ensure that %current is not preempted while switching. When we're
	 * switching from fair to ext, if there are enough threads to saturate
	 * all CPUs, and %current gets switched before them and then scheduled
	 * out, the saturating threads will always take precedence. %current
	 * will never get scheduled again.
	 */
	preempt_disable();

	__normal_sched_class = new_class;

	spin_lock_irq(&scx_tasks_lock);
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		if (p->sched_class == old_class) {
			struct sched_enq_and_set_ctx ctx;

			sched_deq_and_put_task(p, DEQUEUE_SAVE, &ctx);
			p->sched_class = new_class;
			check_class_changing(task_rq(p), p, old_class);
			sched_enq_and_set_task(&ctx);
			check_class_changed(task_rq(p), p, old_class, p->prio);
		}
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);

	preempt_enable();
	percpu_up_write(&scx_ops_rwsem);

	if (new_class == &ext_sched_class)
		static_branch_disable(&__sched_fair_enabled);
	else
		static_branch_disable(&__sched_ext_enabled);

	scx_cgroup_config_knobs();
}

int sched_normal_class_handler(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	char val[SCHED_NORMAL_CLASS_NAME_LEN];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = sizeof(val),
	};
	int ret;

	if (write) {
		static DEFINE_MUTEX(switch_mutex);
		const struct sched_class *old_class, *new_class;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		ret = proc_dostring(&tbl, true, buffer, lenp, ppos);
		if (ret)
			return ret;

		if (!strcmp(val, "fair"))
			new_class = &fair_sched_class;
		else if (!strcmp(val, "ext"))
			new_class = &ext_sched_class;
		else
			return -EINVAL;

		mutex_lock(&switch_mutex);

		old_class = normal_sched_class();
		if (old_class != new_class)
			switch_normal_class(old_class, new_class);

		mutex_unlock(&switch_mutex);
		return 0;
	} else {
		scnprintf(val, sizeof(val), "%s",
			  sched_ext_enabled() ? "ext" : "fair");
		return proc_dostring(&tbl, false, buffer, lenp, ppos);
	}
}

static void sysrq_handle_sched_ext_reset(int key)
{
	if (scx_ops_helper)
		scx_ops_disable(SCX_OPS_EXIT_SYSRQ);
	else
		pr_info("sched_ext bpf ops not used yet");
}

static const struct sysrq_key_op sysrq_sched_ext_reset_op = {
	.handler	= sysrq_handle_sched_ext_reset,
	.help_msg	= "reset-sched-ext(S)",
	.action_msg	= "Resetting sched_ext to FIFO scheduling. If stuck, try nice-all-RT-tasks(n).",
	.enable_mask	= SYSRQ_ENABLE_RTNICE,
};

#ifdef CONFIG_SMP
static void kick_cpus_irq_workfn(struct irq_work *irq_work)
{
	struct rq *this_rq = this_rq();
	int cpu, my_cpu = smp_processor_id();

	for_each_cpu(cpu, this_rq->scx.cpus_to_kick) {
		struct rq *rq = cpu_rq(cpu);
		unsigned long flags;
		bool is_my_cpu = cpu == my_cpu;
		bool should_wait = !is_my_cpu &&
				   cpumask_test_cpu(cpu, this_rq->scx.cpus_to_await);
		this_cpu_ptr(rq_generation)[cpu] = -1;

		raw_spin_rq_lock_irqsave(rq, flags);

		if (cpu_online(cpu) || is_my_cpu) {
			if (cpumask_test_cpu(cpu, this_rq->scx.cpus_to_preempt) &&
			    rq->curr->sched_class == &ext_sched_class)
				rq->curr->scx.slice = 0;
			if (should_wait)
				this_cpu_ptr(rq_generation)[cpu] = rq->scx.generation;
			resched_curr(rq);
		}

		raw_spin_rq_unlock_irqrestore(rq, flags);
	}

	for_each_cpu(cpu, this_rq->scx.cpus_to_await) {
		struct rq *rq;
		int generation;

		if (cpu == my_cpu)
			continue;

		rq = cpu_rq(cpu);
		generation = this_cpu_ptr(rq_generation)[cpu];

		/*
		 * Pairs with smp_store_release() issued by this CPU in
		 * scx_notify_pick_next_task() on the resched path.
		 *
		 * We busy-wait here to guarantee that no other task can be
		 * scheduled on our core before the target CPU has entered the
		 * resched path.
		 */
		while (smp_load_acquire(&rq->scx.generation) == generation)
			cpu_relax();
	}

	cpumask_clear(this_rq->scx.cpus_to_kick);
	cpumask_clear(this_rq->scx.cpus_to_preempt);
	cpumask_clear(this_rq->scx.cpus_to_await);
}
#endif

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

	init_dq(&scx_dq_global, SCX_DQ_GLOBAL);
#ifdef CONFIG_SMP
	BUG_ON(!alloc_cpumask_var(&idle_masks.cpu, GFP_KERNEL));
	BUG_ON(!alloc_cpumask_var(&idle_masks.smt, GFP_KERNEL));

	WARN_ON_ONCE(rq_generation);
	rq_generation = __alloc_percpu(sizeof(*rq_generation) * num_possible_cpus(),
				       __alignof__(*rq_generation));
	BUG_ON(!rq_generation);
#endif

	for_each_possible_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);

		init_dq(&rq->scx.local_dq, SCX_DQ_LOCAL);
		rq->scx.nr_running = 0;
		rq->scx.prev_class = __normal_sched_class;
#ifdef CONFIG_SMP
		BUG_ON(!zalloc_cpumask_var(&rq->scx.cpus_to_kick, GFP_KERNEL));
		BUG_ON(!zalloc_cpumask_var(&rq->scx.cpus_to_preempt, GFP_KERNEL));
		BUG_ON(!zalloc_cpumask_var(&rq->scx.cpus_to_await, GFP_KERNEL));
		init_irq_work(&rq->scx.kick_cpus_irq_work, kick_cpus_irq_workfn);
#endif
	}

	register_sysrq_key('S', &sysrq_sched_ext_reset_op);
	scx_cgroup_config_knobs();
}


/********************************************************************************
 * BPF helpers that can be called from sched_ext programs.
 */
#include <linux/btf_ids.h>

/**
 * scx_bpf_create_dq - Create a dq
 * @dq_id: dq to attach
 * @node: NUMA node to allocate from
 *
 * Create a dq identified by @dq_id. Can be called from ops->init(),
 * ->prep_enable() and ->cgroup_prep_move().
 */
static __used noinline s32 scx_bpf_create_dq(s64 dq_id, s32 node)
{
	if (unlikely(node >= (int)nr_node_ids ||
		     (node < 0 && node != NUMA_NO_NODE)))
		return -EINVAL;
	return PTR_ERR_OR_ZERO(create_dq(dq_id, node));
}

BTF_SET8_START(scx_kfunc_ids_sleepable)
BTF_ID_FLAGS(func, scx_bpf_create_dq)
BTF_SET8_END(scx_kfunc_ids_sleepable)

static const struct btf_kfunc_id_set scx_kfunc_set_sleepable = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_sleepable,
};

/**
 * scx_bpf_select_cpu_dfl - Default implementation of ops->select_cpu()
 * @p: waking task to select CPU for
 * @prev_cpu: cpu @p was on before going to sleep
 * @wake_flags: SCX_WAKE_* flags
 *
 * The default select_cpu() implementation. This is exported so that bpf
 * implementations can use it as a part of their select_cpu(). Can only be
 * called from select_cpu().
 */
static __used noinline s32 scx_bpf_select_cpu_dfl(struct task_struct *p,
						  s32 prev_cpu, u64 wake_flags)
{
	if (likely(prev_cpu < nr_cpu_ids))
		return scx_select_cpu_dfl(p, prev_cpu, wake_flags);
	else
		return prev_cpu;
}

BTF_SET8_START(scx_kfunc_ids_select_cpu)
BTF_ID_FLAGS(func, scx_bpf_select_cpu_dfl)
BTF_SET8_END(scx_kfunc_ids_select_cpu)

static const struct btf_kfunc_id_set scx_kfunc_set_select_cpu = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_select_cpu,
};

/**
 * scx_bpf_dispatch_nr_slots - Return the number of remaining dispatch slots
 */
__used noinline u32 scx_bpf_dispatch_nr_slots(void)
{
	return dispatch_max_batch - __this_cpu_read(dispatch_buf_cursor);
}

/**
 * scx_bpf_dispatch - Dispatch a task to a dq
 * @p: task_struct to dispatch
 * @dq_id: dq to dispatch to
 *
 * Dispatch @p to the dq identified by @dq_id. It is safe to call this function
 * spuriously. Can only be called from ops->dispatch().
 *
 * Returns 0 on success, -errno on failure. None of the failure conditions
 * are recoverable and scx_ops_error() is implicitly triggered. The caller
 * can safely ignore the return value.
 */
__used noinline s32 scx_bpf_dispatch(struct task_struct *p, s64 dq_id)
{
	int idx, ret;

	lockdep_assert_irqs_disabled();

	if (unlikely(!p)) {
		scx_ops_error("called with NULL task");
		return -EINVAL;
	}

	idx = __this_cpu_read(dispatch_buf_cursor);
	if (unlikely(idx >= dispatch_max_batch)) {
		scx_ops_error("dispatch buffer overflow");
		return -EOVERFLOW;
	}

	ret = extl_task_dispatched(p);
	if (unlikely(ret < 0))
		return ret;

	this_cpu_ptr(dispatch_buf)[idx] = (struct dispatch_buf_ent){
		.task = p,
		.qseq = atomic64_read(&p->scx.ops_state) & SCX_OPSS_QSEQ_MASK,
		.dq_id = dq_id,
	};
	__this_cpu_inc(dispatch_buf_cursor);

	return 0;
}

/**
 * scx_bpf_consume - Transfer a task from a dq to the current CPU's local dq
 * @dq_id: dq to consume
 *
 * Consume a task from the dq identified by @dq_id and transfer it to the
 * current CPU's local dq for execution. Can only be called from ops->consume().
 *
 * Returns %true if a task has been consumed, %false if there isn't any task to
 * consume.
 */
static __used noinline bool scx_bpf_consume(s64 dq_id)
{
	struct consume_ctx *cctx = this_cpu_ptr(&consume_ctx);
	struct scx_dispatch_q *dq;

	dq = find_non_local_dq(dq_id);
	if (unlikely(!dq)) {
		scx_ops_error("invalid dq_id 0x%016llx", dq_id);
		return false;
	}

	return consume_dispatch_q(cctx->rq, cctx->rf, dq);
}

BTF_SET8_START(scx_kfunc_ids_consume)
BTF_ID_FLAGS(func, scx_bpf_consume)
BTF_SET8_END(scx_kfunc_ids_consume)

static const struct btf_kfunc_id_set scx_kfunc_set_consume = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_consume,
};

BTF_SET8_START(scx_kfunc_ids_dispatch)
BTF_ID_FLAGS(func, scx_bpf_dispatch_nr_slots)
BTF_ID_FLAGS(func, scx_bpf_dispatch)
BTF_SET8_END(scx_kfunc_ids_dispatch)

static const struct btf_kfunc_id_set scx_kfunc_set_dispatch = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_dispatch,
};

/**
 * scx_bpf_kick_cpu - Trigger reschedule on a CPU
 * @cpu: cpu to kick
 * @flags: SCX_KICK_* flags
 *
 * Kick @cpu into rescheduling. This can be used to wake up an idle CPU or
 * trigger rescheduling on a busy CPU. This can be called from any online
 * scx_ops operation and the actual kicking is performed asynchronously through
 * an irq work.
 */
static __used noinline void scx_bpf_kick_cpu(s32 cpu, u64 flags)
{
	if (!ops_cpu_valid(cpu)) {
		scx_ops_error("invalid cpu %d", cpu);
		return;
	}
#ifdef CONFIG_SMP
	{
		struct rq *rq;

		preempt_disable();
		rq = this_rq();

		/*
		 * Actual kicking is bounced to kick_cpus_irq_workfn() to avoid
		 * nesting rq locks. We can probably be smarter and avoid
		 * bouncing if called from ops which don't hold a rq lock.
		 */
		cpumask_set_cpu(cpu, rq->scx.cpus_to_kick);
		if (flags & SCX_KICK_PREEMPT)
			cpumask_set_cpu(cpu, rq->scx.cpus_to_preempt);
		if (flags & SCX_KICK_WAIT)
			cpumask_set_cpu(cpu, rq->scx.cpus_to_await);

		irq_work_queue(&rq->scx.kick_cpus_irq_work);
		preempt_enable();
	}
#endif
}

/**
 * scx_bpf_dq_nr_queued - Return the number of queued tasks
 * @dq_id: id of the dq
 *
 * Return the number of tasks in the dq matching @dq_id. If not found, -%ENOENT
 * is returned. Can be called from any non-sleepable online scx_ops operations.
 */
static __used noinline s32 scx_bpf_dq_nr_queued(s64 dq_id)
{
	struct scx_dispatch_q *dq;

	lockdep_assert(rcu_read_lock_any_held());

	if (dq_id == SCX_DQ_LOCAL) {
		return this_rq()->scx.local_dq.nr;
	} else if ((dq_id & SCX_DQ_LOCAL_ON) == SCX_DQ_LOCAL_ON) {
		s32 cpu = dq_id & SCX_DQ_LOCAL_CPU_MASK;

		if (ops_cpu_valid(cpu))
			return cpu_rq(cpu)->scx.local_dq.nr;
	} else {
		dq = find_non_local_dq(dq_id);
		if (dq)
			return dq->nr;
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
 * Unavailable if scx_ops->update_idle() is implemented and
 * SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
static __used noinline bool scx_bpf_test_and_clear_cpu_idle(s32 cpu)
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
 * idle cpu number on success. -EBUSY if no matching cpu was found.
 *
 * Unavailable if scx_ops->update_idle() is implemented and
 * SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
static __used noinline
s32 scx_bpf_pick_idle_cpu(const struct cpumask *cpus_allowed)
{
	if (!static_branch_likely(&scx_builtin_idle_enabled)) {
		scx_ops_error("built-in idle tracking is disabled");
		return -EBUSY;
	}

	return scx_pick_idle_cpu(cpus_allowed);
}

/**
 * scx_bpf_has_idle_cpus - Are some CPUs idle?
 *
 * Unavailable if scx_ops->update_idle() is implemented and
 * SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
static __used noinline bool scx_bpf_has_idle_cpus(void)
{
	if (!static_branch_likely(&scx_builtin_idle_enabled)) {
		scx_ops_error("built-in idle tracking is disabled");
		return false;
	}
#ifdef CONFIG_SMP
	return has_idle_cpus;
#else
	return false;
#endif
}

BTF_SET8_START(scx_kfunc_ids_online)
BTF_ID_FLAGS(func, scx_bpf_kick_cpu)
BTF_ID_FLAGS(func, scx_bpf_dq_nr_queued)
BTF_ID_FLAGS(func, scx_bpf_test_and_clear_cpu_idle)
BTF_ID_FLAGS(func, scx_bpf_pick_idle_cpu)
BTF_ID_FLAGS(func, scx_bpf_has_idle_cpus)
BTF_SET8_END(scx_kfunc_ids_online)

static const struct btf_kfunc_id_set scx_kfunc_set_online = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_online,
};

/**
 * scx_bpf_destroy_dq - Destroy a dq
 * @dq_id: dq to destroy
 *
 * Destroy the dq identified by @dq_id. Only dqs created with
 * scx_bpf_create_dq() can be destroyed. Returns -%ENOENT if the dq can't be
 * found. The caller must ensure that the dq is empty and no further tasks are
 * dispatched to it. Can be called from any online scx_ops operations.
 */
static __used noinline s32 scx_bpf_destroy_dq(s64 dq_id)
{
	return destroy_dq(dq_id);
}

/**
 * scx_bpf_task_running - Is task currently running?
 * @p: task of interest
 */
static __used noinline bool scx_bpf_task_running(const struct task_struct *p)
{
	return task_rq(p)->curr == p;
}

/**
 * scx_bpf_task_cpu - CPU a task is currently associated with
 * @p: task of interest
 */
static __used noinline s32 scx_bpf_task_cpu(const struct task_struct *p)
{
	return task_cpu(p);
}

/**
 * scx_bpf_task_cpumask - CPUs that a task is allowed to run on
 * @p: task of interest
 */
static __used noinline
const struct cpumask *scx_bpf_task_cpumask(const struct task_struct *p)
{
	return p->cpus_ptr;
}

/**
 * scx_bpf_task_cgroup - cgroup that a task belongs to
 * @p: task of interest
 *
 * Return @p's cgroup when seen from scheduler which can be different from the
 * cgroup pointed to by bpf_get_current_cgroup_id() depending on CPU controller
 * enable state.
 */
static __used noinline
struct cgroup *scx_bpf_task_cgroup(const struct task_struct *p)
{
	return tg_cgrp(p->sched_task_group);
}

/**
 * scx_bpf_find_task_by_pid - Find task_struct matching the specified PID
 * @pid: pid of interest
 */
static __used noinline struct task_struct *scx_bpf_find_task_by_pid(s32 pid)
{
	return find_task_by_pid_ns(pid, &init_pid_ns);
}

/**
 * scx_bpf_reenqueue_local - Iterate over all of the tasks currently enqueued
 * on the LOCAL_DQ of the caller's CPU, and re-enqueue them in the BPF
 * scheduler.
 * XXX: Restrict this kfunc to only be invokable from the ->cpu_release()
 * callback.
 */
static __used noinline void scx_bpf_reenqueue_local(void)
{
	u32 nr_enqueued, i;
	struct rq *rq;
	struct scx_rq *scx_rq;

	rq = cpu_rq(smp_processor_id());
	lockdep_assert_rq_held(rq);
	scx_rq = &rq->scx;

	/*
	 * Get the number of tasks on the local dq before iterating over it to
	 * pull off tasks. The enqueue callback below can signal that it wants
	 * the task to stay on the local dq, and we want to prevent the BPF
	 * scheduler from causing us to loop indefinitely.
	 */
	nr_enqueued = scx_rq->local_dq.nr;
	for (i = 0; i < nr_enqueued; i++) {
		struct task_struct *p;

		p = pick_task_scx(rq);
		WARN_ON_ONCE(atomic64_read(&p->scx.ops_state) != SCX_OPSS_NONE);
		WARN_ON_ONCE(!(p->scx.flags & SCX_TASK_QUEUED));
		WARN_ON_ONCE(p->scx.holding_cpu != -1);
		dispatch_dequeue(scx_rq, p);
		do_enqueue_task(rq, p, SCX_ENQ_REENQ, -1);
	}
}

BTF_SET8_START(scx_kfunc_ids_any)
BTF_ID_FLAGS(func, scx_bpf_destroy_dq)
BTF_ID_FLAGS(func, scx_bpf_task_running)
BTF_ID_FLAGS(func, scx_bpf_task_cpu)
BTF_ID_FLAGS(func, scx_bpf_task_cpumask)
BTF_ID_FLAGS(func, scx_bpf_task_cgroup)
BTF_ID_FLAGS(func, scx_bpf_find_task_by_pid, KF_RET_NULL)
BTF_ID_FLAGS(func, scx_bpf_reenqueue_local)
BTF_SET8_END(scx_kfunc_ids_any)

static const struct btf_kfunc_id_set scx_kfunc_set_any = {
	.owner			= THIS_MODULE,
	.set			= &scx_kfunc_ids_any,
};

/********************************************************************************
 * Temporary BPF helpers to be replaced by generic non-scx-specific BPF helpers
 */

/**
 * XXX: This is unsafe
 *
 * Untyped version of the above helper to be used in cases where the
 * verifier cannot tell you have a cpumask.
 */
static noinline __used
s32 scx_bpf_pick_idle_cpu_untyped(unsigned long cpus_allowed)
{
	return scx_bpf_pick_idle_cpu((const struct cpumask *)cpus_allowed);
}

/**
 * scx_bpf_has_idle_cpus_among - Are some of the specified CPUs idle?
 *
 * Unavailable if scx_ops->update_idle() is implemented and
 * SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
static __used noinline
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

/**
 * XXX: This is unsafe
 *
 * Untyped version of the above helper to be used in cases where the
 * verifier cannot tell you have a cpumask.
 */
static noinline __used
s32 scx_bpf_has_idle_cpus_among_untyped(unsigned long cpus_allowed)
{
	return scx_bpf_has_idle_cpus_among((const struct cpumask *)cpus_allowed);
}

/*
 * XXX - This should be replaced with generic cpumask helpers.
 */
static __used noinline
s32 scx_bpf_cpumask_test_cpu(s32 cpu, const struct cpumask *cpumask)
{
	return cpumask_test_cpu(cpu, cpumask);
}

/**
 * scx_bpf_cpumask_first - Pick first set cpu in a cpumask
 * @cpus_allowed: Allowed cpumask
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
static noinline __used
s32 scx_bpf_cpumask_first(const struct cpumask *cpus_allowed)
{
	return cpumask_first(cpus_allowed);
}

/**
 * XXX: This is unsafe
 *
 * Untyped version of the above helper to be used in cases where the
 * verifier cannot tell you have a cpumask.
 */
static noinline __used
s32 scx_bpf_cpumask_first_untyped(unsigned long cpus_allowed)
{
	return cpumask_first((const struct cpumask *)cpus_allowed);
}

static __used bool scx_bpf_cpumask_intersects(const struct cpumask *src1p,
					      const struct cpumask *src2p)
{
	return cpumask_intersects(src1p, src2p);
}

BTF_SET8_START(scx_kfunc_ids_xxx)
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
					     &scx_kfunc_set_select_cpu)) ||
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
		pr_err("sched_ext: failed to register kfunc sets (%d)", ret);
		return ret;
	}

	return 0;
}
__initcall(register_ext_kfuncs);
