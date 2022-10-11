/* SPDX-License-Identifier: GPL-2.0 */
enum scx_wake_flags {
	/* expose select WF_* flags as enums */
	SCX_WAKE_EXEC		= WF_EXEC,
	SCX_WAKE_FORK		= WF_FORK,
	SCX_WAKE_TTWU		= WF_TTWU,
	SCX_WAKE_SYNC		= WF_SYNC,
};

enum scx_enq_flags {
	/* expose select ENQUEUE_* flags as enums */
	SCX_ENQ_WAKEUP		= ENQUEUE_WAKEUP,
	SCX_ENQ_HEAD		= ENQUEUE_HEAD,

	/* high 32bits are ext specific flags */

	/*
	 * The task being enqueued was previously enqueued on the current CPU's
	 * %SCX_DQ_LOCAL, but was removed from it in a call to the
	 * bpf_scx_reenqueue_local() kfunc. If bpf_scx_reenqueue_local() was
	 * invoked in a ->cpu_release() callback, and the task is again
	 * dispatched back to %SCX_LOCAL_DQ by this current ->enqueue(), the
	 * task will not be scheduled on the CPU until at least the next invocation
	 * of the ->cpu_acquire() callback.
	 */
	SCX_ENQ_REENQ		= 1LLU << 31,

	/*
	 * The task being enqueued is the only task available for the cpu. By
	 * default, ext core keeps executing such tasks but when
	 * %SCX_OPS_ENQ_LAST is specified, they're ->enqueue()'d with
	 * %SCX_ENQ_LAST flag.
	 *
	 * If the bpf scheduler wants to continue executing the task,
	 * ->enqueue() should dispatch the task to %SCX_DQ_LOCAL immediately. If
	 * the task gets queued on a different dq or the bpf side, the bpf
	 * scheduler is responsible for triggering a follow-up scheduling event.
	 * Otherwise, Execution may stall.
	 */
	SCX_ENQ_LAST	= 1LLU << 32,

	SCX_ENQ_WAKE_IDLE	= 1LLU << 33,	// XXX - actual wakeup not implemented yet

	/* internal */
	SCX_ENQ_CLEAR_OPSS	= 1LLU << 40,
	SCX_ENQ_LOCAL_PREEMPT	= 1LLU << 41,	/* clear local cur's slice and resched */
};

enum scx_deq_flags {
	/* expose select DEQUEUE_* flags as enums */
	SCX_DEQ_SLEEP		= DEQUEUE_SLEEP,
};

enum scx_tg_flags {
	SCX_TG_ONLINE		= 1U << 0,
	SCX_TG_INITED		= 1U << 1,
};

enum scx_kick_flags {
	SCX_KICK_PREEMPT	= 1LLU << 0,	/* force scheduling on the CPU */
	SCX_KICK_WAIT		= 1LLU << 1,	/* wait for the CPU to be rescheduled */
};

#ifdef CONFIG_SCHED_CLASS_EXT

struct sched_enq_and_set_ctx {
	struct task_struct	*p;
	int			queue_flags;
	bool			queued;
	bool			running;
};

void sched_deq_and_put_task(struct task_struct *p, int queue_flags,
			    struct sched_enq_and_set_ctx *ctx);
void sched_enq_and_set_task(struct sched_enq_and_set_ctx *ctx);

extern const struct sched_class ext_sched_class;
extern const struct bpf_verifier_ops bpf_sched_ext_verifier_ops;

#ifdef CONFIG_SCHED_CLASS_EXT_DEFAULT
DECLARE_STATIC_KEY_TRUE(__sched_ext_enabled);
#define sched_ext_enabled()	static_branch_likely(&__sched_ext_enabled)
DECLARE_STATIC_KEY_FALSE(__sched_fair_enabled);
#define sched_fair_enabled()	static_branch_unlikely(&__sched_fair_enabled)
#else
DECLARE_STATIC_KEY_FALSE(__sched_ext_enabled);
#define sched_ext_enabled()	static_branch_unlikely(&__sched_ext_enabled)
DECLARE_STATIC_KEY_TRUE(__sched_fair_enabled);
#define sched_fair_enabled()	static_branch_likely(&__sched_fair_enabled)
#endif

DECLARE_STATIC_KEY_FALSE(scx_ops_cpu_preempt);

__printf(1, 2) void scx_ops_error(const char *fmt, ...);
int scx_bpf_dispatch(struct task_struct *p, s64 dq_id);

void scx_pre_fork(struct task_struct *p);
int scx_fork(struct task_struct *p);
void scx_post_fork(struct task_struct *p);
void scx_cancel_fork(struct task_struct *p);

int balance_scx(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
bool can_stop_tick_scx(struct rq *rq);
void cgroup_move_scx(struct task_struct *p);
void __scx_notify_pick_next_task(struct rq *rq,
				 const struct task_struct *p,
				 const struct sched_class *active);
static inline void scx_notify_pick_next_task(struct rq *rq,
					     const struct task_struct *p,
					     const struct sched_class *active)
{
	if (!sched_ext_enabled())
		return;

#ifdef CONFIG_SMP
	/*
	 * Pairs with the smp_load_acquire() issued by a CPU in
	 * kick_cpus_irq_workfn() who is waiting for this CPU to perform a
	 * resched.
	 */
	smp_store_release(&rq->scx.generation, rq->scx.generation + 1);
#endif

	if (!static_branch_unlikely(&scx_ops_cpu_preempt))
		return;

	__scx_notify_pick_next_task(rq, p, active);
}
void init_sched_ext_class(void);

static inline const struct sched_class *next_active_class(const struct sched_class *class)
{
	class++;
	if (!sched_fair_enabled() && class == &fair_sched_class)
		class++;
	if (!sched_ext_enabled() && class == &ext_sched_class)
		class++;
	return class;
}

#define for_active_class_range(class, _from, _to)				\
	for (class = (_from); class != (_to); class = next_active_class(class))

#define for_each_active_class(class)						\
	for_active_class_range(class, __sched_class_highest, __sched_class_lowest)

/*
 * ext requires a balance() call before every pick_next_task() call including
 * when waking up from idle.
 */
#define for_balance_class_range(class, prev_class, end_class)			\
	for_active_class_range(class, (prev_class) > &ext_sched_class ?		\
			       &ext_sched_class : (prev_class), (end_class))

extern const struct sched_class *__normal_sched_class;

static inline const struct sched_class *normal_sched_class(void)
{
	return __normal_sched_class;
}

#else	/* CONFIG_SCHED_CLASS_EXT */

#define sched_ext_enabled()	false
#define sched_fair_enabled()	true

static inline void scx_pre_fork(struct task_struct *p) {}
static inline int scx_fork(struct task_struct *p) { return 0; }
static inline void scx_post_fork(struct task_struct *p) {}
static inline void scx_cancel_fork(struct task_struct *p) {}
static inline int balance_scx(struct rq *rq, struct task_struct *prev,
			      struct rq_flags *rf) { return 0; }
static inline bool can_stop_tick_scx(struct rq *rq) { return true; }
static inline void cgroup_move_scx(struct task_struct *p) {}
static inline void scx_notify_pick_next_task(struct rq *rq,
					     const struct task_struct *p,
					     const struct sched_class *active) {}
static inline void init_sched_ext_class(void) {}

#define for_each_active_class		for_each_class
#define for_balance_class_range		for_class_range

static inline const struct sched_class *normal_sched_class(void)
{
	return &fair_sched_class;
}

#endif	/* CONFIG_SCHED_CLASS_EXT */

#ifndef CONFIG_SMP
static inline void balance_scx_on_up(struct rq *rq, struct task_struct *prev,
				     struct rq_flags *rf)
{
	balance_scx(rq, prev, rf);
}
#endif

#if defined(CONFIG_SCHED_CLASS_EXT) && defined(CONFIG_SMP)
void __scx_update_idle(struct rq *rq, bool idle);

static inline void scx_update_idle(struct rq *rq, bool idle)
{
	if (sched_ext_enabled())
		__scx_update_idle(rq, idle);
}
#else
static inline void scx_update_idle(struct rq *rq, bool idle) {}
#endif

#ifdef CONFIG_CGROUP_SCHED
#ifdef CONFIG_EXT_GROUP_SCHED
int scx_tg_online(struct task_group *tg);
void scx_tg_offline(struct task_group *tg);
int scx_can_attach(struct task_group *tg, struct task_struct *p);
void scx_cancel_attach(struct task_group *tg, struct task_struct *p);
void scx_group_set_weight(struct task_group *tg, unsigned long cgrp_weight);
#else	/* CONFIG_EXT_GROUP_SCHED */
static inline int scx_tg_online(struct task_group *tg) { return 0; }
static inline void scx_tg_offline(struct task_group *tg) {}
static inline int scx_can_attach(struct task_group *tg, struct task_struct *p) { return 0; }
static inline void scx_cancel_attach(struct task_group *tg, struct task_struct *p) {}
static inline void scx_group_set_weight(struct task_group *tg, unsigned long cgrp_weight) {}
#endif	/* CONFIG_EXT_GROUP_SCHED */
#endif	/* CONFIG_CGROUP_SCHED */
