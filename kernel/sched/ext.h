/* SPDX-License-Identifier: GPL-2.0 */

#ifdef CONFIG_SCHED_CLASS_EXT
#error "NOT IMPLEMENTED YET"
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

#ifdef CONFIG_CGROUP_SCHED
#ifdef CONFIG_EXT_GROUP_SCHED
#error "NOT IMPLEMENTED YET"
#else	/* CONFIG_EXT_GROUP_SCHED */
static inline int scx_tg_online(struct task_group *tg) { return 0; }
static inline void scx_tg_offline(struct task_group *tg) {}
static inline int scx_can_attach(struct task_group *tg, struct task_struct *p) { return 0; }
static inline void scx_cancel_attach(struct task_group *tg, struct task_struct *p) {}
static inline void scx_group_set_weight(struct task_group *tg, unsigned long cgrp_weight) {}
#endif	/* CONFIG_EXT_GROUP_SCHED */
#endif	/* CONFIG_CGROUP_SCHED */
