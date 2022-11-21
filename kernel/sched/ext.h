/* SPDX-License-Identifier: GPL-2.0 */

#ifdef CONFIG_SCHED_CLASS_EXT
#error "NOT IMPLEMENTED YET"
#else	/* CONFIG_SCHED_CLASS_EXT */

#define scx_enabled()		false

static inline void scx_pre_fork(struct task_struct *p) {}
static inline int scx_fork(struct task_struct *p) { return 0; }
static inline void scx_post_fork(struct task_struct *p) {}
static inline void scx_cancel_fork(struct task_struct *p) {}
static inline int balance_scx(struct rq *rq, struct task_struct *prev,
			      struct rq_flags *rf) { return 0; }
static inline bool scx_can_stop_tick(struct rq *rq) { return true; }
static inline void init_sched_ext_class(void) {}

#define for_each_active_class		for_each_class
#define for_balance_class_range		for_class_range

#endif	/* CONFIG_SCHED_CLASS_EXT */
