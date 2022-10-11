/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf_verifier.h>

#ifdef CONFIG_SCHED_CLASS_EXT_LIB

struct extl_task_group {
	/* flex array member can't be the only one */
	u64			__dummy__;
	char			data[] __aligned(__alignof__(u64));
};

DECLARE_STATIC_KEY_FALSE(extl_enabled);

int extl_init(void);
void extl_exit(void);

int __extl_prep_enable_pre(struct task_struct *p, struct task_group *tg);
int __extl_prep_enable_post(struct task_struct *p, struct task_group *tg);
void __extl_enable_pre(struct task_struct *p);
void __extl_enable_post(struct task_struct *p);
void __extl_cancel_enable(struct task_struct *p, struct task_group *tg);
void __extl_disable(struct task_struct *p);

void __extl_enqueue_pre(struct task_struct *p);
void __extl_enqueue_post(struct task_struct *p, s64 verdict);
void __extl_dequeue_pre(struct task_struct *p);
void __extl_dequeue_post(struct task_struct *p, u64 deq_flags);
void __extl_dispatch_pre(void);
void __extl_dispatch_post(void);
int __extl_task_dispatched(struct task_struct *p);

static inline int extl_prep_enable_pre(struct task_struct *p,
				       struct task_group *tg)
{
	if (static_branch_likely(&extl_enabled))
		return __extl_prep_enable_pre(p, tg);
	else
		return 0;
}

static inline void extl_enable_pre(struct task_struct *p)
{
	if (static_branch_likely(&extl_enabled))
		__extl_enable_pre(p);
}

static inline void extl_enable_post(struct task_struct *p)
{
	if (static_branch_likely(&extl_enabled))
		__extl_enable_post(p);
}

static inline void extl_cancel_enable(struct task_struct *p,
				      struct task_group *tg)
{
	if (static_branch_likely(&extl_enabled))
		__extl_cancel_enable(p, tg);
}

static inline void extl_disable(struct task_struct *p)
{
	if (static_branch_likely(&extl_enabled))
		__extl_disable(p);
}

static inline void extl_enqueue_pre(struct task_struct *p)
{
	if (static_branch_likely(&extl_enabled))
		__extl_enqueue_pre(p);
}

static inline void extl_enqueue_post(struct task_struct *p, s64 verdict)
{
	if (static_branch_likely(&extl_enabled))
		__extl_enqueue_post(p, verdict);
}

static inline void extl_dequeue_pre(struct task_struct *p)
{
	if (static_branch_likely(&extl_enabled))
		__extl_dequeue_pre(p);
}

static inline void extl_dequeue_post(struct task_struct *p, u64 deq_flags)
{
	if (static_branch_likely(&extl_enabled))
		__extl_dequeue_post(p, deq_flags);
}

static inline void extl_dispatch_pre(void)
{
	if (static_branch_likely(&extl_enabled))
		__extl_dispatch_pre();
}

static inline void extl_dispatch_post(void)
{
	if (static_branch_likely(&extl_enabled))
		__extl_dispatch_post();
}

static inline int extl_task_dispatched(struct task_struct *p)
{
	if (static_branch_likely(&extl_enabled))
		return __extl_task_dispatched(p);
	else
		return 0;
}

int bpf_sched_extl_btf_struct_access(struct bpf_verifier_log *log,
				     const struct btf *btf,
				     const struct btf_type *t, int off,
				     int size, enum bpf_access_type atype,
				     u32 *next_btf_id);
bool bpf_sched_extl_check_kfunc_call(u32 kfunc_btf_id, struct module *owner);
int bpf_sched_extl_init(struct btf *btf);

#else	/* CONFIG_SCHED_CLASS_EXT_LIB */

static inline void extl_init(void) {}
static inline void extl_exit(void) {}
static inline int extl_prep_enable(struct task_struct *p, struct task_group *tg) { return 0; }
static inline int extl_prep_enable_pre(struct task_struct *p, struct task_group *tg) { return 0; }
static inline void extl_enable_pre(struct task_struct *p) {}
static inline void extl_enable_post(struct task_struct *p) {}
static inline void extl_cancel_enable(struct task_struct *p, struct task_group *tg) {}
static inline void extl_disable(struct task_struct *p) {}
static inline void extl_enqueue_pre(struct task_struct *p) {}
static inline void extl_enqueue_post(struct task_struct *p, s64 verdict) {}
static inline void extl_dequeue_pre(struct task_struct *p) {}
static inline void extl_dequeue_post(struct task_struct *p, u64 deq_flags) {}
static inline void extl_dispatch_pre(void) {}
static inline void extl_dispatch_post(void) {}
static inline int extl_task_dispatched(struct task_struct *p) { return 0; }
static inline int bpf_sched_extl_btf_struct_access(struct bpf_verifier_log *log,
					const struct btf *btf,
					const struct btf_type *t, int off,
					int size, enum bpf_access_type atype,
					u32 *next_btf_id)
{ return -EAGAIN; }
static inline bool bpf_sched_extl_check_kfunc_call(u32 kfunc_btf_id,
						   struct module *owner)
{ return false; }
static inline int extl_setup(void) { return 0; }
static inline int bpf_sched_extl_init(struct btf *btf) { return 0; }

#endif	/* CONFIG_SCHED_CLASS_EXT_LIB */
