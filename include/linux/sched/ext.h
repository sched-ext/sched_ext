/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_EXT_H
#define _LINUX_SCHED_EXT_H

#ifdef CONFIG_SCHED_CLASS_EXT

#include <linux/rhashtable.h>
#include <linux/llist.h>

struct cgroup;

enum scx_consts {
	SCX_OPS_NAME_LEN	= 128,
	SCX_OPS_EXIT_MSG_MAX	= 180,
	SCX_OPS_EXIT_BT_MAX	= 64,

	SCX_SLICE_DFL		= (20 * NSEC_PER_MSEC),
	SCX_SLICE_INF		= U64_MAX,	/* infinite, implies nohz */
};

/*
 * DQ IDs are 64bit of the format:
 *
 *   Bits: [63 .. 56] [55 ..  0]
 *         [SBPPRRRR] [   ID   ]
 *
 *    S: Sign, every valid ID is a positive number
 *    B: 1 for IDs for built-in DQs, 0 for ops-created user DQs
 *    P: 0, SCX_DQ_PREEMPT / HEAD or TAIL
 *    R: Reserved, must be zero
 *   ID: 56 bit ID
 *
 * Built-in IDs:
 *
 *   Bits: [55] [54..32] [31 ..  0]
 *         [ L] [   R  ] [    V   ]
 *
 *    L: 1 for LOCAL_ON DQ IDs, 0 for others
 *    R: Reserved, must be zero
 *    V: For LOCAL_ON DQ IDs, a CPU number. For others, a pre-defined value.
 */
enum scx_dq_id_flags {
	SCX_DQ_FLAGS_MASK	= 0x7fLL << 56,
	SCX_DQ_ID_MASK		= S64_MAX & ~SCX_DQ_FLAGS_MASK,

	SCX_DQ_FLAG_BUILTIN	= 1LL << 62,
	SCX_DQ_FLAG_LOCAL_ON	= 1LL << 55,

	SCX_DQ_NONE		= SCX_DQ_FLAG_BUILTIN | 0,
	SCX_DQ_GLOBAL		= SCX_DQ_FLAG_BUILTIN | 1,
	SCX_DQ_LOCAL		= SCX_DQ_FLAG_BUILTIN | 2,
	SCX_DQ_LOCAL_ON		= SCX_DQ_FLAG_BUILTIN | SCX_DQ_FLAG_LOCAL_ON,
	SCX_DQ_LOCAL_CPU_MASK	= 0xffffffffLL,

	/*
	 * Options that can be ORd to IDs.
	 */

	/*
	 * Indicate queueing position and the need for preemption using bits 60
	 * and 61. PREEMPT can only be used on local dq's. Can only be OR'd to a
	 * valid DQ ID in the return value of ->enqueue() and @dq_id of
	 * scx_bpf_dispatch(). If not specified, follow @enq_flags on
	 * ->enqueue() and queue at the tail on scx_bpf_dispatch().
	 */
	__SCX_DQ_POS_MASK	= 3LL << 60,
	SCX_DQ_HEAD		= 1LL << 60,
	SCX_DQ_TAIL		= 2LL << 60,
	SCX_DQ_PREEMPT		= 3LL << 60,	/* queue at head and preempt */
};

/* exit reason */
enum scx_ops_exit_type {
	SCX_OPS_EXIT_NONE,
	SCX_OPS_EXIT_DONE,

	SCX_OPS_EXIT_UNREG,	/* bpf unregistration */
	SCX_OPS_EXIT_ERROR,	/* runtime error, error msg contains details */
	SCX_OPS_EXIT_SYSRQ,	/* requested by 'S' sysrq */
};

struct scx_ops_exit_info {
	enum scx_ops_exit_type type;
	u32			bt_len;
	unsigned long		bt[SCX_OPS_EXIT_BT_MAX];
	char			msg[SCX_OPS_EXIT_MSG_MAX];
};

/* sched_ext_ops->flags */
enum scx_ops_flags {
	/*
	 * Keep built-in idle tracking even if ops->update_idle() is
	 * implemented.
	 */
	SCX_OPS_KEEP_BUILTIN_IDLE = 1LLU << 0,

	/*
	 * By default, if there are no other task to run, ext core keeps running
	 * the current task even after its slice expires. If this flag is
	 * specified, such tasks are passed to ->enqueue() with %SCX_ENQ_LAST.
	 * See the comment above the flag for more info.
	 */
	SCX_OPS_ENQ_LAST	= 1LLU << 1,

	/*
	 * An exiting task may schedule after PF_EXITING is set. In such cases,
	 * scx_bpf_find_task_by_pid() may not be able to find the task and if
	 * the bpf scheduler depends on pid lookup for dispatching, the task
	 * will be lost leading to various issues including and RCU grace period
	 * stalls.
	 *
	 * To mask this problem, by default, unhashed tasks are automatically
	 * dispatched to the local dq on enqueue. If a bpf scheduler doesn't
	 * depend on pid lookups and wants to handle these tasks directly, the
	 * following flag can be used.
	 */
	SCX_OPS_ENQ_EXITING	= 1LLU << 2,

	/*
	 * CPU cgroup knob enable flags
	 */
	SCX_OPS_CGROUP_KNOB_WEIGHT = 1LLU << 16,	/* cpu.weight */

	SCX_OPS_ALL_FLAGS	= SCX_OPS_KEEP_BUILTIN_IDLE |
				  SCX_OPS_ENQ_LAST |
				  SCX_OPS_ENQ_EXITING |
				  SCX_OPS_CGROUP_KNOB_WEIGHT,
};

/* argument container for ops->enable() and friends */
struct scx_enable_args {
	/* the cgroup the task is joining */
	struct cgroup		*cgroup;
};

/* argument container for ops->cgroup_init() */
struct scx_cgroup_init_args {
	/* the weight of the cgroup [1..10000] */
	u32			weight;
};

enum scx_cpu_preempt_reason {
	/* Next task is being scheduled by &sched_class_rt. */
        SCX_CPU_PREEMPT_RT,
	/* Next task is being scheduled by &sched_class_dl. */
        SCX_CPU_PREEMPT_DL,
	/* Next task is being scheduled by &sched_class_stop. */
        SCX_CPU_PREEMPT_STOP,
	/* Unknown reason for SCX being preempted. */
        SCX_CPU_PREEMPT_UNKNOWN,
};

/*
 * Argument container for ops->cpu_acquire(). Currently empty, but may be
 * expanded in the future.
 */
struct scx_cpu_acquire_args {};

/* argument container for ops->cpu_release() */
struct scx_cpu_release_args {
	/* The reason the CPU was preempted. */
	enum scx_cpu_preempt_reason reason;

	/* The task that's going to be scheduled on the CPU. */
	const struct task_struct *task;
};

/**
 * struct sched_ext_ops - Operation table for BPF scheduler implementation
 *
 * By default, sched_ext behaves as a simple global FIFO scheduler. Userland can
 * implement an arbitrary scheduling policy by implementing and loading
 * operations in this table. See samples/sched_ext* for examples.
 */
struct sched_ext_ops {
	/**
	 * select_cpu - Pick the target CPU for a task which is being woken up
	 * @p: task being woken up
	 * @prev_cpu: the cpu @p was on before sleeping
	 * @wake_flags: SCX_WAKE_*
	 *
	 * Decision made here isn't final. @p may be moved to any CPU while it
	 * is getting dispatched for execution later. However, as @p is not on
	 * the rq at this point, getting the eventual execution CPU right here
	 * saves a small bit of overhead down the line.
	 *
	 * If an idle CPU is returned, the CPU is kicked and will try to
	 * dispatch. While an explicit custom mechanism can be added,
	 * select_cpu() serves as the default way to wake up idle CPUs.
	 */
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);

	/**
	 * enqueue - Enqueue a task on the bpf scheduler
	 * @p: task being enqueued
	 * @enq_flags: %SCX_ENQ_*
	 *
	 * @p is ready to run. Dispatch directly or enqueue on the bpf
	 * scheduler. Should return one of the following values:
	 *
	 * SCX_DQ_NONE   @p is queued on the bpf side, will be dispatched later
	 * SCX_DQ_LOCAL  Skip bpf scheduling, dispatch directly to LOCAL
	 * SCX_DQ_GLOBAL Skip bpf scheduling, dispatch directly to GLOBAL
	 * Custom dq_id  Skip bpf scheduling, dispatch directly to a custom dq
	 * -errno        Error
	 *
	 * If DQ_NONE is returned, the bpf scheduler owns @p and if it fails to
	 * dispatch @p, the task will stall.
	 */
	s64 (*enqueue)(struct task_struct *p, u64 enq_flags);

	/**
	 * dequeue - Remove a task from the bpf scheduler
	 * @p: task being dequeued
	 * @deq_flags: %SCX_DEQ_*
	 *
	 * Remove @p from the bpf scheduler. This is usually called to isolate
	 * the task while updating its scheduling properties (e.g. priority).
	 *
	 * The ext core keeps track of whether the bpf side owns a given task or
	 * not and can gracefully ignore spurious dispatches from bpf side,
	 * which makes it safe to not implement this method. However, depending
	 * on the scheduling logic, this can lead to confusing behaviors - e.g.
	 * scheduling position not being updated across a priority change.
	 */
	void (*dequeue)(struct task_struct *p, u64 deq_flags);

	/**
	 * dispatch - Dispatch tasks from the bpf scheduler into dq's
	 * @cpu: CPU to dispatch tasks for
	 * @prev: previous task being switched out
	 *
	 * Called when a CPU can't find a task to execute after ->consume(). The
	 * operation should dispatch one or more tasks from the bpf scheduler to
	 * the dq's using scx_bpf_dispatch(). The maximum number of tasks which
	 * can be dispatched in a single call is specified by the
	 * @dispatch_max_batch field of this struct.
	 *
	 * Return 0 for success, -errno for error.
	 */
	s32 (*dispatch)(s32 cpu, struct task_struct *prev);

	/**
	 * consume - Consume tasks from the dq's to the local dq for execution
	 * @cpu: CPU to consume tasks for
	 *
	 * Called when a CPU's local dq is empty. The operation should transfer
	 * one or more tasks from the dq's to the CPU's local dq using
	 * scx_bpf_consume(). If this function fails to fill the local dq,
	 * ->dispatch() will be called.
	 *
	 * This operation is unnecessary if the bpf scheduler always dispatches
	 * either to one of the local dq's or the global dq. If implemented,
	 * this operation is also responsible for consuming the global_dq.
	 */
	void (*consume)(s32 cpu);

	/**
	 * consume_final - Final consume call before going idle
	 * @cpu: CPU to consume tasks for
	 *
	 * After ->consume() and ->dispatch(), @cpu still doesn't have a task to
	 * execute and is about to go idle. This operation can be used to
	 * implement more aggressive consumption strategies. Otherwise
	 * equivalent to ->consume().
	 */
	void (*consume_final)(s32 cpu);

	/**
	 * runnable - A task is becoming runnable on its associated CPU
	 * @p: task becoming runnable
	 * @enq_flags: %SCX_ENQ_*
	 *
	 * This and the following three functions can be used to track a task's
	 * execution state transitions. A task becomes ->runnable() on a CPU,
	 * and then goes through one or more ->running() and ->stopping() pairs
	 * as it runs on the CPU, and eventually becomes ->quiescent() when it's
	 * done running on the CPU.
	 *
	 * @p is becoming runnable on the CPU because it's
	 *
	 * - waking up (%SCX_ENQ_WAKEUP)
	 * - being moved from another CPU
	 * - being restored after temporarily taken off the queue for an
	 *   attribute change.
	 *
	 * This and ->enqueue() are related but not coupled. This operation
	 * notifies @p's state transition and may not be followed by ->enqueue()
	 * e.g. when @p is being dispatched to a remote CPU. Likewise, a task
	 * may be ->enqueue()'d without being preceded by this operation e.g.
	 * after exhausting its slice.
	 */
	void (*runnable)(struct task_struct *p, u64 enq_flags);

	/**
	 * running - A task is starting to run on its associated CPU
	 * @p: task starting to run
	 *
	 * See ->runnable() for explanation on the task state notifiers.
	 */
	void (*running)(struct task_struct *p);

	/**
	 * stopping - A task is stopping execution
	 * @p: task stopping to run
	 * @runnable: is task @p still runnable?
	 *
	 * See ->runnable() for explanation on the task state notifiers. If
	 * !@runnable, ->quiescent() will be invoked after this operation
	 * returns.
	 */
	void (*stopping)(struct task_struct *p, bool runnable);

	/**
	 * quiescent - A task is becoming not runnable on its associated CPU
	 * @p: task becoming not runnable
	 * @deq_flags: %SCX_DEQ_*
	 *
	 * See ->runnable() for explanation on the task state notifiers.
	 *
	 * @p is becoming quiescent on the CPU because it's
	 *
	 * - sleeping (%SCX_DEQ_SLEEP)
	 * - being moved to another CPU
	 * - being temporarily taken off the queue for an attribute change
	 *   (%SCX_DEQ_SAVE)
	 *
	 * This and ->dequeue() are related but not coupled. This operation
	 * notifies @p's state transition and may not be preceded by ->dequeue()
	 * e.g. when @p is being dispatched to a remote CPU.
	 */
	void (*quiescent)(struct task_struct *p, u64 deq_flags);

	/**
	 * yield - Yield CPU
	 * @from: yielding task
	 * @to: optional yield target task
	 *
	 * If @to is NULL, @from is yielding the CPU to other runnable tasks.
	 * The bpf scheduler should ensure that other available tasks are
	 * dispatched before the yielding task. Return value is ignored in this
	 * case.
	 *
	 * If @to is not-NULL, @from wants to yield the CPU to @to. If the bpf
	 * scheduler can implement the request, return %true; otherwise, %false.
	 */
	bool (*yield)(struct task_struct *from, struct task_struct *to);

	/**
	 * set_cpumask - Set CPU affinity
	 * @p: task to set CPU affinity for
	 * @cpumask: cpumask of cpus that @p can run on
	 *
	 * Update @p's CPU affinity to @cpumask.
	 */
	void (*set_cpumask)(struct task_struct *p, struct cpumask *cpumask);

	/**
	 * update_idle - Update the idle state of a CPU
	 * @cpu: CPU to udpate the idle state for
	 * @idle: whether entering or exiting the idle state
	 *
	 * This operation is called when @rq's CPU goes or leaves the idle
	 * state. By default, implementing this operation disables the built-in
	 * idle CPU tracking and the following helpers become unavailable:
	 *
	 * - scx_bpf_select_cpu_dfl()
	 * - scx_bpf_test_and_clear_cpu_idle()
	 * - scx_bpf_pick_idle_cpu()
	 * - scx_bpf_any_idle_cpu()
	 *
	 * The user also must implement ->select_cpu() as the default
	 * implementation relies on scx_bpf_select_cpu_dfl().
	 *
	 * If you keep the built-in idle tracking, specify the
	 * %SCX_OPS_KEEP_BUILTIN_IDLE flag.
	 */
	void (*update_idle)(s32 cpu, bool idle);

	/**
	 * cpu_online - A CPU became online
	 * @cpu: CPU which just came up
	 *
	 * @cpu just came online. @cpu doesn't call ->enqueue() or consume tasks
	 * associated with other CPUs beforehand.
	 */
	void (*cpu_online)(s32 cpu);

	/**
	 * cpu_offline - A CPU is going offline
	 * @cpu: CPU which is going offline
	 *
	 * @cpu is going offline. @cpu doesn't call ->enqueue() or consume tasks
	 * associated with other CPUs afterwards.
	 */
	void (*cpu_offline)(s32 cpu);

	/**
	 * cpu_acquire - A CPU that was previously released from the BPF
	 * scheduler is now once again under its control.
	 * @cpu: The CPU being acquired by the BPF scheduler.
	 * @args: Acquire arguments, see the struct definition.
	 */
	void (*cpu_acquire)(s32 cpu, struct scx_cpu_acquire_args *args);

	/**
	 * cpu_release - The specified CPU is no longer under the control of
	 * the BPF scheduler. This could be because it was preempted by a
	 * higher priority sched_class, though there may be other reasons as
	 * well. The caller should consult the %SCX_CPU_ flags in the release
	 * args to determine the cause.
	 * @cpu: The CPU being released by the BPF scheduler.
	 * @args: Release arguments, see the struct definition.
	 */
	void (*cpu_release)(s32 cpu, struct scx_cpu_release_args *args);

	/**
	 * prep_enable - Prepare to enable bpf scheduling for a task
	 * @p: task to prepare bpf scheduling for
	 * @args: enable arguments, see the struct definition
	 *
	 * Either we're loading a bpf scheduler or a new task is being forked.
	 * Prepare bpf scheduling for @p. This operation may block and can be
	 * used for allocations.
	 *
	 * Return 0 for success, -errno for failure. An error return while
	 * loading will abort loading of the bpf scheduler. During a fork, will
	 * abort the specific fork.
	 */
	s32 (*prep_enable)(struct task_struct *p, struct scx_enable_args *args);

	/**
	 * enable - Enable bpf scheduling for a task
	 * @p: task to enable bpf scheduling for
	 * @args: enable arguments, see the struct definition
	 *
	 * Enable @p for bpf scheduling. @p is now in the cgroup specified for
	 * the preceding prep_enable() and will start running soon.
	 */
	void (*enable)(struct task_struct *p, struct scx_enable_args *args);

	/**
	 * cancel_enable - Cancel prep_enable()
	 * @p: task being canceled
	 * @args: enable arguments, see the struct definition
	 *
	 * @p was prep_enable()'d but failed before reaching enable(). Undo the
	 * preparation.
	 */
	void (*cancel_enable)(struct task_struct *p,
			      struct scx_enable_args *args);

	/**
	 * disable - Disable bpf scheduling for a task
	 * @p: task to disable bpf scheduling for
	 *
	 * @p is exiting or the bpf scheduler is being unloaded. Disable bpf
	 * scheduling for @p.
	 */
	void (*disable)(struct task_struct *p);

	/**
	 * cgroup_init - Initialize a cgroup
	 * @cgrp: cgroup being initialized
	 * @args: init arguments, see the struct definition
	 *
	 * Either the bpf scheduler is being loaded or @cgrp created, initialize
	 * @cgrp for sched_ext. This operation may block.
	 *
	 * Return 0 for success, -errno for failure. An error return while
	 * loading will abort loading of the bpf scheduler. During cgroup
	 * creation, it will abort the specific cgroup creation.
	 */
	s32 (*cgroup_init)(struct cgroup *cgrp,
			   struct scx_cgroup_init_args *args);

	/**
	 * cgroup_exit - Exit a cgroup
	 * @cgrp: cgroup being exited
	 *
	 * Either the bpf scheduler is being unloaded or @cgrp destroyed, exit
	 * @cgrp for sched_ext. This operation my block.
	 */
	void (*cgroup_exit)(struct cgroup *cgrp);

	/**
	 * cgroup_prep_move - Prepare a task to be moved to a different cgroup
	 * @p: task being moved
	 * @from: cgroup @p is being moved from
	 * @to: cgroup @p is being moved to
	 *
	 * Prepare @p for move from cgroup @from to @to. This operation may
	 * block and can be used for allocations.
	 *
	 * Return 0 for success, -errno for failure. An error return aborts the
	 * migration.
	 */
	s32 (*cgroup_prep_move)(struct task_struct *p,
				struct cgroup *from, struct cgroup *to);

	/**
	 * cgroup_move - Commit cgroup move
	 * @p: task being moved
	 * @from: cgroup @p is being moved from
	 * @to: cgroup @p is being moved to
	 *
	 * Commit the move. @p is dequeued during this operation.
	 */
	void (*cgroup_move)(struct task_struct *p,
			    struct cgroup *from, struct cgroup *to);

	/**
	 * cgroup_cancel_move - Cancel cgroup move
	 * @p: task whose cgroup move is being canceled
	 * @from: cgroup @p was being moved from
	 * @to: cgroup @p was being moved to
	 *
	 * @p was cgroup_prep_move()'d but failed before reaching cgroup_move().
	 * Undo the preparation.
	 */
	void (*cgroup_cancel_move)(struct task_struct *p,
				   struct cgroup *from, struct cgroup *to);

	/**
	 * cgroup_set_weight - A cgroup's weight is being changed
	 * @cgrp: cgroup whose weight is being updated
	 * @weight: new weight [1..10000]
	 *
	 * Update @tg's weight to @weight.
	 */
	void (*cgroup_set_weight)(struct cgroup *cgrp, u32 weight);

	/*
	 * All online ops must come before ->init().
	 */

	/**
	 * init - Initialize the bpf scheduler
	 */
	s32 (*init)(void);

	/**
	 * exit - Clean up after the bpf scheduler
	 * @info: Exit info
	 */
	void (*exit)(struct scx_ops_exit_info *info);

	/**
	 * dispatch_max_batch - Max nr of tasks that dispatch() can dispatch
	 */
	u32 dispatch_max_batch;

	/**
	 * flags - %SCX_OPS_* flags
	 */
	u64 flags;

	/**
	 * name - bpf scheduler's name
	 *
	 * Must be a non-zero valid bpf object name including only isalnum(),
	 * '_' and '.' chars. Shows up in kernel.sched_ext_ops sysctl while the
	 * bpf scheduler is enabled.
	 */
	char name[SCX_OPS_NAME_LEN];
};

struct scx_dispatch_q {
	raw_spinlock_t		lock;
	struct list_head	fifo;
	s64			id;
	u32			nr;
	struct rhash_head	hash_node;
	struct list_head	all_node;
	struct llist_node	free_node;
	struct rcu_head		rcu;
};

/* scx_entity->flags */
enum scx_ent_flags {
	SCX_TASK_QUEUED		= 1 << 0, /* on ext runqueue */
	SCX_TASK_OPS_ENABLED	= 1 << 1, /* task has bpf scheduler enabled */
	SCX_TASK_BAL_KEEP	= 1 << 2, /* balance decided to keep current */

	/*
	 * Used by scx_select_cpu_dfl() to hint that the task should be enqueued
	 * on the local dq of the selected CPU.
	 */
	SCX_TASK_SCD_ENQ_LOCAL	= 1 << 3,

	SCX_TASK_CURSOR		= 1 << 31, /* iteration cursor, not a task */
};

struct extl_entity;

struct sched_ext_entity {
	struct scx_dispatch_q	*dq;
	struct list_head	dq_node;
	u32			flags;		/* protected by rq lock */
	u32			weight;
	s32			sticky_cpu;
	s32			holding_cpu;
	atomic64_t		ops_state;
	u64			slice;
	struct list_head	tasks_node;
#ifdef CONFIG_SCHED_CLASS_EXT_LIB
	struct extl_entity	*le;
#endif
};

void sched_ext_free(struct task_struct *p);

/* sysctl */
#define SCHED_NORMAL_CLASS_NAME_LEN	32
#define SCHED_AVAILABLE_NORMAL_CLASSES	"fair ext"
int sched_normal_class_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int sched_ext_ops_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);

#else	/* !CONFIG_SCHED_CLASS_EXT */

static inline void sched_ext_free(struct task_struct *p) {}

#endif	/* CONFIG_SCHED_CLASS_EXT */
#endif	/* _LINUX_SCHED_EXT_H */
