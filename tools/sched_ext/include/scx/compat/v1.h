/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef SCX_COMPAT_V1_H
#define SCX_COMPAT_V1_H

#include <scx/common.bpf.h>

/* sched_ext_ops.flags */
enum scx_ops_flags___v1 {
	/*
	 * Keep built-in idle tracking even if ops.update_idle() is implemented.
	 */
	SCX_OPS_KEEP_BUILTIN_IDLE_V1	= 1LLU << 0,

	/*
	 * By default, if there are no other task to run on the CPU, ext core
	 * keeps running the current task even after its slice expires. If this
	 * flag is specified, such tasks are passed to ops.enqueue() with
	 * %SCX_ENQ_LAST. See the comment above %SCX_ENQ_LAST for more info.
	 */
	SCX_OPS_ENQ_LAST_V1		= 1LLU << 1,

	/*
	 * An exiting task may schedule after PF_EXITING is set. In such cases,
	 * bpf_task_from_pid() may not be able to find the task and if the BPF
	 * scheduler depends on pid lookup for dispatching, the task will be
	 * lost leading to various issues including RCU grace period stalls.
	 *
	 * To mask this problem, by default, unhashed tasks are automatically
	 * dispatched to the local DSQ on enqueue. If the BPF scheduler doesn't
	 * depend on pid lookups and wants to handle these tasks directly, the
	 * following flag can be used.
	 */
	SCX_OPS_ENQ_EXITING_V1		= 1LLU << 2,

	/*
	 * CPU cgroup knob enable flags
	 */
	SCX_OPS_CGROUP_KNOB_WEIGHT_V1	= 1LLU << 16,	/* cpu.weight */

	SCX_OPS_ALL_FLAGS_V1		= SCX_OPS_KEEP_BUILTIN_IDLE_V1 |
				 	  SCX_OPS_ENQ_LAST_V1 |
				 	  SCX_OPS_ENQ_EXITING_V1 |
					  SCX_OPS_CGROUP_KNOB_WEIGHT_V1,
};

/* argument container for ops.enable() and friends */
struct scx_enable_args___v1 {
#ifdef CONFIG_EXT_GROUP_SCHED
	/* the cgroup the task is joining */
	struct cgroup		*cgroup;
#endif
};

/**
 * struct sched_ext_ops - Operation table for BPF scheduler implementation
 *
 * Userland can implement an arbitrary scheduling policy by implementing and
 * loading operations in this table.
 */
struct sched_ext_ops___v1 {
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
	 * enqueue - Enqueue a task on the BPF scheduler
	 * @p: task being enqueued
	 * @enq_flags: %SCX_ENQ_*
	 *
	 * @p is ready to run. Dispatch directly by calling scx_bpf_dispatch()
	 * or enqueue on the BPF scheduler. If not directly dispatched, the bpf
	 * scheduler owns @p and if it fails to dispatch @p, the task will
	 * stall.
	 */
	void (*enqueue)(struct task_struct *p, u64 enq_flags);

	/**
	 * dequeue - Remove a task from the BPF scheduler
	 * @p: task being dequeued
	 * @deq_flags: %SCX_DEQ_*
	 *
	 * Remove @p from the BPF scheduler. This is usually called to isolate
	 * the task while updating its scheduling properties (e.g. priority).
	 *
	 * The ext core keeps track of whether the BPF side owns a given task or
	 * not and can gracefully ignore spurious dispatches from BPF side,
	 * which makes it safe to not implement this method. However, depending
	 * on the scheduling logic, this can lead to confusing behaviors - e.g.
	 * scheduling position not being updated across a priority change.
	 */
	void (*dequeue)(struct task_struct *p, u64 deq_flags);

	/**
	 * dispatch - Dispatch tasks from the BPF scheduler and/or consume DSQs
	 * @cpu: CPU to dispatch tasks for
	 * @prev: previous task being switched out
	 *
	 * Called when a CPU's local dsq is empty. The operation should dispatch
	 * one or more tasks from the BPF scheduler into the DSQs using
	 * scx_bpf_dispatch() and/or consume user DSQs into the local DSQ using
	 * scx_bpf_consume().
	 *
	 * The maximum number of times scx_bpf_dispatch() can be called without
	 * an intervening scx_bpf_consume() is specified by
	 * ops.dispatch_max_batch. See the comments on top of the two functions
	 * for more details.
	 *
	 * When not %NULL, @prev is an SCX task with its slice depleted. If
	 * @prev is still runnable as indicated by set %SCX_TASK_QUEUED in
	 * @prev->scx.flags, it is not enqueued yet and will be enqueued after
	 * ops.dispatch() returns. To keep executing @prev, return without
	 * dispatching or consuming any tasks. Also see %SCX_OPS_ENQ_LAST.
	 */
	void (*dispatch)(s32 cpu, struct task_struct *prev);

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
	 * The BPF scheduler should ensure that other available tasks are
	 * dispatched before the yielding task. Return value is ignored in this
	 * case.
	 *
	 * If @to is not-NULL, @from wants to yield the CPU to @to. If the bpf
	 * scheduler can implement the request, return %true; otherwise, %false.
	 */
	bool (*yield)(struct task_struct *from, struct task_struct *to);

	/**
	 * core_sched_before - Task ordering for core-sched
	 * @a: task A
	 * @b: task B
	 *
	 * Used by core-sched to determine the ordering between two tasks. See
	 * Documentation/admin-guide/hw-vuln/core-scheduling.rst for details on
	 * core-sched.
	 *
	 * Both @a and @b are runnable and may or may not currently be queued on
	 * the BPF scheduler. Should return %true if @a should run before @b.
	 * %false if there's no required ordering or @b should run before @a.
	 *
	 * If not specified, the default is ordering them according to when they
	 * became runnable.
	 */
	bool (*core_sched_before)(struct task_struct *a,struct task_struct *b);

	/**
	 * set_weight - Set task weight
	 * @p: task to set weight for
	 * @weight: new eight [1..10000]
	 *
	 * Update @p's weight to @weight.
	 */
	void (*set_weight)(struct task_struct *p, u32 weight);

	/**
	 * set_cpumask - Set CPU affinity
	 * @p: task to set CPU affinity for
	 * @cpumask: cpumask of cpus that @p can run on
	 *
	 * Update @p's CPU affinity to @cpumask.
	 */
	void (*set_cpumask)(struct task_struct *p,
			    const struct cpumask *cpumask);

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
	 *
	 * The user also must implement ops.select_cpu() as the default
	 * implementation relies on scx_bpf_select_cpu_dfl().
	 *
	 * Specify the %SCX_OPS_KEEP_BUILTIN_IDLE flag to keep the built-in idle
	 * tracking.
	 */
	void (*update_idle)(s32 cpu, bool idle);

	/**
	 * cpu_acquire - A CPU is becoming available to the BPF scheduler
	 * @cpu: The CPU being acquired by the BPF scheduler.
	 * @args: Acquire arguments, see the struct definition.
	 *
	 * A CPU that was previously released from the BPF scheduler is now once
	 * again under its control.
	 */
	void (*cpu_acquire)(s32 cpu, struct scx_cpu_acquire_args *args);

	/**
	 * cpu_release - A CPU is taken away from the BPF scheduler
	 * @cpu: The CPU being released by the BPF scheduler.
	 * @args: Release arguments, see the struct definition.
	 *
	 * The specified CPU is no longer under the control of the BPF
	 * scheduler. This could be because it was preempted by a higher
	 * priority sched_class, though there may be other reasons as well. The
	 * caller should consult @args->reason to determine the cause.
	 */
	void (*cpu_release)(s32 cpu, struct scx_cpu_release_args *args);

	/**
	 * cpu_online - A CPU became online
	 * @cpu: CPU which just came up
	 *
	 * @cpu just came online. @cpu doesn't call ops.enqueue() or run tasks
	 * associated with other CPUs beforehand.
	 */
	void (*cpu_online)(s32 cpu);

	/**
	 * cpu_offline - A CPU is going offline
	 * @cpu: CPU which is going offline
	 *
	 * @cpu is going offline. @cpu doesn't call ops.enqueue() or run tasks
	 * associated with other CPUs afterwards.
	 */
	void (*cpu_offline)(s32 cpu);

	/**
	 * prep_enable - Prepare to enable BPF scheduling for a task
	 * @p: task to prepare BPF scheduling for
	 * @args: enable arguments, see the struct definition
	 *
	 * Either we're loading a BPF scheduler or a new task is being forked.
	 * Prepare BPF scheduling for @p. This operation may block and can be
	 * used for allocations.
	 *
	 * Return 0 for success, -errno for failure. An error return while
	 * loading will abort loading of the BPF scheduler. During a fork, will
	 * abort the specific fork.
	 */
	s32 (*prep_enable)(struct task_struct *p,
			   struct scx_enable_args___v1 *args);

	/**
	 * enable - Enable BPF scheduling for a task
	 * @p: task to enable BPF scheduling for
	 * @args: enable arguments, see the struct definition
	 *
	 * Enable @p for BPF scheduling. @p is now in the cgroup specified for
	 * the preceding prep_enable() and will start running soon.
	 */
	void (*enable)(struct task_struct *p,
		       struct scx_enable_args___v1 *args);

	/**
	 * cancel_enable - Cancel prep_enable()
	 * @p: task being canceled
	 * @args: enable arguments, see the struct definition
	 *
	 * @p was prep_enable()'d but failed before reaching enable(). Undo the
	 * preparation.
	 */
	void (*cancel_enable)(struct task_struct *p,
			      struct scx_enable_args___v1 *args);

	/**
	 * disable - Disable BPF scheduling for a task
	 * @p: task to disable BPF scheduling for
	 *
	 * @p is exiting, leaving SCX or the BPF scheduler is being unloaded.
	 * Disable BPF scheduling for @p.
	 */
	void (*disable)(struct task_struct *p);

	/**
	 * cgroup_init - Initialize a cgroup
	 * @cgrp: cgroup being initialized
	 * @args: init arguments, see the struct definition
	 *
	 * Either the BPF scheduler is being loaded or @cgrp created, initialize
	 * @cgrp for sched_ext. This operation may block.
	 *
	 * Return 0 for success, -errno for failure. An error return while
	 * loading will abort loading of the BPF scheduler. During cgroup
	 * creation, it will abort the specific cgroup creation.
	 */
	s32 (*cgroup_init)(struct cgroup *cgrp,
			   struct scx_cgroup_init_args *args);

	/**
	 * cgroup_exit - Exit a cgroup
	 * @cgrp: cgroup being exited
	 *
	 * Either the BPF scheduler is being unloaded or @cgrp destroyed, exit
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
	 * All online ops must come before ops.init().
	 */

	/**
	 * init - Initialize the BPF scheduler
	 */
	s32 (*init)(void);

	/**
	 * exit - Clean up after the BPF scheduler
	 * @info: Exit info
	 */
	void (*exit)(struct scx_exit_info *info);

	/**
	 * dispatch_max_batch - Max nr of tasks that dispatch() can dispatch
	 */
	u32 dispatch_max_batch;

	/**
	 * flags - %SCX_OPS_* flags
	 */
	u64 flags;

	/**
	 * timeout_ms - The maximum amount of time, in milliseconds, that a
	 * runnable task should be able to wait before being scheduled. The
	 * maximum timeout may not exceed the default timeout of 30 seconds.
	 *
	 * Defaults to the maximum allowed timeout value of 30 seconds.
	 */
	u32 timeout_ms;

	/**
	 * name - BPF scheduler's name
	 *
	 * Must be a non-zero valid BPF object name including only isalnum(),
	 * '_' and '.' chars. Shows up in kernel.sched_ext_ops sysctl while the
	 * BPF scheduler is enabled.
	 */
	char name[SCX_OPS_NAME_LEN];
};

/* scx_entity.flags */
enum scx_ent_flags___v1 {
	SCX_TASK_ENQ_LOCAL	= 1 << 2, /* used by scx_select_cpu_dfl() to set SCX_ENQ_LOCAL */

	SCX_TASK_OPS_PREPPED	= 1 << 8, /* prepared for BPF scheduler enable */
	SCX_TASK_OPS_ENABLED	= 1 << 9, /* task has BPF scheduler enabled */
};

enum scx_enq_flags___v1 {
	/*
	 * A hint indicating that it's advisable to enqueue the task on the
	 * local dsq of the currently selected CPU. Currently used by
	 * select_cpu_dfl() and together with %SCX_ENQ_LAST.
	 */
	SCX_ENQ_LOCAL		= 1LLU << 42,
};

#endif	/* SCX_COMPAT_V1_H */
