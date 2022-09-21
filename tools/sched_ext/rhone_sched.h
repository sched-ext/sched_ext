// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#ifndef __RHONE_SCHED_H
#define __RHONE_SCHED_H

/* The maximum size of a rhone scheduler name. */
#define RHONE_SCHED_NAME_SZ 32

struct rhone_domain;
struct rhone_sched;
struct rhone_sched_config;
struct rhone_task;

struct rhone_sched_ops {
	/**
	 * choose_task_domain - Choose the domain that a task should be
	 * enqueued to.
	 * @task: The task for which we're choosing a domain.
	 * @prev: The domain that the task was previously enqueued in, or NULL
	 * if the task was not previously scheduled on a domain.
	 *
	 * It is unsafe to allocate on this path under any circumstances.
	 * Allocations may cause a deadlock.
	 *
	 * Schedulers must implement this callback, or rhone_sched_create() will fail.
	 *
	 * The callback should return a domain that the task will be enqueued
	 * to.
	 */
	struct rhone_domain *(*choose_task_domain)(struct rhone_task *task,
						   struct rhone_domain *prev);

	/**
	 * task_enabled - Callback that is invoked when a new task has been
	 * added to @sched. It is safe for callbacks to allocate on this path.
	 * @sched: The scheduler receiving the new task.
	 * @task: The task being added to the scheduler.
	 *
	 * Schedulers may choose to not implement this callback.
	 *
	 * Note that this callback may be issued concurrently with .enqueue()
	 * callbacks for a task, on domains in the scheduler. The core rhone
	 * scheduler may be improved to provide stronger ordering guarantees
	 * for:
	 *
	 * enable -> enqueue -> dequeue -> ... -> disable
	 *
	 * messages at a later time, but for now, edge schedulers must be
	 * resilient to enable and disable messages being invoked concurrently
	 * with enqueue messages. Enable and disable messages are, however,
	 * guaranteed to be invoked serially for individual tasks.
	 *
	 * Returns 0 if the task was successfully enabled.
	 * Any error code will cause the scheduler to exit.
	 */
	int (*task_enabled)(struct rhone_task *task);

	/**
	 * task_disabled - Callback that is invoked when a previously-enabled
	 * task will no longer be scheduled with @sched. The rhone scheduler
	 * guarantees that once this callback is invoked, that no further
	 * scheduling events will ever be emitted for @task.
	 * @sched: The scheduler receiving the new task.
	 * @task: The task being added to the scheduler.
	 *
	 * Schedulers may choose to not implement this callback.
	 *
	 * Note that this callback may be issued concurrently with .enqueue()
	 * callbacks for a task, on domains in the scheduler. The core rhone
	 * scheduler may be improved to provide stronger ordering guarantees
	 * for:
	 *
	 * enable -> enqueue -> dequeue -> ... -> disable
	 *
	 * messages at a later time, but for now, edge schedulers must be
	 * resilient to enable and disable messages being invoked concurrently
	 * with enqueue messages. Enable and disable messages are, however,
	 * guaranteed to be invoked serially for individual tasks.
	 */
	void (*task_disabled)(struct rhone_task *task);

	/**
	 * stopping - Callback that is invoked when @sched is exiting. When
	 * this callback is invoked, the core rhone scheduler guarantees that
	 * no more tasks will be scheduled, and no scheduling events will be
	 * emitted to any domains. This callback is also guaranteed to be
	 * invoked exactly once every time @sched transitions from running to
	 * stopped.
	 * @sched: The scheduler that is exiting.
	 *
	 * Schedulers may choose to not implement this callback.
	 */
	void (*stopping)(struct rhone_sched *sched);
};

/* The number of CPUs supported for this rhone scheduler. */
extern int rhone_num_cpus;

/**
 * Notify the kernel that it should dispatch the specified task to the
 * specified DQ.
 * @pid: The pid of the task to dispatch.
 *
 * Return 0 for success, -errno for error.
 */
int rhone_dispatch_task(__s32 pid);

/**
 * Create an instance of a rhone scheduler.
 * @name: The name of the scheduler.
 * @ops: The callbacks that are invoked for various scheduling events.
 * @domains: The scheduling domains that will be used.
 * @num_domains: The number of scheduling domains.
 * @config: The configuration for the scheduler.
 * @out: On a successful invocation, an initialized scheduler that can
 * be started with rhone_sched_start().
 *
 * @domains must point to a list of rhone domains that were created with
 * rhone_domain_create(). Domains may not overlap on any CPUs, and in
 * aggregate, all of the domains must cover every CPU in the system. Domains
 * must also not be used amongst multiple instances of struct rhone_sched
 * objects.
 *
 * After passing them to rhone_sched_create(), they must not be referenced
 * again unless in a scheduler callback. The rhone_sched subsystem will
 * eventually destroy the domains, even in the case of a failure.
 *
 * Return 0 if a rhone scheduler was successfully created and stored in @out.
 *
 * **-ENOMEM** if there was insufficient memory to create the rhone scheduler.
 *
 * **-EINVAL** if any of the domain overlapped a CPU, or the domains did not
 * encompass all CPU, in aggregate.
 */
int rhone_sched_create(const char *name, const struct rhone_sched_ops *ops,
		       struct rhone_domain **domains, unsigned num_domains,
		       const struct rhone_sched_config *config,
		       struct rhone_sched **out);

/**
 * Destroy a previously created rhone scheduler.
 * @scheduler: The scheduler to destroy.
 *
 * Destroy a previously created rhone scheduler. Destroying a running
 * scheduler will cause the scheduler to stop. This function may block.
 */
void rhone_sched_destroy(struct rhone_sched *scheduler);

/**
 * Start a rhone scheduler.
 * @scheduler: The scheduler to use.
 * @block: Whether the caller should be blocked until the scheduler has
 * stopped.
 *
 * Activate a rhone scheduler, and begin making scheduling decisions for the
 * system. If there is another active scheduler, this function will fail and
 * return an error code.
 *
 * The scheduler may be stopped later either by calling rhone_sched_stop(), or
 * by destroying the scheduler with rhone_sched_destroy().
 *
 * Returns:
 * 0 for success
 * -EBUSY if there was already an active scheduler.
 * -ENOMEM if there was insufficient memory on the system.
 */
int rhone_sched_start(struct rhone_sched *scheduler, bool block);

/**
 * Stop an actively running rhone scheduler.
 * @scheduler: The scheduler to stop.
 *
 * Stop an actively running rhone scheduler, and revert back to using the
 * default sched_ext global FIFO algorithm for scheduling.
 *
 * Returns:
 * 0 for success
 * -EINVAL if the scheduler was not the actively running scheduler.
 */
int rhone_sched_stop(struct rhone_sched *scheduler);

/**
 * Create a rhone configuration object with default settings.
 *
 * A rhone_sched_config object is created with the following settings:
 *
 * Trace pipe
 * ----------
 * Description: Spawns an RT thread that periodically prints the contents of
 * the /sys/kernel/debug/tracing/trace_pipe buffer. May be useful for
 * debugging interactions between the BPF program and the user-space
 * scheduler.
 * Default: false
 *
 * Print stats
 * -----------
 * Description: Spawns an RT thread that periodically prints statistics about
 * the scheduler.
 * Default: false
 *
 * Returns a struct rhone_sched_config* that must be destroyed in a subsequent
 * call to rhone_sched_config_destroy().
 */
struct rhone_sched_config *rhone_sched_config_create(void);

/**
 * Destroy a previously initialized struct rhone_sched_config object.
 * @config: The configuration object to destroy.
 */
void rhone_sched_config_destroy(struct rhone_sched_config *config);

/**
 * Set whether a rhone configuration object should enable trace buffer
 * reading.
 * @config: The configuration object to be updated.
 */
void rhone_sched_config_set_trace_pipe(struct rhone_sched_config *config, bool trace_pipe);

/**
 * Set whether a rhone configuration object should enable printing statistics.
 * @config: The configuration object to be updated.
 */
void rhone_sched_config_set_print_stats(struct rhone_sched_config *config, bool print_stats);

/**
 * Set whether the user-space scheduler will also schedule kernel tasks. While
 * scheduling kernel tasks provides the scheduler with finer-grained control
 * over scheduling decisions in the kernel, it also requires very precise
 * engineering to avoid hanging the system. For example, if the user-space
 * scheduler allocates on certain paths (e.g. enqueue), it could deadlock the
 * system if the task being enqueued is a reclaim task, and reclaim is triggered
 * during the allocation.
 * @config: The configuration object to be updated.
 */
void rhone_sched_config_set_schedule_kernel_tasks(struct rhone_sched_config *config, bool sched);

#endif  // __RHONE_SCHED_H
