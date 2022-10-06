// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#ifndef __RHONE_DOMAIN_H
#define __RHONE_DOMAIN_H

struct rhone_cpumask;
struct rhone_domain;
struct rhone_sched;
struct rhone_task;

struct rhone_domain_ops {
	/**
	 * enqueue - Callback that is invoked when a task should be enqueued on
	 *	     the specified domain. This callback must be safe to be
	 *	     invoked concurrently from multiple threads. This callback
	 *	     may not allocate memory under any circumstances, or deadlock
	 *	     may occur.
	 *
	 *	     Note as well that this callback may be invoked
	 *	     concurrently with enable / disable callbacks in the
	 *	     scheduler ops. The rhone scheduler may eventually provide
	 *	     a stronger ordering guarantee for enable -> enqueue ->
	 *	     dequeue -> ... -> disable messages, but for now, this
	 *	     guarantee is not provided and the domain must be resilient
	 *	     to such orderings.
	 * @task:  The task being enqueued.
	 * @context: The caller-specified context from when the domain was
	 *	     created.
	 * @domain: The domain in which the task is being enqueued.
	 * @flags Enqueue flags
	 *
	 * Returns:
	 * 0	  Successfully enqueued
	 * -errno Error, causing the scheduler to exit.
	 */
	int (*enqueue)(struct rhone_task *task, void *context,
		       struct rhone_domain *domain, __u64 flags);

	/**
	 * dequeue - Callback that is invoked when a task should be dequeued
	 *	     from the specified domain. This callback must be safe to be
	 *	     invoked concurrently from multiple threads.
	 *
	 *	     This callback may be invoked concurrently with an enqueue
	 *	     callback in the domain. The core rhone scheduler may
	 *	     eventually provide a stronger ordering guarantee for
	 *	     enable -> enqueue -> dequeue -> ... -> disable messages,
	 *	     but for now, this guarantee is not provided and the domain
	 *	     must be resilient to such orderings.
	 * @task:  The task being dequeued.
	 * @context: The caller-specified context from when the domain was
	 *	     created.
	 * @domain: The domain from which the task is being dequeued.
	 *
	 * Returns:
	 * 0	  Successfully enqueued
	 * -errno Error
	 */
	void (*dequeue)(struct rhone_task *task, void *context, struct rhone_domain *domain);

	/**
	 * going_idle - Callback that is invoked when a CPU has no more tasks
	 * to run, and is going to go idle soon.
	 * @sched: The scheduler
	 * @cpu: The CPU that will soon be going idle.
	 * @context: Caller-specified context.
	 * @domain: The domain containing the CPU going idle.
	 *
	 * This callback may schedule tasks on the specified CPU using
	 * rhone_task_schedule(). If no task is scheduled to the CPU, the CPU
	 * will go idle.
	 *
	 * This callback may not allocate memory under any circumstances, or
	 * deadlock may occur.
	 *
	 * Note that it is safe for the domain to spuriously dispatch disabled
	 * or dequeued tasks. In such a case, a subsequent invocation to the
	 * callback will take place, possibly after doing one or more round
	 * trips to the kernel.
	 */
	void (*going_idle)(struct rhone_sched *sched, int cpu, void *context,
			   struct rhone_domain *domain);
};

struct rhone_domain {
	/* User specified ops that are invoked when making scheduling decisions. */
	struct rhone_domain_ops ops;

	/* Optional user-specified context that is passed to domain op callbacks. */
	void *context;

	/* Cpumask that identifies the CPUs this domain can schedule to. */
	struct rhone_cpumask *cpumask;

	/* The scheduler that owns this domain. */
	struct rhone_sched *sched;

	/* The identifier of the dispatch queue in the kernel. */
	__s64 dq_id;
};

/**
 * Create a new domain that has the specified cpumask, and track it in
 * the specified scheduler.
 * @ops: The operations that the core rhone scheduler will invoke when
 * making scheduler decisions.
 * @context: Optional user-specified context that is passed to all of the
 * rhone domain op callbacks.
 * @cpumask: The cpumask of the new rhone task.
 *
 * Creates a new instance of a domain in the specified scheduler. cpumask must
 * not be referenced after invoking this function call. The rhone domain
 * subsystem retains ownership of the cpumask, and is responsible for
 * destroying it, even in the event of an error.
 *
 * Returns an initialized and tracked struct rhone_domain* on a successful
 * call, or NULL and errno set on a failure.
 */
struct rhone_domain *rhone_domain_create(struct rhone_domain_ops *ops,
					 void *context,
					 struct rhone_cpumask *cpumask);

/**
 * Destroy a rhone domain.
 * @domain: The domain being removed.
 *
 * By the time this function returns, @domain may not be referenced.
 */
void rhone_domain_destroy(struct rhone_domain* domain);

/**
 * Enqueue a task in the specified domain.
 * @domain: The domain that the task will be scheduled in.
 * @task: The task being enqueued.
 *
 * Returns 0 if the task was successfully enqueued, or an error code otherwise.
 */
int rhone_domain_enqueue_task(struct rhone_domain *domain, struct rhone_task *task);

#endif  // __RHONE_DOMAIN_H
