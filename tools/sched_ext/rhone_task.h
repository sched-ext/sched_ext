// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#ifndef __RHONE_TASK_H
#define __RHONE_TASK_H

#include <assert.h>
#include <stdatomic.h>

#include "rhone_sched.h"

typedef __s32 rhone_task_id;

struct rhone_cpumask;
struct rhone_sched;

typedef void (*rhone_task_context_destructor)(void *context);

struct rhone_task {
	/* The name of the task. */
	char name[RHONE_SCHED_NAME_SZ];

	/* The mask of CPUs that this rhone task can support. */
	struct rhone_cpumask *cpumask;

	/* The domain the task currently resides in. */
	struct rhone_domain *domain;

	/* The reference count for the current task. */
	int _Atomic refcount;

	/*
	 * The destructor that is invoked in the caller when the task is being
	 * destroyed, and its context needs to be freed.
	 */
	rhone_task_context_destructor _Atomic context_destructor;

	/* Per-task context that may be set by a caller with rhone_task_set_context(). */
	void * _Atomic context;

	/* The global ID of the rhone task. */
	rhone_task_id tid;
};

/**
 * Get caller-owned context to the specified task.
 * @task: The task tracking the context.
 *
 * Returns previously set context if any was set on the task, or NULL if no
 * context was previously set.
 */
static inline void *rhone_task_get_context(struct rhone_task *task)
{
	/* Synchronizes with atomic_exchange() in rhone_task_set_context(). */
	return atomic_load_explicit(&task->context, memory_order_acquire);
}

/**
 * @brief Set caller-owned context to the specified task.
 * @param task: The task tracking the context.
 * @param context: The context to be set in the task. May be NULL if the caller
 * wishes to remove existing context. If there was already context set on
 * the task, it is returned.
 * @param destructor An optional destructor for the context which should be
 * invoked when the task is being destroyed. If NULL is passed, the context
 * will be freed using free(). The core rhone scheduler guarantees that no
 * locks will be held in the core scheduler when this destructor is called.
 *
 * This function will never be called by the core rhone scheduler, and it is
 * not safe to be invoked concurrently by multiple threads. Callers that may
 * invoke this function concurrently must synchronize amongst themselves.
 */
void rhone_task_set_context(struct rhone_task *task,
			    void *context,
			    rhone_task_context_destructor destructor);

/**
 * @brief Dispatch a task to the DQ for the current CPU.
 * @param task: The task being dispatched.
 */
int rhone_task_dispatch(struct rhone_task *task);

/**
 * @brief Destroy a rhone task.
 * @param task: The task being destroyed.
 */
void rhone_task_destroy(struct rhone_task *task);

static inline void rhone_task_acquire(struct rhone_task *task)
{
	int count = atomic_fetch_add(&task->refcount, 1);
	assert(count > 0);
}

static inline void rhone_task_release(struct rhone_task *task)
{
	int count = atomic_fetch_sub(&task->refcount, 1);
	assert(count > 0);

	if (count == 1)
		rhone_task_destroy(task);
}

#endif  // __RHONE_TASK_H
