// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#ifndef __RHONE_TASK_INTERNAL_H
#define __RHONE_TASK_INTERNAL_H

/**
 * Create a new rhone task.
 * @name: The name of the task.
 * @id: The ID of the new rhone task.
 * @cpumask: The cpumask of the new rhone task.
 *
 * Creates a new instance of a task in the specified scheduler. cpumask must
 * exist beyond this function call, and the rhone_task subsystem is responsible
 * for destroying the cpumask when the rhone task is destroyed.
 *
 * Returns an initialized and inserted struct rhone_task* on a successful call,
 * or NULL and errno set on a failure.
 */
struct rhone_task *task_create(const char *name, rhone_task_id id, struct rhone_cpumask *cpumask);

#endif  // __RHONE_TASK_INTERNAL_H
