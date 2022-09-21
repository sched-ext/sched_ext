// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "rhone.h"
#include "rhone_internal.h"
#include "rhone_bpf_internal.h"
#include "rhone_cpumask.h"
#include "rhone_task.h"

#include "rhone_task_internal.h"

struct rhone_task *task_create(const char *name, rhone_task_id id,
			       struct rhone_cpumask *cpumask)
{
	struct rhone_task *task = calloc(1, sizeof(struct rhone_task));

	if (!task) {
		errno = ENOMEM;
		return NULL;
	}

	task->tid = id;
	task->cpumask = cpumask;
	task->refcount = 1;

	strncpy(task->name, name, sizeof(task->name));
	task->name[sizeof(task->name) - 1] = '\0';

	return task;
}

void rhone_task_destroy(struct rhone_task *task)
{
	void *context;
	rhone_task_context_destructor context_destructor;

	/*
	 * Refcount should be zero here, which means that the context and
	 * context destructor should never change again, and it's safe to read
	 * them here without racing.
	 */
	assert(task->refcount == 0);
	context = rhone_task_get_context(task);
	context_destructor = atomic_load(&task->context_destructor);
	if (context) {
		if (context_destructor)
			context_destructor(context);
		else
			free(context);
	}


	rhone_cpumask_destroy(task->cpumask);

	free(task);
}

void rhone_task_set_context(struct rhone_task *task,
			    void *context,
			    rhone_task_context_destructor destructor)
{
	void *prev_context;
	rhone_task_context_destructor prev_destructor;

	assert(task->refcount > 0);

	prev_context = atomic_exchange(&task->context, context);
	prev_destructor = atomic_exchange(&task->context_destructor, destructor);

	if (prev_context) {
		if (prev_destructor)
			prev_destructor(prev_context);
		else
			free(prev_context);
	}
}

int rhone_task_dispatch(struct rhone_task *task)
{
	struct user_ring_buffer *rb = my_uprod_rb;
	struct rhone_bpf_user_sched_msg *msg;

	msg = user_ring_buffer__reserve(rb, sizeof(*msg));
	if (!msg)
		return -errno;

	msg->msg_type = RHONE_BPF_USER_MSG_TASK_DISPATCH;
	msg->pid = task->tid;
	user_ring_buffer__submit(rb, msg);

	return 0;
}
