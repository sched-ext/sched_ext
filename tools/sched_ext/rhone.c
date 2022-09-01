// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <unistd.h>

#include "rhone.h"

struct task_node {
	struct rhone_task *task;
	TAILQ_ENTRY(task_node) list_node;
};

TAILQ_HEAD(tasks_fifo, task_node);

/* The global queue of enqueued tasks in the global domain. */
static struct tasks_fifo global_fifo = TAILQ_HEAD_INITIALIZER(global_fifo);

/* The spinlock that synchronizes the global FIFO. */
static pthread_spinlock_t fifo_spinlock;

/* The number of tasks that are batched when the system is going idle. */
static int batch_size = 1;

/*
 * The global FIFO domain.
 *
 * TODO: Create a struct that encompasses an instance of a domain, and let the
 * user configure this on the command line.
 */
static struct rhone_domain *global_fifo_domain;

static bool node_in_list(const struct task_node *node)
{
	return node->list_node.tqe_prev != &node->list_node.tqe_next;
}

/*
 * Initialize a struct task_node's list node to be empty. For some reason there
 * is no macro for this in sys/queue.h, so we'll do it ourselves.
 */
static void list_node_initialize(struct task_node *node)
{
	node->list_node.tqe_next = NULL;
	node->list_node.tqe_prev = &node->list_node.tqe_next;
}

static int global_fifo_enqueue(struct rhone_task *task, void *context,
			       struct rhone_domain *domain, __u64 flags)
{
	struct task_node *node = rhone_task_get_context(task);

	/*
	 * The task's context should always be present until the task is
	 * removed, as a strong reference is acquired on it before it's passed
	 * to this callback.
	 */
	assert(node);
	pthread_spin_lock(&fifo_spinlock);
	/*
	 * Though SCX guarantees that an enqueue callback will only ever be
	 * invoked at most once without a subsequent dequeue or disable
	 * callback, we currently do not guarantee this in the core rhone
	 * scheduler as enqueue / dequeue / disable callbacks may all be
	 * emitted on different CPUs. This isn't an issue in BPF programs where
	 * the calls are handled synchronously, but in user-space where the
	 * messages are all asynchronous, it's a challenge.
	 *
	 * Soon, we'll update the core rhone scheduler to provide this
	 * guarantee by always enqueuing such messages to the same CPU, but
	 * that requires some more BPF work before it can land (specifically,
	 * making per-task storage non-flaky).
	 */
	if (!node_in_list(node))
		/*
		 * Note that because we race with enable / disable calls, it's
		 * possible that we may be enqueuing a disabled task here. SCX
		 * is resilient to spurious dispatching of disabled tasks, and
		 * will issue subsequent dispatch callbacks if it can't
		 * actually consume any of the tasks we've dispatched.
		 *
		 * So while this is not optimal in terms of scheduling
		 * decisions, it should not cause us to incorrectly go idle.
		 * Later, when the core rhone scheduler provides stronger
		 * ordering guarantees for
		 *
		 * enable -> enqueue -> dequeue -> ... * -> disable
		 *
		 * messages, this should no longer be an issue.
		 */
		TAILQ_INSERT_TAIL(&global_fifo, node, list_node);
	pthread_spin_unlock(&fifo_spinlock);
	return 0;
}

static void remove_task_from_fifo(struct rhone_task *task, void *context,
				  struct rhone_domain *domain)
{
	struct task_node *node = rhone_task_get_context(task);

	pthread_spin_lock(&fifo_spinlock);
	if (node_in_list(node)) {
		TAILQ_REMOVE(&global_fifo, node, list_node);
		list_node_initialize(node);
	}
	pthread_spin_unlock(&fifo_spinlock);
}

static void global_fifo_dequeue(struct rhone_sched *sched, int cpu, void *context, struct rhone_domain *domain)
{
	int i;

	for (i = 0; i < batch_size; i++) {
		struct task_node *node;
		struct rhone_task *task = NULL;
		int err;

		pthread_spin_lock(&fifo_spinlock);
		TAILQ_FOREACH(node, &global_fifo, list_node) {
			if (rhone_cpumask_test_cpu(cpu, node->task->cpumask)) {
				task = node->task;
				/* Released below. */
				rhone_task_acquire(task);
				TAILQ_REMOVE(&global_fifo, node, list_node);
				list_node_initialize(node);
				break;
			}
		}
		pthread_spin_unlock(&fifo_spinlock);

		if (!task)
			return;

		/*
		 * Note that it is safe to spuriously dispatch disabled tasks
		 * here. See global_fifo_enqueue() for details.
		 */
		err = rhone_task_dispatch(task);
		if (err)
			/*
			 * If we fail to dispatch the task, fail hard in the
			 * scheduler. Doing anything that could possibly cause
			 * another thread to be scheduled, including e.g.
			 * printing error messages, is not safe.
			 *
			 * TODO: Use a blocking call, which is pending landing
			 * on the bpf-next branch. Once that's available and
			 * ported to SCX, we won't have to handle this error
			 * case.
			 */
			rhone_sched_stop(sched);
		/* Acquired above. */
		rhone_task_release(task);
	}
}

static struct rhone_domain_ops domain_ops = {
	.enqueue = global_fifo_enqueue,
	.dequeue = remove_task_from_fifo,
	.going_idle = global_fifo_dequeue,
};

static int alloc_set_task_context(struct rhone_task *task)
{
	/* Freed the task destructor. */
	struct task_node *node = calloc(1, sizeof (struct task_node));

	if (!node) {
		fprintf(stderr, "Failed to allocate task node\n");
		return -ENOMEM;
	}

	node->task = task;
	list_node_initialize(node);
	assert(!node_in_list(node));
	rhone_task_set_context(task, node, NULL);

	return 0;
}

static void print_enqueued_tasks(struct rhone_sched *sched)
{
	struct task_node *curr = TAILQ_FIRST(&global_fifo);

	printf("-----------------------\n");
	printf("Printing enqueued tasks\n");
	printf("-----------------------\n");
	while (curr != NULL) {
		struct rhone_task *task = curr->task;

		printf("\tTask %s (%d) was still enqueued\n", task->name, task->tid);
		curr = TAILQ_NEXT(curr, list_node);
	}
	printf("\n----------------------------\n");
	printf("Done printing enqueued tasks\n");
	printf("----------------------------\n");
}

static struct rhone_domain *get_global_domain(struct rhone_task *task, struct rhone_domain *prev)
{
	assert(!prev || prev == global_fifo_domain);
	return global_fifo_domain;
}

static struct rhone_sched_ops sched_ops = {
	.choose_task_domain = get_global_domain,
	.task_enabled = alloc_set_task_context,
	.stopping = print_enqueued_tasks,
};

int run_usersched(struct rhone_sched_config *config)
{
	int ret;
	struct rhone_sched *scheduler;
	struct rhone_cpumask *cpumask;

	ret = pthread_spin_init(&fifo_spinlock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		fprintf(stderr, "Failed to initialize spinlock: %s\n", strerror(ret));
		return -1;
	}

	cpumask = rhone_cpumask_create(NULL);
	if (!cpumask) {
		fprintf(stderr, "Failed to create domain cpumask: %s\n", strerror(errno));
		goto destroy_spinlock;
	}

	rhone_cpumask_setall(cpumask);
	global_fifo_domain = rhone_domain_create(&domain_ops, NULL, cpumask);
	if (!global_fifo_domain) {
		fprintf(stderr, "Failed to create domain: %s\n", strerror(errno));
		goto destroy_spinlock;
	}

	ret = rhone_sched_create("global_fifo", &sched_ops, &global_fifo_domain,
				 1, config, &scheduler);
	if (ret) {
		fprintf(stderr, "Failed to create scheduler: %s\n", strerror(-ret));
		goto destroy_spinlock;
	}

	ret = rhone_sched_start(scheduler, true);
	if (ret)
		fprintf(stderr, "Failed to start scheduler: %s\n", strerror(-ret));

	rhone_sched_destroy(scheduler);
destroy_spinlock:
	pthread_spin_destroy(&fifo_spinlock);
	return ret;
}

static void __attribute__((noreturn))
print_usage_exit(int exit_status, const char *command)
{
	FILE *stream = exit_status == EXIT_SUCCESS ? stdout : stderr;

	fprintf(stream, "usage: %s [-ht] [-b <batch_size>]\n", command);
	fprintf(stream, "\t-t: Pipe the output of /sys/kernel/debug/tracing/trace_pipe\n");
	fprintf(stream, "\t    to stdout while the scheduler is running.\n");
	fprintf(stream, "\t-s: Print statistics about the scheduler while it is running.\n");
	fprintf(stream, "\t-b batch_size: The number of tasks that should be dispatched\n");
	fprintf(stream, "\t   when a CPU is going idle. Must be > 0. Defaults to 1.\n");
	fprintf(stream, "\t-h: Print this usage message.\n");
	fflush(stream);

	exit(exit_status);
}

static struct rhone_sched_config *parse_args(int argc, char **argv)
{
	int opt;
	struct rhone_sched_config *config = rhone_sched_config_create();

	if (!config) {
		fprintf(stderr, "Failed to create rhone config: %s\n", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "thsb:")) != -1) {
		switch (opt) {
			case 't':
				rhone_sched_config_set_trace_pipe(config, true);
				break;
			case 's':
				rhone_sched_config_set_print_stats(config, true);
				break;
			case 'b':
				batch_size = atoi(optarg);
				if (batch_size <= 0) {
					fprintf(stderr, "Invalid batch size %d specified\n", batch_size);
					print_usage_exit(EXIT_FAILURE, argv[0]);
				}
				break;
			case 'h':
				print_usage_exit(EXIT_SUCCESS, argv[0]);
			default:
				print_usage_exit(EXIT_FAILURE, argv[0]);
		}
	}

	return config;
}

int main(int argc, char **argv)
{
	struct rhone_sched_config *config = parse_args(argc, argv);
	int ret;

	ret = run_usersched(config);
	rhone_sched_config_destroy(config);

	return ret;
}
