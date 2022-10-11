// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <unistd.h>

#include "rhone.h"

TAILQ_HEAD(tasks_fifo, task_node);

struct task_node {
	struct rhone_task *task;
	TAILQ_ENTRY(task_node) list_node;
};

struct fifo_domain {
	/* The spinlock that synchronizes the FIFO task queue. */
	pthread_spinlock_t fifo_spinlock;

	/* The FIFO queue that the tasks are scheduled on. */
	struct tasks_fifo tasks_fifo;

	/* The rhone_domain for this FIFO instance. */
	struct rhone_domain *rhone_domain;
};

#define DEFAULT_BATCH_SIZE 1

/* The number of tasks that are batched when the system is going idle. */
static int batch_size = DEFAULT_BATCH_SIZE;

/* A map from CPU -> domain that is managing it. */
static struct fifo_domain **cpu_domain_map = NULL;

#define DEFAULT_NUM_DOMAINS 1
#define MAX_NUM_DOMAINS 64

/* Whether the scheduler should also schedule kernel tasks. */
static bool schedule_kernel_tasks = false;

/*
 * The number of FIFO domains on the system. Must be a multiple of the # of
 * CPUs.
 */
static int num_domains = DEFAULT_NUM_DOMAINS;

/* An array of the number of available FIFO domains. */
static struct fifo_domain **domains = NULL;

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
			       struct rhone_domain *rhone_domain, __u64 flags)
{
	struct fifo_domain *domain = context;
	struct task_node *node = rhone_task_get_context(task);

	/*
	 * The task's context should always be present until the task is
	 * removed, as a strong reference is acquired on it before it's passed
	 * to this callback.
	 */
	assert(node);
	pthread_spin_lock(&domain->fifo_spinlock);
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
		TAILQ_INSERT_TAIL(&domain->tasks_fifo, node, list_node);
	pthread_spin_unlock(&domain->fifo_spinlock);
	return 0;
}

static void remove_task_from_fifo(struct rhone_task *task, void *context,
				  struct rhone_domain *rhone_domain)
{
	struct task_node *node = rhone_task_get_context(task);
	struct fifo_domain *domain = context;

	pthread_spin_lock(&domain->fifo_spinlock);
	if (node_in_list(node)) {
		TAILQ_REMOVE(&domain->tasks_fifo, node, list_node);
		list_node_initialize(node);
	}
	pthread_spin_unlock(&domain->fifo_spinlock);
}

static bool domain_find_dispatch_task(int cpu, struct fifo_domain *domain,
				      struct rhone_sched *sched)
{
	struct task_node *node;
	struct rhone_task *task = NULL;

	pthread_spin_lock(&domain->fifo_spinlock);
	TAILQ_FOREACH(node, &domain->tasks_fifo, list_node) {
		if (rhone_cpumask_test_cpu(cpu, node->task->cpumask)) {
			task = node->task;
			/* Released below. */
			rhone_task_acquire(task);
			TAILQ_REMOVE(&domain->tasks_fifo, node, list_node);
			list_node_initialize(node);
			break;
		}
	}
	pthread_spin_unlock(&domain->fifo_spinlock);

	if (!task)
		return false;

	/*
	 * Note that it is safe to spuriously dispatch disabled tasks
	 * here. See global_fifo_enqueue() for details.
	 */
	if (rhone_task_dispatch(task))
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

	return true;
}

static void domain_dequeue(struct rhone_sched *sched, int cpu,
			   void *context, struct rhone_domain *rhone_domain)
{
	int i, tasks_found;
	struct fifo_domain *domain = context;

	for (tasks_found = 0; tasks_found < batch_size; tasks_found++)
		if (!domain_find_dispatch_task(cpu, domain, sched))
			break;

	/*
	 * No tasks were found, walk around domains trying to load balance. We
	 * bias towards the earlier domains. We could always do something
	 * smarter if we wanted to.
	 */
	if (tasks_found == 0) {
		for (i = 0; i < num_domains; i++) {
			struct fifo_domain *other = domains[i];

			/* Skip over the current domain. */
			if (other == domain)
				continue;
			if (domain_find_dispatch_task(cpu, other, sched))
				/* Once we find a task, just return. */
				return;
		}
	}
}

static struct rhone_domain_ops domain_ops = {
	.enqueue = global_fifo_enqueue,
	.dequeue = remove_task_from_fifo,
	.going_idle = domain_dequeue,
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
	int i;

	for (i = 0; i < num_domains; i++) {
		struct fifo_domain *domain = domains[i];
		struct task_node *curr = TAILQ_FIRST(&domain->tasks_fifo);

		printf("-----------------------\n");
		printf("Printing enqueued tasks\n");
		printf("for domain %d          \n", i);
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
}

static struct rhone_domain *choose_task_domain(struct rhone_task *task,
					       struct rhone_domain *prev)
{
	int i;

	if (prev) {
		/*
		 * This assertion will never trigger because we don't yet
		 * publish messages for when a task's cpumask has changed.
		 * When we do, this will have to be updated to actually check
		 * the cpumask before returning prev.
		 */
		assert(rhone_cpumask_intersects(task->cpumask, prev->cpumask));
		return prev;
	}

	/*
	 * If the task can be scheduled anywhere, try to evenly spread the load
	 * across domains. This static int isn't atomic, so we're not guaranteed
	 * to evenly spread load across the domains.
	 */
	if (rhone_cpumask_full(task->cpumask)) {
		static int _Atomic domain_index = 0;
		int current_index = atomic_fetch_add_explicit(&domain_index, 1,
							      memory_order_relaxed);

		return domains[current_index % num_domains]->rhone_domain;
	}

	/*
	 * If the task is only allowed to run on a subset of CPUs, just find the
	 * first domain that works.
	 */
	for (i = 0; i < num_domains; i++) {
		struct fifo_domain *fifo_domain = domains[i];
		struct rhone_domain *rhone_domain = fifo_domain->rhone_domain;

		if (rhone_cpumask_intersects(task->cpumask, rhone_domain->cpumask))
			return rhone_domain;
	}

	return NULL;
}

static struct rhone_sched_ops sched_ops = {
	.choose_task_domain = choose_task_domain,
	.task_enabled = alloc_set_task_context,
	.stopping = print_enqueued_tasks,
};

static struct rhone_cpumask *create_domain_cpumask(int domain_num)
{
	struct rhone_cpumask *cpumask;
	int i, cpus_per_domain, cpu_offset;

	cpumask = rhone_cpumask_create(NULL);
	if (!cpumask) {
		fprintf(stderr, "Failed to create cpumask: %s\n", strerror(errno));
		return NULL;
	}

	assert(rhone_num_cpus % num_domains == 0);
	cpus_per_domain = rhone_num_cpus / num_domains;
	cpu_offset = domain_num * cpus_per_domain;

	for (i = 0; i < cpus_per_domain; i++)
		rhone_cpumask_set_cpu(i + cpu_offset, cpumask);

	return cpumask;
}

static struct fifo_domain *create_fifo_domain(int domain_num)
{
	int ret;
	struct fifo_domain *domain;
	struct rhone_cpumask *cpumask;

	domain = calloc(1, sizeof(*domain));
	if (!domain) {
		fprintf(stderr, "Failed to allocate domain %d\n", domain_num);
		return NULL;
	}

	TAILQ_INIT(&domain->tasks_fifo);

	ret = pthread_spin_init(&domain->fifo_spinlock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		fprintf(stderr, "Failed to initialize spinlock: %s\n", strerror(ret));
		goto free_domain;
	}

	cpumask = create_domain_cpumask(domain_num);
	if (!cpumask) {
		fprintf(stderr, "Failed to create domain %d cpumask\n", domain_num);
		goto destroy_spinlock;
	}

	domain->rhone_domain = rhone_domain_create(&domain_ops, domain, cpumask);
	if (!domain->rhone_domain) {
		fprintf(stderr, "Failed to create domain: %s\n", strerror(errno));
		goto destroy_spinlock;
	}

	return domain;

destroy_spinlock:
	pthread_spin_destroy(&domain->fifo_spinlock);
free_domain:
	free(domain);
	return NULL;
}

static void destroy_fifo_domain(struct fifo_domain *domain)
{
	pthread_spin_destroy(&domain->fifo_spinlock);

	rhone_domain_destroy(domain->rhone_domain);

	free(domain);
}

int run_usersched(struct rhone_sched_config *config)
{
	int ret = -1, i;
	struct rhone_sched *scheduler;
	struct rhone_domain *local_domains[MAX_NUM_DOMAINS];

	cpu_domain_map = calloc(rhone_num_cpus, sizeof(struct fifo_domain *));
	if (!cpu_domain_map) {
		fprintf(stderr, "Failed to allocate cpu domain map\n");
		return -1;
	}

	domains = calloc(num_domains, sizeof(*domains));
	if (!domains) {
		fprintf(stderr, "Failed to allocate domains array\n");
		goto free_cpu_domain_map;
	}

	for (i = 0; i < num_domains; i++) {
		struct fifo_domain *domain = create_fifo_domain(i);

		if (!domain) {
			fprintf(stderr, "Failed to create FIFO domain %d\n", i);
			goto destroy_fifo_domains;
		}

		domains[i] = domain;
		local_domains[i] = domain->rhone_domain;
	}

	for (i = 0; i < rhone_num_cpus; i++) {
		int cpus_per_domain = rhone_num_cpus / num_domains;

		cpu_domain_map[i] = domains[i / cpus_per_domain];
	}

	ret = rhone_sched_create("fifo", &sched_ops, local_domains,
				 num_domains, config, &scheduler);
	if (ret) {
		fprintf(stderr, "Failed to create scheduler: %s\n", strerror(-ret));
		goto free_domains;
	}

	ret = rhone_sched_start(scheduler, true);
	if (ret)
		fprintf(stderr, "Failed to start scheduler: %s\n", strerror(-ret));

	rhone_sched_destroy(scheduler);
	goto free_domains;

destroy_fifo_domains:
	for (i = 0; i < num_domains; i++)
		destroy_fifo_domain(domains[i]);
free_domains:
	free(domains);
free_cpu_domain_map:
	free(cpu_domain_map);
	return ret;
}

static void __attribute__((noreturn))
print_usage_exit(int exit_status, const char *command)
{
	FILE *stream = exit_status == EXIT_SUCCESS ? stdout : stderr;

	fprintf(stream, "usage: %s [-htsk] [-b <batch_size>] [-d <num_domains>]\n", command);
	fprintf(stream, "\t-t: Pipe the output of /sys/kernel/debug/tracing/trace_pipe\n");
	fprintf(stream, "\t    to stdout while the scheduler is running.\n");
	fprintf(stream, "\t-s: Print statistics about the scheduler while it is running.\n");
	fprintf(stream, "\t-k: Schedule kernel tasks in addition to user space. The\n");
	fprintf(stream, "\t    default setting is 'false'. If scheduling kernel tasks,\n");
	fprintf(stream, "\t    schedulers must be very careful to not deadlock by\n");
	fprintf(stream, "\t    blocking a scheduler task on a kernel task that needs\n");
	fprintf(stream, "\t    that scheduler task to dispatch it to a CPU.\n");
	fprintf(stream, "\t-b batch_size: The number of tasks that should be dispatched\n");
	fprintf(stream, "\t   when a CPU is going idle. Must be > 0. Defaults to %d.\n",
		DEFAULT_BATCH_SIZE);
	fprintf(stream, "\t-d num_domains: The number of FIFO domains that should be\n");
	fprintf(stream, "\t   created. Must be a multiple of the # of CPUs on the\n");
	fprintf(stream, "\t   system. CPUs are partitioned equally amongst the domains.\n");
	fprintf(stream, "\t   The default number of domains is %d. The number of domains\n",
		DEFAULT_NUM_DOMAINS);
	fprintf(stream, "\t   cannot exceed the lesser of %d, or the # of CPUs.\n",
		MAX_NUM_DOMAINS);
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

	while ((opt = getopt(argc, argv, "thskb:d:")) != -1) {
		switch (opt) {
			case 't':
				rhone_sched_config_set_trace_pipe(config, true);
				break;
			case 's':
				rhone_sched_config_set_print_stats(config, true);
				break;
			case 'k':
				schedule_kernel_tasks = true;
				rhone_sched_config_set_schedule_kernel_tasks(config, true);
				break;
			case 'b':
				batch_size = atoi(optarg);
				if (batch_size <= 0) {
					fprintf(stderr, "Invalid batch size %d specified\n", batch_size);
					print_usage_exit(EXIT_FAILURE, argv[0]);
				}
				break;
			case 'd':
				num_domains = atoi(optarg);
				if (num_domains <= 0 ||
				    rhone_num_cpus % num_domains != 0 ||
				    num_domains > MAX_NUM_DOMAINS) {
					fprintf(stderr,
						"Invalid # domains: %d specified, total # of CPUs: %d\n",
						num_domains, rhone_num_cpus);
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
