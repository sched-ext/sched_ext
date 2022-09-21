// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#define _GNU_SOURCE
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "rhone_prog.skel.h"
#include "rhone_cpumask.h"
#include "rhone_bpf_internal.h"
#include "rhone_domain.h"
#include "rhone_task.h"
#include "rhone.h"

#include "rhone_task_internal.h"

struct rhone_sched_config {
	/*
	 * Whether an RT thread that continuously reads from
	 * /sys/kernel/debug/tracing/trace_pipe, and pipes it to stdout
	 * should be spawned when the scheduler is started.
	 */
	bool read_trace_pipe;

	/*
	 * Whether an RT thread that continuously reads prints statistics about
	 * the currently running scheduler should be spawned when the scheduler
	 * is started.
	 */
	bool print_stats;

	/*
	 * Whether the scheduler will be responsible for scheduling kernel
	 * tasks.
	 */
	bool schedule_kernel_tasks;
};

struct rhone_sched {
	/* The name of the scheduler. */
	const char name[RHONE_SCHED_NAME_SZ];

	/* The skeleton of the BPF program portion of the scheduler. */
	struct rhone_prog *skel;

	/* The BPF link of an actively running rhone BPF scheduler program. */
	struct bpf_link *link;

	/* The kernel-producer per-CPU ringbuffers. */
	struct ring_buffer **kprod_ringbuffers;

	/* The user-producer per-CPU ringbuffers. */
	struct user_ring_buffer **uprod_ringbuffers;

	/* The per-cpu threads making scheduling decision for a given CPU. */
	pthread_t* commanders;

	/* The callbacks that are invoked for various events that are delivered
	 * from kernel space.
	 */
	struct rhone_sched_ops ops;

	/* The maximum number of tasks allowed on the system. */
	rhone_task_id max_tasks;

	/* An array of all possible tasks running on the system. */
	struct rhone_task **tasks;

	/* A lock protecting access to the array of tasks. */
	pthread_spinlock_t lock;

	/* The number of domains in this scheduler. */
	unsigned num_domains;

	/* An array of all domains in this scheduler. */
	struct rhone_domain **domains;

	/* A map from CPU to the domain that contains it. */
	struct rhone_domain **cpu_domain_map;

	/* The number of tasks that are sent to the kernel to be scheduled. */
	__u32 batch_size;

	/* Barrier waited on by all threads, both when initializing all of the
	 * commanders, and when exiting the program.
	 */
	pthread_barrier_t barrier;

	/* The ringbuffer on which sched management messages are sent by the kernel. */
	struct ring_buffer *manager_rb;

	/* The task that is responsible for receiving task enable / disable
	 * messages, messages indicating that the scheduler has exited, etc.
	 * Basically all messages that are not task enqueue, and "needs more
	 * tasks".
	 */
	pthread_t manager;

	/* When enabled, the ID of an RT thread that continuously reads from
	 * /sys/kernel/debug/tracing/trace_pipe, and pipes it to stdout.
	 */
	pthread_t trace_reader;

	/* When enabled, the ID of an RT thread that continuously prints
	 * statistics about the currently running scheduler.
	 */
	pthread_t stats_printer;

	/* The configuration for this rhone scheduler. */
	struct rhone_sched_config config;

	/* The FD for the map that tracks whether a CPU needs more tasks. */
	int need_tasks_map_fd;
};

/* The number of CPUs in the scheduler. */
int rhone_num_cpus;

/* The maximum number of tasks in the scheduler. */
static size_t rhone_max_tasks;

/* The currently active scheduler. NULL if no scheduler is active. */
static struct rhone_sched * _Atomic active_sched = NULL;

__thread int my_cpu;
__thread struct ring_buffer *my_kprod_rb;
__thread struct user_ring_buffer *my_uprod_rb;
__thread struct rhone_domain *my_domain;

/* The index of the ringbuffer that is used to send bootstrap messages to the kernel. */
#define BOOTSTRAP_RB 0

static struct rhone_sched *get_active_sched(void)
{
	return (struct rhone_sched *)atomic_load_explicit(&active_sched, memory_order_acquire);
}

/**
 * Determine whether the specified scheduler is the active scheduler. This
 * function is safe to call even if the specified scheduler may be freed.
 * @sched: The scheduler to check.
 */
static bool sched_is_active(struct rhone_sched *sched)
{
	return sched == get_active_sched();
}

static void* stop_sched_ret(struct rhone_sched *sched)
{
	int ret = rhone_sched_stop(sched);

	if (ret)
		fprintf(stderr, "Failed to stop sched %s: %s\n", sched->name, strerror(-ret));

	return NULL;
}

static bool task_id_valid_warn(struct rhone_sched *sched, rhone_task_id id)
{
	if (id >= rhone_max_tasks) {
		fprintf(stderr, "Invalid task %d requested\n", id);
		return false;
	}

	return true;
}

static void sched_task_insert(struct rhone_sched *sched, struct rhone_task *task)
{
	assert(task_id_valid_warn(sched, task->tid));
	assert(task->refcount > 0);

	/*
	 * Task enable / task disable messages are delivered serially on the
	 * management ring buffer, so we should have a guarantee that nobody
	 * else has put this task in the map yet.
	 */
	pthread_spin_lock(&sched->lock);
	assert(sched->tasks[task->tid] == NULL);
	sched->tasks[task->tid] = task;
	pthread_spin_unlock(&sched->lock);
}

static void sched_task_remove(struct rhone_sched *sched, struct rhone_task *task)
{
	assert(task_id_valid_warn(sched, task->tid));
	/*
	 * Task enable / disable is delivered serially on the management ring
	 * buffer, so there should always be a task in the map, as we should
	 * have received an enable message from the kernel.
	 */
	assert(sched->tasks[task->tid] != NULL);

	pthread_spin_lock(&sched->lock);
	sched->tasks[task->tid] = NULL;
	pthread_spin_unlock(&sched->lock);
	rhone_task_release(task);
}

static int handle_enable_msg(struct rhone_sched *sched,
			     const struct rhone_bpf_kernel_task_enable_msg *enable_msg)
{
	struct rhone_task *task;
	struct rhone_cpumask *cpumask;
	int err;
	pid_t pid = enable_msg->pid;

	cpumask = rhone_cpumask_create(enable_msg->cpumask);
	if (!cpumask) {
		fprintf(stderr, "Failed to create cpumask: %s\n", strerror(errno));
		return -1;
	}
	/* Initial refcount released below or in sched_task_remove(). */
	task = task_create((char *)enable_msg->name, pid, cpumask);
	if (!task) {
		fprintf(stderr, "Failed to create task: %s\n", strerror(errno));
		return -1;
	}

	task->domain = sched->ops.choose_task_domain(task, NULL);
	if (!task->domain) {
		fprintf(stderr, "No domain set for task %s\n", task->name);
		goto free_task;
	}

	if (sched->ops.task_enabled) {
		err = sched->ops.task_enabled(task);
		if (err) {
			fprintf(stderr, "Failed to enable task %d\n", pid);
			goto free_task;
		}
	}

	/*
	 * Insert the task *after* calling the .task_enabled() op above.  We
	 * need to ensure that the edge-scheduler has had a chance to save and
	 * bootstrap any context it needs, or an .enqueue() call may happen
	 * without that context being available.
	 *
	 * Note that while a task can be enqueued before we insert it here,
	 * that's fine. We handle what look like spurious enqueues in
	 * handle_enqueue_msg() by just dispatching directly back to the
	 * kernel, so it's safe to defer the insertion until now and race with
	 * enqueueing.
	 */
	sched_task_insert(sched, task);

	return 0;

free_task:
	rhone_task_release(task);
	return -1;
}

/*
 * Look up a task in the sched task list. If one is found acquire a strong
 * reference to it, which the caller is responsible for releasing, and return
 * it. If no task is found, NULL is returned.
 */
static struct rhone_task *sched_task_lookup_acquire(struct rhone_sched *sched, rhone_task_id id)
{
	struct rhone_task *task;

	if (!task_id_valid_warn(sched, id))
		return NULL;

	pthread_spin_lock(&sched->lock);
	task = sched->tasks[id];
	if (task)
		rhone_task_acquire(task);
	pthread_spin_unlock(&sched->lock);

	return task;
}

static int handle_disable_msg(struct rhone_sched *sched,
			      const struct rhone_bpf_kernel_task_disable_msg *disable_msg)
{
	struct rhone_task *task;
	struct rhone_domain *domain;
	pid_t pid = disable_msg->pid;

	/* Released below. */
	task = sched_task_lookup_acquire(sched, pid);
	if (!task) {
		/*
		 * This can happen if the scheduler fails to choose a domain
		 * for the task, or call .task_enabled(). The kernel will still
		 * send a disable message, but we can just ignore it because it
		 * was never really enabled in the core scheduler.
		 */
		return 0;
	}

	domain = task->domain;
	if (domain)
		domain->ops.dequeue(task, domain->context, domain);

	if (sched->ops.task_disabled)
		sched->ops.task_disabled(task);

	sched_task_remove(sched, task);
	/* Acquired above. */
	rhone_task_release(task);

	return 0;
}

static int handle_management_event(void *ctx, void *data, size_t data_sz)
{
	struct rhone_sched *sched = ctx;
	const struct rhone_bpf_kernel_manage_msg_hdr *hdr = data;
	const struct rhone_bpf_kernel_task_enable_msg *enable_msg = data;
	const struct rhone_bpf_kernel_task_disable_msg *disable_msg = data;
	int err;

	switch(hdr->msg_type) {
	case RHONE_BPF_MANAGE_MSG_TASK_ENABLE:
		err = handle_enable_msg(sched, enable_msg);
		if (err) {
			fprintf(stderr, "Failed to handle enable msg: %s\n", strerror(errno));
			return rhone_sched_stop(sched);
		}
		break;
	case RHONE_BPF_MANAGE_MSG_TASK_DISABLE:
		err = handle_disable_msg(sched, disable_msg);
		if (err) {
			fprintf(stderr, "Failed to handle disable msg: %s\n", strerror(errno));
			return rhone_sched_stop(sched);
		}
		break;
	default:
		printf("Unknown management message type %d!\n", hdr->msg_type);
		return rhone_sched_stop(sched);
	}

	return 0;
}

static int handle_enqueue_msg(struct rhone_sched *sched,
			      const struct rhone_bpf_kernel_enqueue_msg *enqueue_msg)
{
	struct rhone_task *task;
	struct rhone_domain *domain;
	pid_t pid = enqueue_msg->pid;
	int err;

	/* Released below. */
	task = sched_task_lookup_acquire(sched, pid);
	if (!task) {
		struct rhone_bpf_user_sched_msg *msg;

		/*
		 * We may sometimes fail to find a task, even though it was
		 * properly enabled. This is because task enable and disable
		 * messages are sent on the management ring buffer, and those
		 * messages may be delivered concurrently with enqueue messages
		 * due to all of the communication between BPF and user-space
		 * being asynchronous.
		 *
		 * For example:
		 *
		 * // In BPF:
		 * rhone_prep_enable(struct task_struct *p)
		 *	// Delivered asynchronously.
		 *	send_enable_msg(p);
		 *	return;
		 *					   // In BPF:
		 *					   rhone_enqueue(struct task_struct *p)
		 *					   // Delivered asynchronously.
		 *					   send_enqueue_msg(p);
		 *					   return;
		 *
		 *					   // In rhone:
		 *					   handle_enqueue_msg(p);
		 *					   task = lookup_task(p);
		 * // In rhone:
		 * handle_enable_msg(p);
		 * task = rhone_task_create(p, ...);
		 * ...
		 * insert_task(task);
		 *
		 * In this case, tell the kernel that we've received a task we
		 * don't recognize, and dispatch it to the SCX_GLOBAL_DQ. scx
		 * in the kernel can handle spurious dispatches, so this is
		 * perfectly safe.
		 *
		 * The scheduling decisions may not be optimal during this race
		 * window, but the window should be short.
		 */
		msg = user_ring_buffer__reserve(my_uprod_rb, sizeof(*msg));
		if (!msg)
			/*
			 * If we can't dispatch the task, return an error
			 * and exit out of the scheduler.
			 */
			return ENOSPC;
		msg->msg_type = RHONE_BPF_USER_MSG_TASK_UNKNOWN;
		msg->pid = pid;
		user_ring_buffer__submit(my_uprod_rb, msg);
		return 0;
	}
	domain = sched->ops.choose_task_domain(task, task->domain);
	if (!domain) {
		err = ENOENT;
		goto release_task;
	}

	err = domain->ops.enqueue(task, domain->context, domain,
				  enqueue_msg->flags);

release_task:
	rhone_task_release(task);
	return err;
}

static void notify_my_domain_going_idle(struct rhone_sched *sched)
{
	struct rhone_domain *domain = sched->cpu_domain_map[my_cpu];
	__u32 key = my_cpu;
	__u8 needs_tasks = 0;
	int err;

	domain->ops.going_idle(sched, my_cpu, domain->context, domain);

	err = bpf_map_update_elem(sched->need_tasks_map_fd, &key, &needs_tasks, 0);
	if (err)
		/* Should never happen. */
		rhone_sched_stop(sched);
}

static int handle_kern_event(void *ctx, void *data, size_t data_sz)
{
	struct rhone_sched *sched = ctx;
	const struct rhone_bpf_kernel_percpu_msg_hdr *hdr = data;
	const struct rhone_bpf_kernel_enqueue_msg *enqueue_msg = data;
	int err;

	switch(hdr->msg_type) {
	case RHONE_BPF_KERN_MSG_TASK_ENQUEUE:
		err = handle_enqueue_msg(sched, enqueue_msg);
		if (err)
			return rhone_sched_stop(sched);
		break;
	case RHONE_BPF_KERN_MSG_NEED_TASKS:
		notify_my_domain_going_idle(sched);
		break;
	default:
		return rhone_sched_stop(sched);
	}

	return 0;
}

static void*
ringbuf_listen_loop(struct rhone_sched *sched)
{
	struct rhone_prog *skel = sched->skel;
	__u32 key = my_cpu;

	while (!skel->bss->exiting) {
		int err;
		__u8 needs_tasks = 0;

		err = ring_buffer__poll(my_kprod_rb, 2000);
		if (err < 0) {
			if (err != -EINTR) {
				fprintf(stderr, "Failed to poll ring buffer: %d\n", err);
				return stop_sched_ret(sched);
			}
		}

		err = bpf_map_lookup_elem(sched->need_tasks_map_fd, &key, &needs_tasks);
		if (err) {
			fprintf(stderr, "Failed to lookup needs tasks for %d: %d\n", my_cpu, err);
			return stop_sched_ret(sched);
		}
		if (needs_tasks)
			notify_my_domain_going_idle(sched);
	}

	return NULL;
}

static struct rhone_domain*
get_rhone_domain_by_cpu(struct rhone_sched *sched, int cpu)
{
	unsigned i = 0;

	assert(cpu < rhone_num_cpus);
	for (i = 0; i < sched->num_domains; i++) {
		struct rhone_domain *domain = sched->domains[i];

		if (rhone_cpumask_test_cpu(cpu, domain->cpumask))
			return domain;
	}

	/*
	 * The scheduler should have verified that all CPUs had a domain before
	 * allowing a rhone_sched_create() call to succeed.
	 */
	__builtin_unreachable();
}

static void*
run_commander(void *arg)
{
	struct rhone_sched *sched = arg;

	my_cpu = sched_getcpu();
	my_kprod_rb = sched->kprod_ringbuffers[my_cpu];
	my_uprod_rb = sched->uprod_ringbuffers[my_cpu];
	my_domain = get_rhone_domain_by_cpu(sched, my_cpu);

	pthread_barrier_wait(&sched->barrier);

	if (my_cpu < 0) {
		fprintf(stderr, "Failed to query cpu: %s\n", strerror(errno));
		return stop_sched_ret(sched);
	}

	return ringbuf_listen_loop(sched);
}

static int
initialize_pthread_attr(pthread_attr_t *attr, bool debugging_task, int cpu)
{
	int ret;
	struct sched_param sched_param = {
		.sched_priority = sched_get_priority_min(SCHED_FIFO),
	};

	ret = pthread_attr_init(attr);
	if (ret) {
		fprintf(stderr, "Failed to init attr: %s\n", strerror(ret));
		return ret;
	}

	ret = pthread_attr_setschedpolicy(attr, SCHED_FIFO);
	if (ret) {
		fprintf(stderr,
			"Failed to set pthread as SCHED_FIFO: %s\n",
			strerror(ret));
		goto destroy_attr;
	}

	if (debugging_task)
		/*
		 * Make the priority of the debugger tasks higher than the
		 * sched tasks so that debugging output will be visible even if
		 * the scheduler tasks are buggy and e.g. infinite
		 * busy-looping.
		 */
		sched_param.sched_priority++;
	assert(sched_param.sched_priority >= sched_get_priority_min(SCHED_FIFO));
	/*
	 * Keep the priority below max, to ensure that sysrq(S) will always run
	 * at higher priority than any rhone RT task. If the priority of the
	 * rhone scheduling tasks are too high, the helper kthread that runs in
	 * the sysrq(S) handler to reset SCX and clear the existing sched ops
	 * may never be able to run if e.g. the scheduling tasks are buggy and
	 * spin indefinitely without ever sleeping or yielding a CPU.
	 */
	assert(sched_param.sched_priority < sched_get_priority_max(SCHED_FIFO));
	ret = pthread_attr_setschedparam(attr, &sched_param);
	if (ret) {
		fprintf(stderr, "Failed to set sched param: %s\n",
			strerror(ret));
		goto destroy_attr;
	}

	ret = pthread_attr_setinheritsched(attr, PTHREAD_EXPLICIT_SCHED);
	if (ret) {
		fprintf(stderr, "Failed set inherit sched: %s\n",
			strerror(ret));
		goto destroy_attr;
	}

	if (cpu >= 0) {
		cpu_set_t cpuset;

		CPU_ZERO(&cpuset);
		CPU_SET(cpu, &cpuset);
		ret = pthread_attr_setaffinity_np(attr, sizeof(cpu_set_t),
				&cpuset);
		if (ret) {
			fprintf(stderr,
					"Failed to set affinity to %d: %s\n", cpu,
					strerror(ret));
			goto destroy_attr;
		}
	}

	return 0;

destroy_attr:
	pthread_attr_destroy(attr);

	return ret;
}

static int
spawn_commanders(struct rhone_sched *sched)
{
	int i, ret;

	/* Freed in bootstrap_usersched(). */
	sched->commanders = calloc(rhone_num_cpus, sizeof(pthread_t));
	if (!sched->commanders) {
		fprintf(stderr, "Failed to allocate commanders: %s\n", strerror(errno));
		return -ENOMEM;
	}

	ret = pthread_barrier_init(&sched->barrier, NULL, rhone_num_cpus + 1);
	if (ret) {
		fprintf(stderr, "Failed to initialize barrier: %s\n", strerror(errno));
		return ret;
	}

	for (i = 0; i < rhone_num_cpus; i++) {
		pthread_attr_t attr;

		ret = initialize_pthread_attr(&attr, false, i);
		if (ret)
			return ret;

		ret = pthread_create(&sched->commanders[i], &attr, run_commander, sched);
		pthread_attr_destroy(&attr);
		if (ret)  {
			fprintf(stderr, "Failed to spawn commander %d: %s\n", i, strerror(ret));
			return ret;
		}
	}

	pthread_barrier_wait(&sched->barrier);

	return 0;
}

static void destroy_commanders(struct rhone_sched *sched)
{
	int i;

	if (!sched->commanders)
		return;

	for (i = 0; i < rhone_num_cpus; i++) {
		int status;
		void *retval;

		status = pthread_cancel(sched->commanders[i]);
		if (status) {
			fprintf(stderr, "Failed to cancel commander %d\n", i);
			continue;
		}

		status = pthread_join(sched->commanders[i], &retval);
		if (!status)
			printf("Commander %d exited\n", i);
		else
			fprintf(stderr, "Commander %d failed to exit\n", i);
	}
	free(sched->commanders);
	sched->commanders = NULL;
}

static void *run_sched_manager(void *arg)
{
	struct rhone_sched *sched = arg;
	struct rhone_prog *skel = sched->skel;
	struct ring_buffer *manager_rb = sched->manager_rb;

	while (!skel->bss->exiting) {
		int err;

		err = ring_buffer__poll(manager_rb, 2000);
		if (err < 0) {
			if (err != -EINTR) {
				fprintf(stderr, "Failed to poll ring buffer: %d\n", err);
				return stop_sched_ret(sched);
			}
		}
	}

	return NULL;
}

static int spawn_sched_manager(struct rhone_sched *sched)
{
	pthread_attr_t attr;
	int ret;

	ret = initialize_pthread_attr(&attr, false, -1);
	if (ret) {
		fprintf(stderr, "Failed to init attr: %s\n", strerror(ret));
		return ret;
	}

	ret = pthread_create(&sched->trace_reader, &attr, run_sched_manager, sched);
	pthread_attr_destroy(&attr);
	if (ret)
		fprintf(stderr, "Failed to create sched manager: %s\n", strerror(ret));

	return ret;
}

static void* run_trace_reader(void *arg)
{
	int fd;
	char buf[4096];
	struct rhone_sched *sched = arg;
	struct rhone_prog *skel = sched->skel;

	fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open trace pipe: %s\n", strerror(errno));
		return stop_sched_ret(sched);
	}

	while (!skel->bss->exiting) {
		ssize_t total_read;

		total_read = read(fd, buf, 4096);

		if (total_read < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "Failed to read trace pipe: %s\n",
					strerror(errno));
				return stop_sched_ret(sched);
			}
		} else {
			ssize_t total_written = 0;

			while (total_written < total_read) {
				ssize_t written;

				written = write(STDOUT_FILENO, buf + total_written,
						total_read - total_written);
				if (written < 0) {
					if (errno != EINTR) {
						fprintf(stderr, "Failed to write to stdout: %s\n",
							strerror(errno));
						return stop_sched_ret(sched);
					}
				} else {
					total_written += written;
				}
			}
		}
	}

	return NULL;
}

static int spawn_trace_reader(struct rhone_sched *sched)
{
	pthread_attr_t attr;
	int ret;

	ret = initialize_pthread_attr(&attr, true, -1);
	if (ret) {
		fprintf(stderr, "Failed to init attr: %s\n", strerror(ret));
		return ret;
	}

	ret = pthread_create(&sched->trace_reader, &attr, run_trace_reader, sched);
	pthread_attr_destroy(&attr);
	if (ret)  {
		fprintf(stderr, "Failed to create trace reader: %s\n",
			strerror(ret));
	}

	return ret;
}

static void *run_stats_printer(void *arg)
{
	struct rhone_sched *sched = arg;
	struct rhone_prog *skel = sched->skel;

	while (!skel->bss->exiting) {
		unsigned long long nr_local_dispatched, nr_global_dispatched;
		unsigned long long nr_local_enqueued, nr_global_enqueued;
		unsigned long long nr_consumed;
		unsigned long long total_enqueued, total_dispatched;
		unsigned long long nr_global_dq_dispatched, nr_global_dq_consumed;

		nr_local_enqueued = skel->bss->nr_local_enqueued;
		nr_global_enqueued = skel->bss->nr_global_enqueued;
		total_enqueued = nr_local_enqueued + nr_global_enqueued;

		nr_local_dispatched = skel->bss->nr_local_dispatched;
		nr_global_dispatched = skel->bss->nr_global_dispatched;
		nr_global_dq_dispatched = skel->bss->nr_global_dq_dispatched;
		nr_consumed = skel->bss->nr_consumed;
		nr_global_dq_consumed = skel->bss->nr_global_dq_consumed;
		total_dispatched = nr_local_dispatched + nr_global_dispatched;

		printf("TOTAL:   %llu queued, %llu dispatched\n",
				 total_enqueued, total_dispatched);
		printf("GLOBAL:  %llu enqueued, %llu dispatched, %llu consumed\n",
				 nr_global_enqueued, nr_global_dispatched, nr_consumed);
		printf("LOCAL:   %llu enqueued, %llu dispatched\n",
				 nr_local_enqueued, nr_local_dispatched);
		printf("GLBL_DQ: %llu dispatched, %llu consumed\n",
				 nr_global_dq_dispatched, nr_global_dq_consumed);
		printf("KERNEL:  %llu local-enqueued\n", skel->bss->nr_kernel_tasks);
		printf("ERRORS:  %lu overflowed\n", skel->bss->nr_overflowed);
		printf("\n");
		sleep(1);
	}

	return NULL;
}

static int spawn_stats_printer(struct rhone_sched *sched)
{
	pthread_attr_t attr;
	int ret;

	ret = initialize_pthread_attr(&attr, true, -1);
	if (ret) {
		fprintf(stderr, "Failed to init attr: %s\n", strerror(ret));
		return ret;
	}

	ret = pthread_create(&sched->stats_printer, &attr, run_stats_printer, sched);
	pthread_attr_destroy(&attr);
	if (ret)  {
		fprintf(stderr, "Failed to create stats printer: %s\n", strerror(ret));
	}

	return ret;
}

static void kill_helper_thread(pthread_t thread)
{
	int err;
	void *retval;

	if (!thread)
		return;

	err = pthread_cancel(thread);
	if (err) {
		fprintf(stderr, "Failed to cancel helper thread %lu\n", thread);
		return;
	}


	err = pthread_join(thread, &retval);
	if (err)
		fprintf(stderr, "Helper thread %lu did not exit: %s\n", thread,
				strerror(errno));
}

static void free_ringbuffers(struct rhone_sched *sched)
{
	int i, n_ringbuffer_pairs = rhone_num_cpus;

	if (!sched->kprod_ringbuffers || !sched->uprod_ringbuffers)
		goto skip_freeing_inner;

	for (i = 0; i < n_ringbuffer_pairs; i++) {
		struct ring_buffer *kprod_rb = sched->kprod_ringbuffers[i];
		struct user_ring_buffer *uprod_rb = sched->uprod_ringbuffers[i];

		if (kprod_rb)
			ring_buffer__free(kprod_rb);

		if (uprod_rb)
			user_ring_buffer__free(uprod_rb);
	}

skip_freeing_inner:
	free(sched->kprod_ringbuffers);
	free(sched->uprod_ringbuffers);

	ring_buffer__free(sched->manager_rb);
}

static int create_percpu_ringbuffers(struct rhone_sched *sched)
{
	struct rhone_prog *skel;
	int i, ret = -ENOMEM;
	int kprod_rbs_outer_fd, uprod_rbs_outer_fd;
	LIBBPF_OPTS(bpf_map_create_opts, create_opts_rb);

	skel = sched->skel;
	kprod_rbs_outer_fd = bpf_map__fd(skel->maps.kprod_ringbuffers);
	uprod_rbs_outer_fd = bpf_map__fd(skel->maps.uprod_ringbuffers);

	if (kprod_rbs_outer_fd < 0 || uprod_rbs_outer_fd < 0) {
		fprintf(stderr,
				"Failed to get outer map fds: kprod: %d, uprod: %d\n",
				kprod_rbs_outer_fd, uprod_rbs_outer_fd);
		return kprod_rbs_outer_fd < 0 ? kprod_rbs_outer_fd :
			uprod_rbs_outer_fd;
	}

	/* Freed in free_ringbuffers(); */
	sched->kprod_ringbuffers = calloc(rhone_num_cpus, sizeof(struct ring_buffer *));
	sched->uprod_ringbuffers = calloc(rhone_num_cpus, sizeof(struct user_ring_buffer *));
	if (!sched->kprod_ringbuffers || !sched->uprod_ringbuffers) {
		fprintf(stderr, "Failed to allocate a ringbuffer array: %p, %p\n",
			sched->kprod_ringbuffers, sched->uprod_ringbuffers);
		return -ENOMEM;
	}

	for (i = 0; i < rhone_num_cpus; i++) {
		int inner_fd;

		inner_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0,
					  RHONE_PERCPU_RB_SIZE, &create_opts_rb);
		if (inner_fd < 0) {
			fprintf(stderr, "Failed to create kern rb %d (%d)\n", i, ret);
			return inner_fd;
		}

		ret = bpf_map_update_elem(kprod_rbs_outer_fd, &i, &inner_fd, 0);
		if (ret) {
			fprintf(stderr, "Insert kern rb fd %d (%d)\n", i, ret);
			close(inner_fd);
			return ret;
		}

		/* Freed in free_ringbuffers(); */
		sched->kprod_ringbuffers[i] =
			ring_buffer__new(inner_fd, handle_kern_event, sched, NULL);
		close(inner_fd);
		if (!sched->kprod_ringbuffers[i]) {
			fprintf(stderr, "Failed to create kern ringbuffer %d\n", i);
			return -errno;
		}

		inner_fd = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, NULL, 0,
					  0, RHONE_PERCPU_RB_SIZE, &create_opts_rb);
		if (inner_fd < 0) {
			fprintf(stderr, "Failed to create kern rb %d (%d)\n", i, ret);
			return inner_fd;
		}

		ret = bpf_map_update_elem(uprod_rbs_outer_fd, &i, &inner_fd, 0);
		if (ret) {
			fprintf(stderr, "Insert user rb fd %d (%d)\n", i, ret);
			close(inner_fd);
			return ret;
		}

		/* Freed in free_ringbuffers(); */
		sched->uprod_ringbuffers[i] = user_ring_buffer__new(inner_fd, NULL);
		close(inner_fd);
		if (!sched->uprod_ringbuffers[i]) {
			fprintf(stderr, "Failed to create user ringbuffer %d\n", i);
			return -errno;
		}
	}

	return 0;
}

static int create_manager_rb(struct rhone_sched *sched)
{
	struct rhone_prog *skel;
	int fd;

	skel = sched->skel;
	fd = bpf_map__fd(skel->maps.manager_rb);
	if (fd < 0) {
		fprintf(stderr, "Failed to get manager rb fd: %d\n", fd);
		return fd;
	}

	sched->manager_rb = ring_buffer__new(fd, handle_management_event, sched, NULL);
	if (!sched->manager_rb) {
		fprintf(stderr, "Failed to create manager rb: %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}

static int create_ringbuffers(struct rhone_sched *sched)
{
	int err;

	err = create_percpu_ringbuffers(sched);
	if (err) {
		fprintf(stderr, "Failed to create percpu ringbuffers: %d\n", err);
		return err;
	}

	err = create_manager_rb(sched);
	if (err) {
		fprintf(stderr, "Failed to create manager rb: %d\n", err);
		return err;
	}

	return 0;
}

static int bootstrap_user_skel(struct rhone_prog *skel)
{
	int err;

	err = bpf_map__set_max_entries(skel->maps.uprod_ringbuffers,
				       rhone_num_cpus);
	if (err) {
		fprintf(stderr, "Failed to set max uprod ringbuf entries\n");
		return err;
	}

	err = bpf_map__set_max_entries(skel->maps.kprod_ringbuffers,
				       rhone_num_cpus);
	if (err) {
		fprintf(stderr, "Failed to set max kprod ringbuf entries\n");
		return err;
	}

	err = bpf_map__set_max_entries(skel->maps.cpu_dq_map, rhone_num_cpus);
	if (err) {
		fprintf(stderr, "Failed to set max cpu for dq_id entries\n");
		return err;
	}

	err = bpf_map__set_max_entries(skel->maps.need_tasks_map, rhone_num_cpus);
	if (err) {
		fprintf(stderr, "Failed to set max cpu for need tasks entries\n");
		return err;
	}

	skel->bss->bootstrap_rb = BOOTSTRAP_RB;

	return 0;
}

static struct rhone_prog *open_load_rhone_skel(void)
{
	struct rhone_prog *skel;
	int err;

	skel = rhone_prog__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load: %s\n", strerror(errno));
		return NULL;
	}

	err = bootstrap_user_skel(skel);
	if (err) {
		fprintf(stderr, "Failed to bootstrap BPF scheduler skeleton: %d\n", err);
		goto destroy_skel;
	}

	err = rhone_prog__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF scheduler: %d\n", err);
		goto destroy_skel;
	}

	return skel;

destroy_skel:
	rhone_prog__destroy(skel);
	return NULL;
}

static bool domains_valid(struct rhone_domain **domains, unsigned num_domains)
{
	bool valid = false;
	unsigned i = 0;
	struct rhone_cpumask *test_mask = rhone_cpumask_create(NULL);

	if (!test_mask) {
		fprintf(stderr, "Failed to test cpumask: %s\n", strerror(ENOMEM));
		return false;
	}

	/* None of the domains may overlap. */
	for (i = 0; i < num_domains; i++) {
		struct rhone_domain *domain = domains[i];

		if (domain->sched)
			goto cleanup;

		if (rhone_cpumask_intersects(test_mask, domain->cpumask))
			goto cleanup;

		rhone_cpumask_or(test_mask, test_mask, domain->cpumask);
	}

	/* All the domains should in aggregate cover every CPU. */
	valid = rhone_cpumask_full(test_mask);

cleanup:
	rhone_cpumask_destroy(test_mask);
	return valid;
}

static void populate_cpu_domain_map(struct rhone_sched *sched)
{
	int cpu;
	unsigned i;

	for (cpu = 0; cpu < rhone_num_cpus; cpu++) {
		assert(sched->cpu_domain_map[cpu] == NULL);
		for (i = 0; i < sched->num_domains; i++) {
			struct rhone_domain *domain = sched->domains[i];

			if (rhone_cpumask_test_cpu(cpu, domain->cpumask)) {
				sched->cpu_domain_map[cpu] = domain;
				break;
			}
		}
		/*
		 * We validated that all domains collectively cover all CPUs in
		 * domains_valid(), so all CPUs should find their domain.
		 */
		assert(sched->cpu_domain_map[cpu] != NULL);
	}
}

static int initialize_need_tasks_map(struct rhone_sched *sched)
{
	int i, err;

	sched->need_tasks_map_fd = bpf_map__fd(sched->skel->maps.need_tasks_map);
	if (sched->need_tasks_map_fd < 0) {
		fprintf(stderr, "Failed to get need tasks map fd: %d\n", sched->need_tasks_map_fd);
		return sched->need_tasks_map_fd;
	}

	for (i = 0; i < rhone_num_cpus; i++) {
		__u32 key = i;
		__u8 needs_tasks = 0;

		err = bpf_map_update_elem(sched->need_tasks_map_fd, &key, &needs_tasks, 0);
		if (err) {
			fprintf(stderr, "Failed to set no tasks needed for %d\n", i);
			return err;
		}
	}

	return 0;
}

int rhone_sched_create(const char *name, const struct rhone_sched_ops *ops,
		       struct rhone_domain **domains,
		       unsigned num_domains,
		       const struct rhone_sched_config *config,
		       struct rhone_sched **out)
{
	struct rhone_sched *sched;
	int err = -ENOMEM;
	unsigned i;
	size_t domain_array_size = num_domains * sizeof(*domains);

	/* Freed in rhone_sched_destroy(). */
	sched = calloc(1, sizeof(struct rhone_sched));
	if (!sched)
		goto free_sched;

	sched->num_domains = num_domains;
	sched->domains = malloc(domain_array_size);
	if (!sched->domains)
		goto free_sched_pointers;

	sched->cpu_domain_map = calloc(rhone_num_cpus, sizeof(*domains));
	if (!sched->cpu_domain_map)
		goto free_sched_pointers;

	sched->tasks = calloc(rhone_max_tasks, sizeof(*sched->tasks));
	if (!sched->tasks)
		goto free_sched_pointers;

	err = pthread_spin_init(&sched->lock, PTHREAD_PROCESS_PRIVATE);
	if (err) {
		fprintf(stderr, "Failed to initialize spinlock: %s\n", strerror(err));
		goto free_sched_pointers;
	}

	if (!domains_valid(domains, num_domains)) {
		err = -EINVAL;
		goto destroy_lock;
	}
	memcpy(sched->domains, domains, domain_array_size);

	if (!ops->choose_task_domain) {
		fprintf(stderr, "choose_task_domain() callback not found\n");
		err = -EINVAL;
		goto destroy_lock;
	}
	memcpy(&sched->ops, ops, sizeof(sched->ops));

	populate_cpu_domain_map(sched);

	strncpy((char *)sched->name, name, RHONE_SCHED_NAME_SZ - 1);
	((char* )sched->name)[RHONE_SCHED_NAME_SZ - 1] = '\0';

	sched->skel = open_load_rhone_skel();
	if (!sched->skel) {
		fprintf(stderr, "Failed to open and load: %s\n", strerror(errno));
		err = -errno;
		goto destroy_lock;
	}
	sched->skel->bss->schedule_kernel_tasks = config->schedule_kernel_tasks;

	err = create_ringbuffers(sched);
	if (err) {
		fprintf(stderr, "Failed to create ringbuffers: %d\n", err);
		goto free_ringbuffers;
	}

	err = initialize_need_tasks_map(sched);
	if (err) {
		fprintf(stderr, "Failed to initialize need tasks map: %d\n", err);
		goto free_ringbuffers;
	}

	memcpy(&sched->config, config, sizeof(*config));

	*out = sched;
	return 0;

destroy_lock:
	pthread_spin_destroy(&sched->lock);
free_ringbuffers:
	free_ringbuffers(sched);
	rhone_prog__destroy(sched->skel);
free_sched_pointers:
	free(sched->domains);
	free(sched->cpu_domain_map);
	free(sched->tasks);
free_sched:
	for (i = 0; i < num_domains; i++)
		rhone_domain_destroy(domains[i]);
	free(sched);
	return err;
}

void rhone_sched_destroy(struct rhone_sched *sched)
{
	unsigned i;

	if (!sched)
		return;

	rhone_sched_stop(sched);
	free_ringbuffers(sched);
	rhone_prog__destroy(sched->skel);

	for (i = 0; i < sched->num_domains; i++)
		rhone_domain_destroy(sched->domains[i]);

	pthread_spin_destroy(&sched->lock);

	/* Allocated in rhone_sched_create(). */
	free(sched->domains);

	/* Allocated in rhone_sched_create(). */
	free(sched->cpu_domain_map);

	/* Allocated in rhone_sched_create(). */
	free(sched->tasks);

	/* Allocated in rhone_sched_create(). */
	free(sched);
}

static int write_bootstrap_messages(struct rhone_sched *sched)
{
	unsigned i;
	int cpu, cpu_dq_map_fd;
	struct user_ring_buffer *bootstrap_rb = sched->uprod_ringbuffers[BOOTSTRAP_RB];

	/* Bootstrap all of the dq ids in the kernel. */
	for (i = 0; i < sched->num_domains; i++) {
		struct rhone_domain *domain = sched->domains[i];
		struct rhone_bpf_user_bootstrap_msg *msg;

		domain->dq_id = i;
		msg = user_ring_buffer__reserve(bootstrap_rb, sizeof(*msg));

		if (!msg) {
			fprintf(stderr, "Failed to write bootstrap message: %s\n",
				strerror(errno));
			return -errno;
		}
		msg->dq_id = domain->dq_id;
		user_ring_buffer__submit(bootstrap_rb, msg);
	}

	/* Point CPU to its corresponding dq_id for every domain. */
	cpu_dq_map_fd = bpf_map__fd(sched->skel->maps.cpu_dq_map);
	for (cpu = 0; cpu < rhone_num_cpus; cpu++) {
		int key = cpu, err;
		struct rhone_domain *domain = sched->cpu_domain_map[cpu];
		__s64 dq_id = domain->dq_id;

		err = bpf_map_update_elem(cpu_dq_map_fd, &key, &dq_id, 0);
		if (err) {
			fprintf(stderr, "Failed to write dq map id\n");
			return err;
		}
	}

	return 0;
}

int rhone_sched_start(struct rhone_sched *sched, bool block)
{
	int err;
	struct rhone_sched *expected = NULL;

	if (!atomic_compare_exchange_strong(&active_sched, &expected, sched))
		return -EBUSY;

	err = write_bootstrap_messages(sched);
	if (err) {
		fprintf(stderr, "Failed to write bootstrap messages: %s\n", strerror(-err));
		goto cleanup;
	}

	err = spawn_sched_manager(sched);
	if (err) {
		fprintf(stderr, "Failed to spawn sched manager: %s\n", strerror(-err));
		goto cleanup;
	}

	if (sched->config.read_trace_pipe) {
		err = spawn_trace_reader(sched);
		if (err)
			fprintf(stderr, "Failed to spawn trace pipe reader: %s\n", strerror(-err));
	}

	if (sched->config.print_stats) {
		err = spawn_stats_printer(sched);
		if (err)
			fprintf(stderr, "Failed to spawn stats printer: %s\n", strerror(-err));
	}

	err = spawn_commanders(sched);
	if (err) {
		fprintf(stderr, "Failed to spawn commander threads: %s\n", strerror(-err));
		goto cleanup;
	}

	/* Attach the BPF program, thus starting the scheduler. */
	sched->link = bpf_map__attach_struct_ops(sched->skel->maps.rhone);
	if (!sched->link) {
		fprintf(stderr, "Failed to attach struct ops: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	while (block && sched_is_active(sched))
		pause();

	return 0;

cleanup:
	kill_helper_thread(sched->manager);
	destroy_commanders(sched);
	kill_helper_thread(sched->stats_printer);
	kill_helper_thread(sched->trace_reader);
	/*
	 * Set active_sched to NULL after killing all of the commanders and
	 * helper threads to prevent a race where future threads are spawned,
	 * and interfere with global state (thread-local ringbuffers for the
	 * commanders, double printing the trace_pipe for the trace reader,
	 * etc).
	 *
	 * Synchronizes with atomic_compare_exchange_strong() above.
	 */
	atomic_store_explicit(&active_sched, NULL, memory_order_release);

	return err;
}

int rhone_sched_stop(struct rhone_sched *sched)
{
	/* Synchronizes with atomic_compare_exchange_strong() in rhone_sched_start(). */
	if (!sched || !sched_is_active(sched))
		return -EINVAL;

	sched->skel->bss->exiting = true;
	destroy_commanders(sched);
	kill_helper_thread(sched->stats_printer);
	kill_helper_thread(sched->trace_reader);
	bpf_link__destroy(sched->link);
	sched->link = NULL;

	if (sched->ops.stopping)
		sched->ops.stopping(sched);
	fflush(NULL);

	/* Set active_sched to NULL after killing all of the commanders and
	 * helper threads to prevent a race where future threads are spawned,
	 * and interfere with global state (thread-local ringbuffers for the
	 * commanders, double printing the trace_pipe for the trace reader,
	 * etc).
	 *
	 * Synchronizes with atomic_compare_exchange_strong() in
	 * rhone_sched_start().
	 */
	atomic_store_explicit(&active_sched, NULL, memory_order_release);

	return 0;
}

struct rhone_sched_config *rhone_sched_config_create(void)
{
	/* Disable all helper threads by default. */
	return calloc(1, sizeof(struct rhone_sched_config));
}

void rhone_sched_config_destroy(struct rhone_sched_config *config)
{
	free(config);
}

void rhone_sched_config_set_trace_pipe(struct rhone_sched_config *config, bool trace_pipe)
{
	config->read_trace_pipe = trace_pipe;
}

void rhone_sched_config_set_print_stats(struct rhone_sched_config *config, bool print_stats)
{
	config->print_stats = print_stats;
}

void rhone_sched_config_set_schedule_kernel_tasks(struct rhone_sched_config *config, bool sched)
{
	config->schedule_kernel_tasks = sched;
}

static ssize_t proc_read_max_tasks(void)
{
	int fd;
	ssize_t max_tasks, bytes_read;

	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open pid_max in proc: %s\n", strerror(errno));
		return fd;
	}

	do {
		char buffer[64];

		bytes_read = read(fd, buffer, sizeof(buffer));
		if (bytes_read > 0)
			sscanf(buffer, "%ld", &max_tasks);
		else
			max_tasks = -errno;
	} while (bytes_read < 0 && errno == EINTR);

	close(fd);
	return max_tasks;
}

static void sigint_handler(int dummy)
{
	printf("Exiting rhone scheduler...\n");
	stop_sched_ret(get_active_sched());
}

static void __attribute__((constructor)) init_rhone_sched(void)
{
	ssize_t max_tasks;
	int err;

	rhone_num_cpus = libbpf_num_possible_cpus();
	if (rhone_num_cpus > MAX_CPUS) {
		fprintf(stderr, "Num cpus %u exceeds max %u\n", rhone_num_cpus, MAX_CPUS);
		exit(EXIT_FAILURE);
	}

	max_tasks = proc_read_max_tasks();
	if (max_tasks <= 0) {
		fprintf(stderr, "Unable to read max tasks: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	rhone_max_tasks = max_tasks;

	srand(time(NULL));
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	/*
	 * There are many paths in the scheduler where allocating is unsafe and
	 * can result in a system-wide deadlock. For example, on the enqueue
	 * path, if a scheduler task tries to allocate, it could trap into the
	 * kernel and require a reclaim task to make progress.
	 *
	 * For that reason, force *all* allocations to be both preallocated,
	 * and locked. Places where allocations are safe are called out
	 * explicitly as part of the scheduler APIs.
	 */
	err = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (err) {
		fprintf(stderr, "Failed to prefault and lock address space: %s\n", strerror(err));
		exit(EXIT_FAILURE);
	}
}
