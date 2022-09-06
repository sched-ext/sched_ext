// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#ifndef __RHONE_BPF_INTERNAL_H
#define __RHONE_BPF_INTERNAL_H

/* The maximum size of a rhone scheduler name. */
#define RHONE_SCHED_NAME_SZ 32

/* The size of a per-cpu BPF ring buffer. */
#define RHONE_PERCPU_RB_SIZE 8192

/******************************************************************************
 *			Kernel -> user-space messages			      *
 *									      *
 * This section contains definitions for messages and message types which are *
 * delivered from the BPF program running in the kernel, to the tasks running *
 * user-space which make scheduling decisions. There are two types of	      *
 * kernel -> user-space messages:					      *
 *									      *
 * 1. Per-cpu messages which are sent directly to RT commander task.	      *
 * 2. Management messages which are sent to a specific RT manager task.       *
 *									      *
 * The former types of messages are used for informing the scheduler about    *
 * tasks being enqueued, and a CPU going idle.				      *
 *									      *
 * The latter types of messages are used for informing the scheduler about    *
 * global state change, such as new tasks being added and removed from the    *
 * scheduler. These messages are often messages that need to be consumed in   *
 * FIFO order, and may require larger payloads such as passing a task's       *
 * CPU-mask. For this reason, this ringbuffer is substantially larger in      *
 * size than the per-cpu ringbuffers.					      *
 *									      *
 ******************************************************************************/

/* The types of per-cpu kernel -> user-space messages. */
enum rhone_bpf_percpu_kernel_msg_type {
	RHONE_BPF_KERN_MSG_TASK_ENQUEUE,
	RHONE_BPF_KERN_MSG_NEED_TASKS,
};

/* Header that must be included in all per-cpu kernel -> user-space messages. */
struct rhone_bpf_kernel_percpu_msg_hdr {
	enum rhone_bpf_percpu_kernel_msg_type msg_type;
};

/*
 * Message that is sent when a task is being enqueued on a specific CPU.  If a
 * commander thread receives this message then the specified task is now owned
 * and tracked by rhone sched.
 */
struct rhone_bpf_kernel_enqueue_msg {
	struct rhone_bpf_kernel_percpu_msg_hdr hdr;
	__s32 pid;
	__u64 flags;
};

/*
 * Message that is sent when a CPU needs more tasks to run. If no tasks are
 * scheduled in the domain by the time this message handler completes, the
 * specified CPU will go idle until it is later kicked by another CPU.
 */
struct rhone_bpf_kernel_need_tasks_msg {
	struct rhone_bpf_kernel_percpu_msg_hdr hdr;
};

/*
 * The types of kernel -> user-space sched management messages. These messages
 * can come from multiple CPUs in the kernel scheduler, but are handled
 * exclusively by a single RT thread in the user-space scheduler.
 */
enum rhone_bpf_kernel_manage_msg_type {
	RHONE_BPF_MANAGE_MSG_TASK_ENABLE,
	RHONE_BPF_MANAGE_MSG_TASK_DISABLE,
};

struct rhone_bpf_kernel_manage_msg_hdr {
	enum rhone_bpf_kernel_manage_msg_type msg_type;
};

/* The maximum number of supported CPUs for the rhone scheduler.
 *
 * TODO: It shouldn't be necessary to use this macro, but the struct bpf_dynptr
 * APIs are a bit lacking in that you can't write data that was read from a
 * probed read to a variable length dynptr pointer, due to bpf_dynptr_data()
 * requiring a static, const offset, and only returning a read-only pointer.
 * bpf_dynptr_write() is also not suffificent as it requires a safe pointer to
 * read-only mem.
 */
#define MAX_CPUS 64
#define CPUS_PER_ENTRY (sizeof(__u64) * 8)
#define NUM_CPUMASK_ENTRIES (MAX_CPUS / CPUS_PER_ENTRY)

/*
 * A message that is received from the kernel when a new task is being enabled
 * in the scheduler. This message is sent exclusively on the single, global
 * management ringbuffer.
 *
 * The rhone BPF scheduler guarantees that this message will be delivered to
 * user-space before the corresponding disable message, though it does not
 * guarantee that the message will be delivered before the first enqueue
 * message. Such spurious enqueue messages are automatically dispatched to the
 * SCX_GLOBAL_DQ dq, and are not enqueued in a domain.
 */
struct rhone_bpf_kernel_task_enable_msg {
	struct rhone_bpf_kernel_manage_msg_hdr hdr;
	__s32 pid;
	__u8 name[RHONE_SCHED_NAME_SZ];
	__u64 cpumask[NUM_CPUMASK_ENTRIES];
};

/*
 * A message that is received from the kernel when a previously enabled task is
 * being disabled in the scheduler. This message is sent exclusively on the
 * single, global management ringbuffer.
 *
 * The rhone BPF scheduler guarantees that this message will be delivered to
 * user-space after the corresponding enable message, though it does not
 * guarantee that the message will be delivered before the last enqueue
 * message. Such spurious enqueue messages are automatically dropped by the
 * core rhone scheduler.
 */
struct rhone_bpf_kernel_task_disable_msg {
	struct rhone_bpf_kernel_manage_msg_hdr hdr;
	__s32 pid;
};

/******************************************************************************
 *			User-space -> kernel messages			      *
 *									      *
 * This section contains definitions for messages and message types which are *
 * delivered from user-space tasks running in the rhone scheduler, to the BPF *
 * scheduler running in the kernel.					      *
 *									      *
 * There are two types of user-space -> kernel messages:		      *
 *									      *
 * 1. Bootstrap messages which are sent by user-space before the BPF scheduler*
 * starts running, and which are consumed on the .init path.		      *
 * 2. Per-cpu messages containing scheduling decisions.			      *
 *									      *
 * The former types of messages are used to bootstrap the scheduler to e.g.   *
 * create dispatch queues.						      *
 *									      *
 * The latter types of messages are used for informing the BPF scheduler about*
 * scheduler decisions by indicating tasks that should be dispatched to a dq. *
 *									      *
 ******************************************************************************/

/* The types of per-cpu user-space -> kernel messages. */
enum rhone_bpf_user_msg_type {
	RHONE_BPF_USER_MSG_TASK_DISPATCH,
	RHONE_BPF_USER_MSG_TASK_UNKNOWN,
};

/* A message that is relevant to per-cpu scheduling decisions. */
struct rhone_bpf_user_sched_msg {
	enum rhone_bpf_user_msg_type msg_type;
	__s32 pid;
};

/* A bootstrap message sent before the BPF scheduler is started. */
struct rhone_bpf_user_bootstrap_msg {
	__s64 dq_id;
};

#endif  // __RHONE_BPF_INTERNAL_H
