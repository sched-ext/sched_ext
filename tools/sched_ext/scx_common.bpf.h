/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef __SCHED_EXT_COMMON_BPF_H
#define __SCHED_EXT_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include "user_exit_info.h"

/*
 * Earlier versions of clang/pahole lost upper 32bits in 64bit enums which can
 * lead to really confusing misbehaviors. Let's trigger a build failure.
 */
static inline void ___vmlinux_h_sanity_check___(void)
{
	_Static_assert(SCX_DSQ_FLAG_BUILTIN,
		       "bpftool generated vmlinux.h is missing high bits for 64bit enums, upgrade clang and pahole");
}

extern void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym;

static inline __attribute__((format(printf, 1, 2)))
void ___scx_bpf_error_format_checker(const char *fmt, ...) {}

/*
 * scx_bpf_error() wraps the scx_bpf_error_bstr() kfunc with variadic arguments
 * instead of an array of u64. Note that __param[] must have at least one
 * element to keep the verifier happy.
 */
#define scx_bpf_error(fmt, args...)						\
({										\
	static char ___fmt[] = fmt;						\
	unsigned long long ___param[___bpf_narg(args) ?: 1] = {};		\
										\
	_Pragma("GCC diagnostic push")						\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")			\
	___bpf_fill(___param, args);						\
	_Pragma("GCC diagnostic pop")						\
										\
	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));			\
										\
	___scx_bpf_error_format_checker(fmt, ##args);				\
})

extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern bool scx_bpf_consume(u64 dsq_id) __ksym;
extern u32 scx_bpf_dispatch_nr_slots(void) __ksym;
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;
extern bool scx_bpf_test_and_clear_cpu_idle(s32 cpu) __ksym;
extern s32 scx_bpf_pick_idle_cpu(const cpumask_t *cpus_allowed) __ksym;
extern void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;
extern bool scx_bpf_task_running(const struct task_struct *p) __ksym;
extern s32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;

/* XXX - temporary ones to be replaced by generic BPF helpers */
extern struct cgroup *scx_bpf_task_cgroup(const struct task_struct *p) __ksym;
extern struct task_struct *scx_bpf_find_task_by_pid(s32 pid) __ksym;
extern s32 scx_bpf_pick_idle_cpu_untyped(unsigned long cpus_allowed) __ksym;
extern bool scx_bpf_has_idle_cpus_among(const struct cpumask *cpus_allowed) __ksym;
extern bool scx_bpf_has_idle_cpus_among_untyped(unsigned long cpus_allowed) __ksym;
extern s32 scx_bpf_cpumask_test_cpu(s32 cpu, const struct cpumask *cpumask) __ksym;
extern s32 scx_bpf_cpumask_first(const struct cpumask *cpus_allowed) __ksym;
extern s32 scx_bpf_cpumask_first_untyped(unsigned long cpus_allowed) __ksym;
extern bool scx_bpf_cpumask_intersects(const struct cpumask *src1p, const struct cpumask *src2p) __ksym;

#define PF_KTHREAD			0x00200000	/* I am a kernel thread */
#define PF_EXITING			0x00000004
#define CLOCK_MONOTONIC			1

#define BPF_STRUCT_OPS(name, args...)						\
SEC("struct_ops/"#name)								\
BPF_PROG(name, ##args)

/**
 * MEMBER_VPTR - Obtain the verified pointer to a struct or array member
 * @base: struct or array to index
 * @member: dereferenced member (e.g. ->field, [idx0][idx1], ...)
 *
 * The verifier often gets confused by the instruction sequence the compiler
 * generates for indexing struct fields or arrays. This macro forces the
 * compiler to generate a code sequence which first calculates the byte offset,
 * checks it against the struct or array size and add that byte offset to
 * generate the pointer to the member to help the verifier.
 *
 * Ideally, we want to abort if the calculated offset is out-of-bounds. However,
 * BPF currently doesn't support abort, so evaluate to NULL instead. The caller
 * must check for NULL and take appropriate action to appease the verifier. To
 * avoid confusing the verifier, it's best to check for NULL and dereference
 * immediately.
 *
 *	vptr = MEMBER_VPTR(my_array, [i][j]);
 *	if (!vptr)
 *		return error;
 *	*vptr = new_value;
 */
#define MEMBER_VPTR(base, member) (typeof(base member) *)({			\
	u64 __base = (u64)base;							\
	u64 __addr = (u64)&(base member) - __base;				\
	asm volatile (								\
		"if %0 <= %[max] goto +2\n"					\
		"%0 = 0\n"							\
		"goto +1\n"							\
		"%0 += %1\n"							\
		: "+r"(__addr)							\
		: "r"(__base),							\
		  [max]"i"(sizeof(base) - sizeof(base member)));		\
	__addr;									\
})

#endif	/* __SCHED_EXT_COMMON_BPF_H */
