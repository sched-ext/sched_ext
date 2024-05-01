/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_BPF_H
#define __SCX_COMPAT_BPF_H

/*
 * scx_switch_all() was replaced by %SCX_OPS_SWITCH_PARTIAL. See
 * %__COMPAT_SCX_OPS_SWITCH_PARTIAL in compat.h. This can be dropped in the
 * future.
 */
void scx_bpf_switch_all(void) __ksym __weak;

static inline void __COMPAT_scx_bpf_switch_all(void)
{
	if (!bpf_core_enum_value_exists(enum scx_ops_flags, SCX_OPS_SWITCH_PARTIAL))
		scx_bpf_switch_all();
}

/*
 * scx_bpf_exit() is a new addition. Fall back to scx_bpf_error() if
 * unavailable. Users can use scx_bpf_exit() directly in the future.
 */
#define __COMPAT_scx_bpf_exit(code, fmt, args...)				\
({										\
	if (bpf_ksym_exists(scx_bpf_exit_bstr))					\
		scx_bpf_exit((code), fmt, args);				\
	else									\
		scx_bpf_error(fmt, args);					\
})

/*
 * scx_bpf_nr_cpu_ids(), scx_bpf_get_possible/online_cpumask() are new. No good
 * way to noop these kfuncs. Provide a test macro. Users can assume existence in
 * the future.
 */
#define __COMPAT_HAS_CPUMASKS							\
	bpf_ksym_exists(scx_bpf_nr_cpu_ids)

/*
 * Define sched_ext_ops. This may be expanded to define multiple variants for
 * backward compatibility. See compat.h::SCX_OPS_LOAD/ATTACH().
 */
#define SCX_OPS_DEFINE(__name, ...)						\
	SEC(".struct_ops.link")							\
	struct sched_ext_ops __name = {						\
		__VA_ARGS__,							\
	};

#endif	/* __SCX_COMPAT_BPF_H */
