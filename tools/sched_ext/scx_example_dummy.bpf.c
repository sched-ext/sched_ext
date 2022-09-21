// SPDX-License-Identifier: GPL-2.0
#include "scx_common.h"

char _license[] SEC("license") = "GPL";

long nr_enqueued;
bool exited = false;

enum {
	DUMMY_DQ_ID		= 0,
};

s32 BPF_STRUCT_OPS(dummy_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;
}

s64 BPF_STRUCT_OPS(dummy_enqueue, struct task_struct *p, u64 enq_flags)
{
	__sync_fetch_and_add(&nr_enqueued, 1);
	return DUMMY_DQ_ID;
}

void BPF_STRUCT_OPS(dummy_consume, s32 cpu)
{
	scx_bpf_consume(DUMMY_DQ_ID);
}

s32 BPF_STRUCT_OPS(dummy_init)
{
	return scx_bpf_create_dq(DUMMY_DQ_ID, -1);
}

void BPF_STRUCT_OPS(dummy_exit, struct scx_ops_exit_info *ei)
{
	exited = true;
}

SEC(".struct_ops")
struct sched_ext_ops dummy_ops = {
	.select_cpu		= (void *)dummy_select_cpu,
	.enqueue		= (void *)dummy_enqueue,
	.consume		= (void *)dummy_consume,
	.init			= (void *)dummy_init,
	.exit			= (void *)dummy_exit,
	.name			= "dummy",
};
