// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __ATROPOS_H
#define __ATROPOS_H

#include <stdbool.h>

#define	MAX_CPUS 512
#define	MAX_DOMS 64 /* limited to avoid complex bitmask ops */
#define	CACHELINE_SIZE 64

/* Statistics */
enum stat_idx {
	ATROPOS_STAT_TASK_GET_ERR,
	ATROPOS_STAT_TASK_GET_ERR_ENABLE,
	ATROPOS_STAT_CPUMASK_ERR,
	ATROPOS_STAT_WAKE_SYNC,
	ATROPOS_STAT_PREV_IDLE,
	ATROPOS_STAT_PINNED,
	ATROPOS_STAT_DIRECT_DISPATCH,
	ATROPOS_STAT_DSQ_DISPATCH,
	ATROPOS_STAT_GREEDY,
	ATROPOS_STAT_LOAD_BALANCE,
	ATROPOS_STAT_LAST_TASK,
	ATROPOS_NR_STATS,
};

struct task_ctx {
	unsigned long long dom_mask; /* the domains this task can run on */
	unsigned long long cpumask[MAX_CPUS / 64];
	unsigned int dom_id;
	unsigned int weight;
	bool dispatch_local;
};

#endif /* __ATROPOS_H */
