#ifndef __SCHED_EXTL_FLAT_H

#include "scx_ravg.h"

enum {
	MAX_CPUS		= 512,
	MAX_DOMS		= 64, /* limited to avoid complex bitmask ops */
	CACHELINE_SIZE		= 64,
	LB_INTERVAL_MS		= 100,
	MS_TO_NS		= 1000000LLU,
	LB_INTERVAL_NS		= LB_INTERVAL_MS * MS_TO_NS,
};

/* Statistics */
enum stat_idx {
	FLAT_STAT_WAKE_SYNC,
	FLAT_STAT_DIRECT_DISPATCH,
	FLAT_STAT_LAST_TASK,
	FLAT_STAT_ENQUEUED,
	FLAT_STAT_SKIP,

	FLAT_STAT_NR_TOTAL,

	FLAT_STAT_DEQUEUED = FLAT_STAT_NR_TOTAL,
	FLAT_STAT_DISPATCHED,

	FLAT_STAT_LB_PULL_CONFLICT,
	FLAT_STAT_LB_PULL_EMPTY,
	FLAT_STAT_LB_PULL_AFFINITY,
	FLAT_STAT_LB_PULL_LOW,
	FLAT_STAT_LB_PULL_SKIP,
	FLAT_STAT_LB_PULL,

	FLAT_STAT_IDLE_PULL_CONFLICT,
	FLAT_STAT_IDLE_PULL_EMPTY,
	FLAT_STAT_IDLE_PULL_AFFINITY,
	FLAT_STAT_IDLE_PULL,

	FLAT_STAT_GREEDY,

	FLAT_STAT_SLICE_DEPLETED,
	FLAT_STAT_SKIP_EXPIRED,
	FLAT_STAT_SKIP_LOW_BUDGET,

	FLAT_NR_STATS,
};

struct dom_ctx {
	__u64			load;		/* last load read by the lb timer */

	__u32			lb_seq;
	__u32			lb_cadence_shift;

	__u64			load_to_pull;
	__u64			load_pulled;
	__u64			load_to_give;
};

/*
 * Per-cpu context
 *
 * bpf_map_lookup_percpu_elem() isn't available yet. Do a custom implementation
 * with an array with cacheline aligned members.
 */
struct pcpu_ctx {
	long			syscall_id;	/* the last syscall # */

	__u32			dom_rr_cur;	/* used when scanning other doms */

	/*
	 * Per-CPU load. We track each change in total weight runnable on the
	 * CPU and accumulate on each change instead of accumulating per-task on
	 * dispatch (or some other event) which would be simpler. This is to
	 * allow reading up-to-date load value from the lb timer.
	 */
	struct ravg_data	load_data;

	__u64			load;		/* last load read by the lb timer */
} __attribute__ ((aligned(CACHELINE_SIZE)));

#endif /* __SCHED_EXTL_FLAT_H */
