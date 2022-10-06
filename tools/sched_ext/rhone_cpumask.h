/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022 Meta, Inc */
#ifndef __RHONE_CPUMASK_H
#define __RHONE_CPUMASK_H

#include <stdio.h>
#include <string.h>

#include <linux/bitmap.h>
#include <linux/bitops.h>

/* The number of CPUs supported for this rhone scheduler. */
extern int rhone_num_cpus;

struct rhone_cpumask {
	unsigned long bitmap;
};

#define cpumask_bitmap(_cpumask) (unsigned long *)(_cpumask)

struct rhone_cpumask *rhone_cpumask_create(const __u64 *bitmap);

void rhone_cpumask_destroy(struct rhone_cpumask *cpumask);

static inline int cpumask_check_warn(int cpu)
{
	if (unlikely(cpu >= rhone_num_cpus))
		fprintf(stderr, "Invalid cpu %d, max: %d\n", cpu, rhone_num_cpus);

	return cpu;
}

static inline size_t rhone_cpumask_num_entries(void)
{
	size_t cpus_per_entry;

	cpus_per_entry = sizeof(struct rhone_cpumask) * 8;

	/* Round up to the nearest entry size that could be required given hte
	 * # of CPUs on the system.
	 */
	return (rhone_num_cpus + cpus_per_entry - 1) / cpus_per_entry;
}

static inline void rhone_cpumask_set_cpu(int cpu, struct rhone_cpumask *cpumask)
{
	set_bit(cpumask_check_warn(cpu), cpumask_bitmap(cpumask));
}

static inline void rhone_cpumask_clear_cpu(int cpu, struct rhone_cpumask *cpumask)
{
	clear_bit(cpumask_check_warn(cpu), cpumask_bitmap(cpumask));
}

static inline bool rhone_cpumask_test_cpu(int cpu, struct rhone_cpumask *cpumask)
{
	return test_bit(cpumask_check_warn(cpu), cpumask_bitmap(cpumask));
}

static inline bool rhone_cpumask_intersects(struct rhone_cpumask *a,
					    struct rhone_cpumask *b)
{
	return bitmap_intersects(cpumask_bitmap(a), cpumask_bitmap(b), rhone_num_cpus);
}

static inline void rhone_cpumask_or(struct rhone_cpumask *dst,
				    struct rhone_cpumask *a,
				    struct rhone_cpumask *b)
{
	bitmap_or(cpumask_bitmap(dst), cpumask_bitmap(a), cpumask_bitmap(b),
		  rhone_num_cpus);
}

static inline bool rhone_cpumask_full(struct rhone_cpumask *cpumask)
{
	return bitmap_full(cpumask_bitmap(cpumask), rhone_num_cpus);
}

static inline void rhone_cpumask_setall(struct rhone_cpumask *cpumask)
{
	bitmap_fill(cpumask_bitmap(cpumask), rhone_num_cpus);
}

static inline void rhone_cpumask_clear(struct rhone_cpumask *cpumask)
{
	bitmap_zero(cpumask_bitmap(cpumask), rhone_num_cpus);
}

#endif  // __RHONE_CPUMASK_H
