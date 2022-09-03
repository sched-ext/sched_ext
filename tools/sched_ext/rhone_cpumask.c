#include <stdio.h>
#include <stdlib.h>

#include "rhone_cpumask.h"

struct rhone_cpumask *rhone_cpumask_create(const __u64 *bitmap)
{
	struct rhone_cpumask *cpumask;
	size_t bitmap_size = rhone_cpumask_num_entries() * sizeof(struct rhone_cpumask);

	cpumask = malloc(bitmap_size);
	if (!cpumask)
		return NULL;

	if (bitmap)
		memcpy(cpumask, bitmap, bitmap_size);
	else
		memset(cpumask, 0, bitmap_size);

	return cpumask;
}

void rhone_cpumask_destroy(struct rhone_cpumask *cpumask)
{
	free(cpumask);
}

/* Implementation of lib functions required by the rhone_cpumask subsystem. */

bool __bitmap_intersects(const unsigned long *bitmap1,
				       const unsigned long *bitmap2, unsigned int bits)
{
	unsigned int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap1[k] & bitmap2[k])
			return true;

	if (bits % BITS_PER_LONG)
		if ((bitmap1[k] & bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
			return true;
	return false;
}

void __bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
		 const unsigned long *bitmap2, int bits)
{
	unsigned int k;
	unsigned int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] | bitmap2[k];
}

/*
 * Find the first cleared bit in a memory region.
 */
unsigned long _find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}
