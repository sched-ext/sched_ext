// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#include <errno.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "rhone_cpumask.h"
#include "rhone_domain.h"
#include "rhone_task.h"

struct rhone_domain *rhone_domain_create(struct rhone_domain_ops *ops,
					 void *context,
					 struct rhone_cpumask *cpumask)
{
	struct rhone_domain *domain = NULL;

	if (!ops->enqueue || !ops->dequeue || !ops->going_idle) {
		errno = EINVAL;
		goto fail;
	}

	domain = malloc(sizeof(struct rhone_domain));
	if (!domain) {
		errno = ENOMEM;
		goto fail;
	}

	memcpy(&domain->ops, ops, sizeof(*ops));
	domain->context = context;

	domain->cpumask = cpumask;

	return domain;
fail:
	rhone_cpumask_destroy(cpumask);
	free(domain);
	return NULL;
}

/**
 * Destroy a rhone domain.
 * @domain: The domain being removed.
 *
 * By the time this function returns, @domain may not be referenced.
 */
void rhone_domain_destroy(struct rhone_domain* domain)
{
	rhone_cpumask_destroy(domain->cpumask);

	free(domain);
}
