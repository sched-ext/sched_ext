// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <bpf/bpf.h>
#include "scx_example_pair.h"
#include "scx_example_pair.skel.h"

static volatile int exit_req;

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_example_pair *skel;
	struct bpf_link *link;
	u64 seq = 0;
	s32 stride, i, opt, outer_fd;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_example_pair__open();
	if (!skel) {
		fprintf(stderr, "Failed to open: %s\n", strerror(errno));
		return 1;
	}

	skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();

	/* pair up the earlier half to the latter by default, override with -s */
	stride = skel->rodata->nr_cpu_ids / 2;

	while ((opt = getopt(argc, argv, "hs:")) != -1) {
		switch (opt) {
		case 's':
			stride = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			fprintf(stderr, "usage: %s [-s <stride>]\n", argv[0]);
		return opt != 'h';
		}
	}

	for (i = 0; i < skel->rodata->nr_cpu_ids; i++) {
		if (skel->rodata->pair_cpu[i] < 0) {
			skel->rodata->pair_cpu[i] = i + stride;
			skel->rodata->pair_cpu[i + stride] = i;
			skel->rodata->pair_id[i] = i;
			skel->rodata->pair_id[i + stride] = i;
			skel->rodata->in_pair_idx[i] = 0;
			skel->rodata->in_pair_idx[i + stride] = 1;
		}
	}

	if (scx_example_pair__load(skel)) {
		fprintf(stderr, "Failed to load: %s\n", strerror(errno));
		return 1;
	}

	/*
	 * Populate the cgrp_q_arr map which is an array containing per-cgroup
	 * queues. It'd probably be better to do this from BPF but there are too
	 * many to initialize statically and there's no way to dynamically
	 * populate from BPF.
	 */
	outer_fd = bpf_map__fd(skel->maps.cgrp_q_arr);
	if (outer_fd < 0) {
		fprintf(stderr, "Failed to get fd for cgrp_q_arr: %s\n", strerror(errno));
		return 1;
	}

        for (i = 0; i < MAX_CGRPS; i++) {
		s32 inner_fd;

		inner_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, NULL, 0,
					  sizeof(u32), MAX_QUEUED, NULL);
		if (inner_fd < 0) {
			fprintf(stderr, "Failed to create cgrp_q: %s\n", strerror(errno));
			return 1;
		}
		if (bpf_map_update_elem(outer_fd, &i, &inner_fd, BPF_ANY)) {
			fprintf(stderr, "Failed to install cgrp_q: %s\n", strerror(errno));
			return 1;
		}
		close(inner_fd);
        }

	/*
	 * Fully initialized, attach and run.
	 */
	link = bpf_map__attach_struct_ops(skel->maps.pair_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach_struct_ops: %s\n",
			strerror(errno));
		return 1;
	}

	while (!exit_req && !skel->bss->exited) {
		printf("[SEQ %lu]\n", seq++);
		printf(" total:%10lu dispatch:%10lu   missing:%10lu kicks:%10lu\n",
		       skel->bss->nr_total,
		       skel->bss->nr_dispatched,
		       skel->bss->nr_missing,
		       skel->bss->nr_kicks);
		printf("   exp:%10lu exp_wait:%10lu exp_empty:%10lu\n",
		       skel->bss->nr_exps,
		       skel->bss->nr_exp_waits,
		       skel->bss->nr_exp_empty);
		printf("cgnext:%10lu   cgcoll:%10lu   cgempty:%10lu\n",
		       skel->bss->nr_cgrp_next,
		       skel->bss->nr_cgrp_coll,
		       skel->bss->nr_cgrp_empty);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	scx_example_pair__destroy(skel);

	return 0;
}
