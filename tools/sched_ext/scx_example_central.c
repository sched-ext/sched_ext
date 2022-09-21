// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "scx_example_central.skel.h"

static volatile int exit_req;

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_example_central *skel;
	struct bpf_link *link;
	u64 seq = 0;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_example_central__open();
	if (!skel) {
		fprintf(stderr, "Failed to open: %s\n", strerror(errno));
		return 1;
	}

	skel->rodata->central_cpu = 0;
	skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();

	if (scx_example_central__load(skel)) {
		fprintf(stderr, "Failed to load: %s\n", strerror(errno));
		return 1;
	}

	link = bpf_map__attach_struct_ops(skel->maps.central_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach_struct_ops: %s\n",
			strerror(errno));
		return 1;
	}

	while (!exit_req && !skel->bss->exited) {
		printf("[SEQ %lu]\n", seq++);
		printf("total:%10lu    local:%10lu   queued:%10lu     lost:%10lu\n",
		       skel->bss->nr_total,
		       skel->bss->nr_locals,
		       skel->bss->nr_queued,
		       skel->bss->nr_lost_pids);
		printf("timer:%10lu dispatch:%10lu mismatch:%10lu overflow:%10lu\n",
		       skel->bss->nr_timers,
		       skel->bss->nr_dispatches,
		       skel->bss->nr_mismatches,
		       skel->bss->nr_overflows);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	scx_example_central__destroy(skel);

	return 0;
}
