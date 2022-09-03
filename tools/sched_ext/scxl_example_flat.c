// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <bpf/bpf.h>
#include "scxl_example_flat.h"
#include "scxl_example_flat.skel.h"

static volatile int exit_req;

static float read_cpu_util(__u64 *last_sum, __u64 *last_idle)
{
	FILE *fp;
	char buf[4096];
	char *line, *cur = NULL, *tok;
	__u64 sum = 0, idle = 0;
	__u64 delta_sum, delta_idle;
	int idx;

	fp = fopen("/proc/stat", "r");
	if (!fp) {
		perror("fopen(\"/proc/stat\")");
		return 0.0;
	}

	if (!fgets(buf, sizeof(buf), fp)) {
		perror("fgets(\"/proc/stat\")");
		fclose(fp);
		return 0.0;
	}
	fclose(fp);

	line = buf;
	for (idx = 0; (tok = strtok_r(line, " \n", &cur)); idx++) {
		char *endp = NULL;
		__u64 v;

		if (idx == 0) {
			line = NULL;
			continue;
		}
		v = strtoull(tok, &endp, 0);
		if (!endp || *endp != '\0') {
			fprintf(stderr, "failed to parse %dth field of /proc/stat (\"%s\")\n",
				idx, tok);
			continue;
		}
		sum += v;
		if (idx == 4)
			idle = v;
	}

	delta_sum = sum - *last_sum;
	delta_idle = idle - *last_idle;
	*last_sum = sum;
	*last_idle = idle;

	return delta_sum ? (float)(delta_sum - delta_idle) / delta_sum : 0.0;
}

static void read_lflat_stats(struct scxl_example_flat *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[FLAT_NR_STATS][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * FLAT_NR_STATS);

	for (idx = 0; idx < FLAT_NR_STATS; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static int flat_parse_domain(char *start, int dom, struct scxl_example_flat *skel)
{
	char *end;
	int base, len;
	char buf[17];

	/* trim leading "0x" */
	if (start[0] == '0' && start[1] == 'x')
		start += 2;

	for (end = start; *end; end++) {
		if (!isxdigit(*end))
			goto einval;
	}

	len = end - start;
	for (base = 0; base < len; base += 16) {
		char *endp;
		int cnt, bit;
		__u64 mask;

		cnt = len - base;
		cnt = cnt < 16 ? cnt : 16;
		memcpy(buf, end - base - cnt, len - base);
		buf[cnt] = '\0';

		mask = strtoull(buf, &endp, 16);
		if (*endp != '\0')
			goto einval;

		skel->rodata->dom_cpumasks[dom][base / 16] = mask;

		for (bit = 0; bit < 64; bit++) {
			int cpu = base / 16 * 64 + bit;

			if (!(mask & (1LLU << bit)))
				continue;

			if (skel->rodata->cpu_dom_id_map[cpu] != MAX_DOMS) {
				fprintf(stderr, "cpu%d is already assigned to dom%d and can't be assigned to dom%d\n",
					cpu, skel->rodata->cpu_dom_id_map[cpu], dom);
				return -EINVAL;
			}

			skel->rodata->cpu_dom_id_map[cpu] = dom;
			skel->bss->nr_cpu_ids = cpu + 1 > skel->bss->nr_cpu_ids ?
						cpu + 1 : skel->bss->nr_cpu_ids;
		}
	}

	return 0;
einval:
	fprintf(stderr, "invalid domain cpumask \"%s\"\n", start);
	return -EINVAL;
}

static void flat_dump_domains(struct scxl_example_flat *skel)
{
	int dom, cpu, i;

	for (dom = 0; dom < skel->rodata->nr_doms; dom++) {
		__u64 *mask = skel->rodata->dom_cpumasks[dom];

		printf("dom[%d] =", dom);
		for (i = (skel->bss->nr_cpu_ids + 63) / 64 - 1; i >= 0; i--)
			printf(" %016llx", mask[i]);
		printf("\n");
	}

	printf("cpu->dom:");
	for (cpu = 0; cpu < skel->bss->nr_cpu_ids; cpu++) {
		printf(" %d", skel->rodata->cpu_dom_id_map[cpu]);
	}
	printf("\n");
}


static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scxl_example_flat *skel;
	struct bpf_link *link;
	int i, ret = 1;
	__u64 last_cpu_sum = 0, last_cpu_idle = 0;
	__u64 last_stats[FLAT_NR_STATS];
	unsigned long seq = 0;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scxl_example_flat__open();
	if (!skel) {
		fprintf(stderr, "Failed to open: %s\n", strerror(errno));
		goto out;
	}

	for (i = 1; i < argc; i++) {
		char *tok = argv[i];
		char *key;

		key = strsep(&tok, "=");

		if (!strcmp(key, "slice_us")) {
			skel->rodata->slice_us = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "sleep_boost_pct")) {
			skel->rodata->sleep_boost_pct = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "skip_enqueue_min_slice_us")) {
			skel->rodata->skip_enqueue_min_slice_us = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "skip_enqueue_duration_us")) {
			skel->rodata->skip_enqueue_duration_us = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "domains")) {
			int cpu, dom = 0;
			char *v;

			for (cpu = 0; cpu < MAX_CPUS; cpu++)
				skel->rodata->cpu_dom_id_map[cpu] = MAX_DOMS;

			while ((v = strsep(&tok, ","))) {
				if (dom >= MAX_DOMS) {
					fprintf(stderr, "too many domains\n");
					goto out_destroy;
				}
				if (flat_parse_domain(v, dom++, skel))
					goto out_destroy;
			}
			skel->rodata->nr_doms = dom;
			flat_dump_domains(skel);
		} else if (!strcmp(key, "load_imbal_low_pct")) {
			skel->rodata->load_imbal_low_pct = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "load_imbal_high_pct")) {
			skel->rodata->load_imbal_high_pct = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "load_imbal_max_adj_pct")) {
			skel->rodata->load_imbal_max_adj_pct = strtoul(tok, NULL, 0);
		} else if (!strcmp(key, "greedy_threshold")) {
			skel->rodata->greedy_threshold = strtoul(tok, NULL, 0);
		} else {
			fprintf(stderr, "unknown parameter \"%s\"\n", key);
			goto out_destroy;
		}
	}

	if (skel->rodata->skip_enqueue_min_slice_us == (__u64)-1)
		skel->rodata->skip_enqueue_min_slice_us =
			skel->rodata->slice_us / 4;
	if (skel->rodata->skip_enqueue_duration_us == (__u64)-1)
		skel->rodata->skip_enqueue_duration_us =
			skel->rodata->slice_us * 2;

	ret = scxl_example_flat__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to load: %s\n", strerror(errno));
		goto out_destroy;
	}

	link = bpf_map__attach_struct_ops(skel->maps.lflat_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach_struct_ops: %s\n",
			strerror(errno));
		goto out_destroy;
	}

	printf("flat: slice_us=%llu sleep_boost_pct=%u\n"
	       "      skip_enqueue_min_slice_us=%llu skip_enqueue_duration_us=%llu\n"
	       "      load_imbal_low_pct=%u load_imbal_high_pct=%u\n"
	       "      load_imbal_max_adj_pct=%u greedy_threshold=%lld\n",
	       skel->rodata->slice_us,
	       skel->rodata->sleep_boost_pct,
	       skel->rodata->skip_enqueue_min_slice_us,
	       skel->rodata->skip_enqueue_duration_us,
	       skel->rodata->load_imbal_low_pct,
	       skel->rodata->load_imbal_high_pct,
	       skel->rodata->load_imbal_max_adj_pct,
	       skel->rodata->greedy_threshold);

	memset(last_stats, 0, sizeof(last_stats));
	while (!exit_req && !skel->bss->exit_type) {
		__u64 acc_stats[FLAT_NR_STATS];
		__u64 stats[FLAT_NR_STATS];
		__u64 total = 0;
		float cpu_util;
		int i;

		cpu_util = read_cpu_util(&last_cpu_sum, &last_cpu_idle);

		read_lflat_stats(skel, acc_stats);
		for (i = 0; i < FLAT_NR_STATS; i++)
			stats[i] = acc_stats[i] - last_stats[i];

		memcpy(last_stats, acc_stats, sizeof(acc_stats));

		for (i = 0; i < FLAT_STAT_NR_TOTAL; i++)
			total += stats[i];

		printf("\nSEQ %6lu cpu=%5.1lf\n", seq++, cpu_util * 100.0);
		printf("tot=%6llu byp=%5.1lf syn:dir:lst:skp=%4.1lf:%4.1lf:%4.1lf:%4.1lf dpl:exp:low=%4.1lf:%4.1lf:%4.1lf\n",
		       total,
		       100.0 * (total - stats[FLAT_STAT_ENQUEUED]) / total,
		       100.0 * stats[FLAT_STAT_WAKE_SYNC] / total,
		       100.0 * stats[FLAT_STAT_DIRECT_DISPATCH] / total,
		       100.0 * stats[FLAT_STAT_LAST_TASK] / total,
		       100.0 * stats[FLAT_STAT_SKIP] / total,
		       100.0 * stats[FLAT_STAT_SLICE_DEPLETED] / total,
		       100.0 * stats[FLAT_STAT_SKIP_EXPIRED] / total,
		       100.0 * stats[FLAT_STAT_SKIP_LOW_BUDGET] / total);
		if (skel->rodata->nr_doms > 1) {
			__u32 dom_id;

			printf("           load_avg=%.1f idle_pull:affn=%4.1lf:%4.1lf greedy=%4.1lf\n",
			       (float)skel->bss->global_load_avg / (1LLU << RAVG_FRAC_BITS),
			       100.0 * stats[FLAT_STAT_IDLE_PULL] / total,
			       100.0 * stats[FLAT_STAT_IDLE_PULL_AFFINITY] / total,
			       100.0 * stats[FLAT_STAT_GREEDY] / total);
			printf("           lb_pull:confl:empty:affn:low:skip=%4.1lf:%4.1lf:%4.1lf:%4.1lf:%4.1f:%4.1f\n",
			       100.0 * stats[FLAT_STAT_LB_PULL] / total,
			       100.0 * stats[FLAT_STAT_LB_PULL_CONFLICT] / total,
			       100.0 * stats[FLAT_STAT_LB_PULL_EMPTY] / total,
			       100.0 * stats[FLAT_STAT_LB_PULL_AFFINITY] / total,
			       100.0 * stats[FLAT_STAT_LB_PULL_LOW] / total,
			       100.0 * stats[FLAT_STAT_LB_PULL_SKIP] / total);
			for (dom_id = 0; dom_id < skel->rodata->nr_doms; dom_id++) {
				struct dom_ctx *domc = &skel->bss->dom_ctx[dom_id];
				int cpu_load_cnt = 0;
				__u32 cpu;

				printf("DOM[%02d]", dom_id);
				printf(" load=%5.1f", (float)domc->load / (1LLU << RAVG_FRAC_BITS));
				printf(" to_pull:give=%5.1f:%5.1f",
				       (float)domc->load_to_pull / (1LLU << RAVG_FRAC_BITS),
				       (float)domc->load_to_give / (1LLU << RAVG_FRAC_BITS));
				for (cpu = 0; cpu < skel->bss->nr_cpu_ids; cpu++) {
					if (skel->rodata->cpu_dom_id_map[cpu] == dom_id) {
						bool new_line = (cpu_load_cnt % 12) == 0;

						if (new_line)
							printf("\n        cpu_load=");
						printf("%s%5.1f", new_line ? "" : ":",
						       (float)skel->bss->pcpu_ctx[cpu].load /
						       (1LLU << RAVG_FRAC_BITS));
						cpu_load_cnt++;
					}
				}
				printf("\n");
			}
		}

		fflush(stdout);
		sleep(1);
	}

	if (skel->bss->exit_type)
		fprintf(stderr, "exit_type=%d msg=\"%s\"\n",
			skel->bss->exit_type, skel->bss->exit_msg);

	ret = 0;
	bpf_link__destroy(link);
out_destroy:
	scxl_example_flat__destroy(skel);
out:
	return ret;
}
