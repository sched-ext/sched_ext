// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta, Inc */

#ifndef __RHONE_INTERNAL_H
#define __RHONE_INTERNAL_H

#include <bpf/bpf.h>

extern __thread int my_cpu;
extern __thread struct ring_buffer *my_kprod_rb;
extern __thread struct user_ring_buffer *my_uprod_rb;

#endif  /* __RHONE_INTERNAL_H */
