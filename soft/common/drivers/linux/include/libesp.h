/*
 * Copyright (c) 2011-2021 Columbia University, System Level Design Group
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __ESPLIB_H__
#define __ESPLIB_H__
#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "my_stringify.h"
#include "fixed_point.h"
#include "contig.h"
#include "esp.h"
#include "test/time.h"
#include "test/test.h"

#include <esp.h>
#include <esp_accelerator.h>

#include "monitors.h"

unsigned DMA_WORD_PER_BEAT(unsigned _st);

typedef struct esp_accelerator_thread_info {
	bool run;
	char *devname;
	void *hw_buf;
	int ioctl_req;
	/* Partially Filled-in by ESPLIB */
	struct esp_access *esp_desc;
	/* Filled-in by ESPLIB */
	int fd;
	unsigned long long hw_ns;
} esp_thread_info_t;

typedef struct buf2handle_node {
	void *buf;
	contig_handle_t *handle;
	enum contig_alloc_policy policy;
	struct buf2handle_node *next;
} buf2handle_node;

struct thread_args {
	esp_thread_info_t* info;
	unsigned nacc;
};

void *esp_alloc_policy(struct contig_alloc_params params, size_t size);
void *esp_alloc(size_t size);
void esp_run_parallel(esp_thread_info_t* cfg[], unsigned nthreads, unsigned* nacc);
void esp_run(esp_thread_info_t cfg[], unsigned nacc);
void esp_free(void *buf);
unsigned int esp_monitor(esp_monitor_args_t args, esp_monitor_vals_t *vals);
esp_monitor_vals_t* esp_monitor_vals_alloc();
void esp_monitor_free();
esp_monitor_vals_t esp_monitor_diff(esp_monitor_vals_t vals_start, esp_monitor_vals_t vals_end);
void esp_monitor_print(esp_monitor_args_t args, esp_monitor_vals_t vals, FILE* fp);
uint32_t sub_monitor_vals (uint32_t val_start, uint32_t val_end);

#endif /* __ESPLIB_H__ */
