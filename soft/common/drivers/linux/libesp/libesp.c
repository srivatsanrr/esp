/*
 * Copyright (c) 2011-2021 Columbia University, System Level Design Group
 * SPDX-License-Identifier: Apache-2.0
 */

#include "libesp.h"
#include "soc_locs.h"

buf2handle_node *head = NULL;
void *monitor_base_ptr = NULL;
void *mon_alloc_head = NULL;
int mapped = 0;

void insert_buf(void *buf, contig_handle_t *handle, enum contig_alloc_policy policy)
{
	buf2handle_node *new = malloc(sizeof(buf2handle_node));
	new->buf = buf;
	new->handle = handle;
	new->policy = policy;

	new->next = head;
	head = new;
}

contig_handle_t* lookup_handle(void *buf, enum contig_alloc_policy *policy)
{
	buf2handle_node *cur = head;
	while (cur != NULL) {
		if (cur->buf == buf) {
			if (policy != NULL)
				*policy = cur->policy;
			return cur->handle;
		}
		cur = cur->next;
	}
	die("buf not in active allocations\n");
}

void remove_buf(void *buf)
{
	buf2handle_node *cur = head;
	if (cur->buf == buf) {
		head = cur->next;
		contig_free(*(cur->handle));
		free(cur);
		return;
	}

	buf2handle_node *prev;
	while (cur != NULL && cur->buf != buf) {
		prev = cur;
		cur = cur->next;
	}

	if (cur == NULL)
		die("buf not in active allocations\n");

	prev->next = cur->next;
	contig_free(*(cur->handle));
	free(cur->handle);
	free(cur);
}

bool thread_is_p2p(esp_thread_info_t *thread)
{
	return ((thread->esp_desc)->p2p_store || (thread->esp_desc)->p2p_nsrcs);
}

unsigned DMA_WORD_PER_BEAT(unsigned _st)
{
	return (sizeof(void *) / _st);
}

void *accelerator_thread( void *ptr )
{
	esp_thread_info_t *info = (esp_thread_info_t *) ptr;
	struct timespec th_start;
	struct timespec th_end;
	int rc = 0;

	gettime(&th_start);
	rc = ioctl(info->fd, info->ioctl_req, info->esp_desc);
	gettime(&th_end);
	if (rc < 0) {
		perror("ioctl");
	}

	info->hw_ns = ts_subtract(&th_start, &th_end);

	return NULL;
}

void *accelerator_thread_p2p(void *ptr)
{
	struct thread_args *args = (struct thread_args*) ptr;
	esp_thread_info_t *thread = args->info;
	unsigned nacc = args->nacc;
	int rc = 0;
	int i;

	pthread_t *threads = malloc(nacc * sizeof(pthread_t));

	for (i = 0; i < nacc; i++) {
		esp_thread_info_t *info = thread + i;
		if (!info->run)
			continue;
		rc = pthread_create(&threads[i], NULL, accelerator_thread, (void*) info);
		if (rc != 0)
			perror("pthread_create");
	}

	for (i = 0; i < nacc; i++) {
		esp_thread_info_t *info = thread + i;
		if (!info->run)
			continue;
		rc = pthread_join(threads[i], NULL);
		if (rc != 0)
			perror("pthread_join");
		close(info->fd);
	}
	free(threads);
	free(ptr);
	return NULL;
}

void *accelerator_thread_serial(void *ptr)
{
	struct thread_args *args = (struct thread_args*) ptr;
	esp_thread_info_t *thread = args->info;
	unsigned nacc = args->nacc;
	int i;
	for (i = 0; i < nacc; i++) {

		struct timespec th_start;
		struct timespec th_end;
		int rc = 0;
		esp_thread_info_t *info = thread + i;

		if (!info->run)
			continue;

		gettime(&th_start);
		rc = ioctl(info->fd, info->ioctl_req, info->esp_desc);
		gettime(&th_end);
		if (rc < 0) {
			perror("ioctl");
		}

		info->hw_ns = ts_subtract(&th_start, &th_end);
		close(info->fd);
	}
	free(ptr);
	return NULL;
}

void *esp_alloc_policy(struct contig_alloc_params params, size_t size)
{
	contig_handle_t *handle = malloc(sizeof(contig_handle_t));
	void* contig_ptr = contig_alloc_policy(params, size, handle);
	insert_buf(contig_ptr, handle, params.policy);
	return contig_ptr;
}

void *esp_alloc(size_t size)
{
	contig_handle_t *handle = malloc(sizeof(contig_handle_t));
	void* contig_ptr = contig_alloc(size, handle);
	insert_buf(contig_ptr, handle, CONTIG_ALLOC_PREFERRED);
	return contig_ptr;
}

static void esp_config(esp_thread_info_t* cfg[], unsigned nthreads, unsigned *nacc)
{
	int i, j;
	for (i = 0; i < nthreads; i++) {
		unsigned len = nacc[i];
		for(j = 0; j < len; j++) {
			esp_thread_info_t *info = cfg[i] + j;
			if (!info->run)
				continue;

			enum contig_alloc_policy policy;
			contig_handle_t *handle = lookup_handle(info->hw_buf, &policy);

			(info->esp_desc)->contig = contig_to_khandle(*handle);
			(info->esp_desc)->ddr_node = contig_to_most_allocated(*handle);
			(info->esp_desc)->alloc_policy = policy;
			(info->esp_desc)->run = true;
		}
	}
}

static void print_time_info(esp_thread_info_t *info[], unsigned long long hw_ns, int nthreads, unsigned* nacc)
{
	int i, j;

	printf("  > Test time: %llu ns\n", hw_ns);
	for (i = 0; i < nthreads; i++) {
		unsigned len = nacc[i];
		for (j = 0; j < len; j++) {
			esp_thread_info_t* cur = info[i] + j;
			if (cur->run)
				printf("    - %s time: %llu ns\n", cur->devname, cur->hw_ns);
		}
	}
}

void esp_run(esp_thread_info_t cfg[], unsigned nacc)
{
	int i;

	if (thread_is_p2p(&cfg[0])) {
		esp_thread_info_t *cfg_ptrs[1];
		cfg_ptrs[0] = cfg;

		esp_run_parallel(cfg_ptrs, 1, &nacc);
	} else{
		esp_thread_info_t **cfg_ptrs = malloc(sizeof(esp_thread_info_t*) * nacc);
		unsigned *nacc_arr = malloc(sizeof(unsigned) * nacc);

		for (i = 0; i < nacc; i++) {
			nacc_arr[i] = 1;
			cfg_ptrs[i] = &cfg[i];
		}
		esp_run_parallel(cfg_ptrs, nacc, nacc_arr);
		free(nacc_arr);
		free(cfg_ptrs);
	}
}

void esp_run_parallel(esp_thread_info_t* cfg[], unsigned nthreads, unsigned* nacc)
{
	int i, j;
	struct timespec th_start;
	struct timespec th_end;
	pthread_t *thread = malloc(nthreads * sizeof(pthread_t));
	int rc = 0;
	esp_config(cfg, nthreads, nacc);
	for (i = 0; i < nthreads; i++) {
		unsigned len = nacc[i];
		for (j = 0; j < len; j++) {
			esp_thread_info_t *info = cfg[i] + j;
			const char *prefix = "/dev/";
			char path[70];

			if (strlen(info->devname) > 64) {
				contig_handle_t *handle = lookup_handle(info->hw_buf, NULL);
				contig_free(*handle);
				die("Error: device name %s exceeds maximum length of 64 characters\n",
				    info->devname);
			}

			sprintf(path, "%s%s", prefix, info->devname);

			info->fd = open(path, O_RDWR, 0);
			if (info->fd < 0) {
				contig_handle_t *handle = lookup_handle(info->hw_buf, NULL);
				contig_free(*handle);
				die_errno("fopen failed\n");
			}
		}
	}

	gettime(&th_start);
	for (i = 0; i < nthreads; i++) {
		struct thread_args *args = malloc(sizeof(struct thread_args));;
		args->info = cfg[i];
		args->nacc = nacc[i];

		if (thread_is_p2p(cfg[i]))
			rc = pthread_create(&thread[i], NULL, accelerator_thread_p2p, (void*) args);
		else
			rc = pthread_create(&thread[i], NULL, accelerator_thread_serial, (void*) args);

		if(rc != 0) {
			perror("pthread_create");
		}
	}

	for (i = 0; i < nthreads; i++) {
		rc = pthread_join(thread[i], NULL);

		if(rc != 0) {
			perror("pthread_join");
		}
	}

	gettime(&th_end);
	print_time_info(cfg, ts_subtract(&th_start, &th_end), nthreads, nacc);

	free(thread);
}


void esp_free(void *buf)
{
	remove_buf(buf);
}

/***************************************************************************
 *
 * MONITORS API
 *
 **************************************************************************/

void mmap_monitors()
{
    int fd = open("/dev/mem", O_RDWR);
    monitor_base_ptr = mmap(NULL, SOC_ROWS * SOC_COLS * MONITOR_TILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MONITOR_BASE_ADDR);
    close(fd);
}

void munmap_monitors()
{
    munmap(monitor_base_ptr, SOC_ROWS * SOC_COLS * MONITOR_TILE_SIZE);
}

unsigned int read_monitor(int tile_no, int mon_no)
{
    unsigned int offset = (MONITOR_TILE_SIZE / sizeof(unsigned int)) * tile_no;
    unsigned int *addr = ((unsigned int *) monitor_base_ptr) + offset + mon_no + 1;
    return *addr;
}

void write_burst_reg(int tile_no, int val)
{
    unsigned int offset = (MONITOR_TILE_SIZE / sizeof(unsigned int)) * tile_no;
    unsigned int *addr = ((unsigned int *) monitor_base_ptr) + offset;
    *addr = val;
}

unsigned int esp_monitor(esp_monitor_args_t args, esp_monitor_vals_t *vals)
{
    int t, p, q;
    unsigned int tile;

    if (!mapped) {
        mmap_monitors();
        mapped = 1;
    }

    if (args.read_mode == ESP_MON_READ_SINGLE){

        return read_monitor(args.tile_index, args.mon_index);

    } else if (args.read_mode == ESP_MON_READ_ALL){

        for (t = 0; t < SOC_NTILES; t++)
            write_burst_reg(t, 1);

#ifdef __riscv
        __asm__ __volatile__("fence\n");
#else
        __asm__ __volatile__("membar\n");
#endif
    	//ddr accesses
        for (t = 0; t < SOC_NMEM; t++)
            vals->ddr_accesses[t] = read_monitor(mem_locs[t].row * SOC_COLS + mem_locs[t].col, MON_DDR_WORD_TRANSFER_INDEX);

        //mem_reqs
        for (t = 0; t < SOC_NMEM; t++){
            tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
            vals->mem_reqs[t].coh_reqs = read_monitor(tile, MON_MEM_COH_REQ_INDEX);
            vals->mem_reqs[t].coh_fwds = read_monitor(tile, MON_MEM_COH_FWD_INDEX);
            vals->mem_reqs[t].coh_rsps_rcv = read_monitor(tile, MON_MEM_COH_RSP_RCV_INDEX);
            vals->mem_reqs[t].coh_rsps_snd = read_monitor(tile, MON_MEM_COH_RSP_SND_INDEX);
            vals->mem_reqs[t].dma_reqs = read_monitor(tile, MON_MEM_DMA_REQ_INDEX);
            vals->mem_reqs[t].dma_rsps = read_monitor(tile, MON_MEM_DMA_RSP_INDEX);
            vals->mem_reqs[t].coh_dma_reqs = read_monitor(tile, MON_MEM_COH_DMA_REQ_INDEX);
            vals->mem_reqs[t].coh_dma_rsps = read_monitor(tile, MON_MEM_COH_DMA_RSP_INDEX);
        }

        //l2 stats
        for (t = 0; t < SOC_NCPU; t++) {
            tile = cpu_locs[t].row * SOC_COLS + cpu_locs[t].col;
            vals->l2_stats[tile].hits = read_monitor(tile, MON_L2_HIT_INDEX);
            vals->l2_stats[tile].misses = read_monitor(tile, MON_L2_MISS_INDEX);
        }
#ifdef ACCS_PRESENT
        for (t = 0; t < SOC_NACC; t++) {
            if (acc_has_l2[t]) {
                tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
                vals->l2_stats[tile].hits = read_monitor(tile, MON_L2_HIT_INDEX);
                vals->l2_stats[tile].misses = read_monitor(tile, MON_L2_MISS_INDEX);
            }
        }
#endif

        //llc stats
        for (t = 0; t < SOC_NMEM; t++) {
            tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
            vals->l2_stats[tile].hits = read_monitor(tile, MON_LLC_HIT_INDEX);
            vals->l2_stats[tile].misses = read_monitor(tile, MON_LLC_MISS_INDEX);
        }

        //acc stats
#ifdef ACCS_PRESENT
        for (t = 0; t < SOC_NACC; t++) {
            tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
            vals->acc_stats[t].acc_tlb = read_monitor(tile, MON_ACC_TLB_INDEX);
            vals->acc_stats[t].acc_mem_lo = read_monitor(tile, MON_ACC_MEM_LO_INDEX);
            vals->acc_stats[t].acc_mem_hi = read_monitor(tile, MON_ACC_MEM_HI_INDEX);
            vals->acc_stats[t].acc_tot_lo = read_monitor(tile, MON_ACC_TOT_LO_INDEX);
            vals->acc_stats[t].acc_tot_hi = read_monitor(tile, MON_ACC_TOT_HI_INDEX);
        }

#endif

        //dvfs
    	for (p = 0; p < DVFS_OP_POINTS; p++)
    		for (t = 0; t < SOC_NTILES; t++)
    		vals->dvfs_op[t][p] = read_monitor(t, MON_DVFS_BASE_INDEX + p);

       	//noc inject
    	for (p = 0; p < NOC_PLANES; p++)
    		for (t = 0; t < SOC_NTILES; t++)
    		vals->noc_injects[t][p] = read_monitor(t, MON_NOC_TILE_INJECT_BASE_INDEX + p);

        //noc queue full tile
   		for (p = 0; p < NOC_PLANES; p++)
   			for (q = 0; q < NOC_QUEUES; q++)
   				for (t = 0; t < SOC_NTILES; t++)
   					vals->noc_queue_full[t][p][q] = read_monitor(t, MON_NOC_QUEUES_FULL_BASE_INDEX + p * NOC_QUEUES + q);

#ifdef __riscv
        __asm__ __volatile__("fence\n");
#else
        __asm__ __volatile__("membar\n");
#endif
        for (t = 0; t < SOC_NTILES; t++)
            write_burst_reg(t, 0);

        return 0;

    } else {

        memset(vals, 0, sizeof(esp_monitor_vals_t));
        for (t = 0; t < SOC_NTILES; t++)
            write_burst_reg(t, 1);

#ifdef __riscv
        __asm__ __volatile__("fence\n");
#else
        __asm__ __volatile__("membar\n");
#endif

        //ddr accesses
        if (args.read_mask & (1 << ESP_MON_READ_DDR_ACCESSES))
            for (t = 0; t < SOC_NMEM; t++)
                vals->ddr_accesses[t] = read_monitor(mem_locs[t].row * SOC_COLS + mem_locs[t].col, MON_DDR_WORD_TRANSFER_INDEX);

        //mem_reqs
        if (args.read_mask & (1 << ESP_MON_READ_MEM_REQS))
            for (t = 0; t < SOC_NMEM; t++){
                tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
                vals->mem_reqs[t].coh_reqs = read_monitor(tile, MON_MEM_COH_REQ_INDEX);
                vals->mem_reqs[t].coh_fwds = read_monitor(tile, MON_MEM_COH_FWD_INDEX);
                vals->mem_reqs[t].coh_rsps_rcv = read_monitor(tile, MON_MEM_COH_RSP_RCV_INDEX);
                vals->mem_reqs[t].coh_rsps_snd = read_monitor(tile, MON_MEM_COH_RSP_SND_INDEX);
                vals->mem_reqs[t].dma_reqs = read_monitor(tile, MON_MEM_DMA_REQ_INDEX);
                vals->mem_reqs[t].dma_rsps = read_monitor(tile, MON_MEM_DMA_RSP_INDEX);
                vals->mem_reqs[t].coh_dma_reqs = read_monitor(tile, MON_MEM_COH_DMA_REQ_INDEX);
                vals->mem_reqs[t].coh_dma_rsps = read_monitor(tile, MON_MEM_COH_DMA_RSP_INDEX);
            }

        //l2 stats
        if (args.read_mask & (1 << ESP_MON_READ_L2_STATS)) {
            for (t = 0; t < SOC_NCPU; t++) {
                tile = cpu_locs[t].row * SOC_COLS + cpu_locs[t].col;
                vals->l2_stats[tile].hits = read_monitor(tile, MON_L2_HIT_INDEX);
                vals->l2_stats[tile].misses = read_monitor(tile, MON_L2_MISS_INDEX);
            }
#ifdef ACCS_PRESENT
            for (t = 0; t < SOC_NACC; t++) {
                if (acc_has_l2[t]) {
                    tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
                    vals->l2_stats[tile].hits = read_monitor(tile, MON_L2_HIT_INDEX);
                    vals->l2_stats[tile].misses = read_monitor(tile, MON_L2_MISS_INDEX);
                }
            }
#endif
        }

        //llc stats
        if (args.read_mask & (1 << ESP_MON_READ_LLC_STATS))
            for (t = 0; t < SOC_NMEM; t++) {
                tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
                vals->l2_stats[tile].hits = read_monitor(tile, MON_LLC_HIT_INDEX);
                vals->l2_stats[tile].misses = read_monitor(tile, MON_LLC_MISS_INDEX);
            }

        //acc stats
#ifdef ACCS_PRESENT
        if (args.read_mask & (1 << ESP_MON_READ_ACC_STATS)) {
            tile = acc_locs[args.acc_index].row * SOC_COLS + acc_locs[args.acc_index].col;
            vals->acc_stats[args.acc_index].acc_tlb = read_monitor(tile, MON_ACC_TLB_INDEX);
            vals->acc_stats[args.acc_index].acc_mem_lo = read_monitor(tile, MON_ACC_MEM_LO_INDEX);
            vals->acc_stats[args.acc_index].acc_mem_hi = read_monitor(tile, MON_ACC_MEM_HI_INDEX);
            vals->acc_stats[args.acc_index].acc_tot_lo = read_monitor(tile, MON_ACC_TOT_LO_INDEX);
            vals->acc_stats[args.acc_index].acc_tot_hi = read_monitor(tile, MON_ACC_TOT_HI_INDEX);
        }
#endif

        //dvfs
        if (args.read_mask & (1 << ESP_MON_READ_DVFS_OP))
        	for (p = 0; p < DVFS_OP_POINTS; p++)
        		vals->dvfs_op[args.tile_index][p] = read_monitor(args.tile_index, MON_DVFS_BASE_INDEX + p);

       	//noc inject
        if (args.read_mask & (1 << ESP_MON_READ_NOC_INJECTS))
        	for (p = 0; p < NOC_PLANES; p++)
        		vals->noc_injects[args.tile_index][p] = read_monitor(args.tile_index, MON_NOC_TILE_INJECT_BASE_INDEX + p);

        //noc queue full tile
       	if (args.read_mask & (1 << ESP_MON_READ_NOC_QUEUE_FULL_TILE))
       		for (p = 0; p < NOC_PLANES; p++)
       			for (q = 0; q < NOC_QUEUES; q++)
       				vals->noc_queue_full[args.tile_index][p][q] = read_monitor(args.tile_index, MON_NOC_QUEUES_FULL_BASE_INDEX + p * NOC_QUEUES + q);

       	if (args.read_mask & (1 << ESP_MON_READ_NOC_QUEUE_FULL_PLANE))
       		for (q = 0; q < NOC_QUEUES; q++)
       			for (t = 0; t < SOC_NTILES; t++)
       				vals->noc_queue_full[t][args.noc_index][q] = read_monitor(t, MON_NOC_QUEUES_FULL_BASE_INDEX + args.noc_index * NOC_QUEUES + q);

#ifdef __riscv
        __asm__ __volatile__("fence\n");
#else
        __asm__ __volatile__("membar\n");
#endif
        for (t = 0; t < SOC_NTILES; t++)
            write_burst_reg(t, 0);

         return 0;

    }
}

uint32_t sub_monitor_vals (uint32_t val_start, uint32_t val_end)
{
    if (val_end >= val_start)
        return val_end - val_start;
    else
        return (0xFFFFFFFF - val_start + val_end);
}

esp_monitor_vals_t esp_monitor_diff(esp_monitor_vals_t vals_start, esp_monitor_vals_t vals_end)
{
    esp_monitor_vals_t vals_diff;
    int t, p, q, tile;

    for (t = 0; t < SOC_NMEM; t++)
        vals_diff.ddr_accesses[t] = sub_monitor_vals(vals_start.ddr_accesses[t], vals_end.ddr_accesses[t]);

    //mem_reqs
    for (t = 0; t < SOC_NMEM; t++){
        tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
        vals_diff.mem_reqs[t].coh_reqs = sub_monitor_vals(vals_start.mem_reqs[t].coh_reqs, vals_end.mem_reqs[t].coh_reqs);
        vals_diff.mem_reqs[t].coh_fwds = sub_monitor_vals(vals_start.mem_reqs[t].coh_fwds, vals_end.mem_reqs[t].coh_fwds);
        vals_diff.mem_reqs[t].coh_rsps_rcv = sub_monitor_vals(vals_start.mem_reqs[t].coh_rsps_rcv, vals_end.mem_reqs[t].coh_rsps_rcv);
        vals_diff.mem_reqs[t].coh_rsps_snd = sub_monitor_vals(vals_start.mem_reqs[t].coh_rsps_snd, vals_end.mem_reqs[t].coh_rsps_snd);
        vals_diff.mem_reqs[t].dma_reqs = sub_monitor_vals(vals_start.mem_reqs[t].dma_reqs, vals_end.mem_reqs[t].dma_reqs);
        vals_diff.mem_reqs[t].dma_rsps = sub_monitor_vals(vals_start.mem_reqs[t].dma_rsps, vals_end.mem_reqs[t].dma_rsps);
        vals_diff.mem_reqs[t].coh_dma_reqs = sub_monitor_vals(vals_start.mem_reqs[t].coh_dma_reqs, vals_end.mem_reqs[t].coh_dma_reqs);
        vals_diff.mem_reqs[t].coh_dma_rsps = sub_monitor_vals(vals_start.mem_reqs[t].coh_dma_rsps, vals_end.mem_reqs[t].coh_dma_rsps);
    }

    //l2 stats
    for (t = 0; t < SOC_NCPU; t++) {
        tile = cpu_locs[t].row * SOC_COLS + cpu_locs[t].col;
        vals_diff.l2_stats[tile].hits = sub_monitor_vals(vals_start.l2_stats[tile].hits, vals_end.l2_stats[tile].hits);
        vals_diff.l2_stats[tile].misses = sub_monitor_vals(vals_start.l2_stats[tile].misses, vals_end.l2_stats[tile].misses);
    }
#ifdef ACCS_PRESENT
    for (t = 0; t < SOC_NACC; t++) {
        if (acc_has_l2[t]) {
            tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
            vals_diff.l2_stats[tile].hits = sub_monitor_vals(vals_start.l2_stats[tile].hits, vals_end.l2_stats[tile].hits);
            vals_diff.l2_stats[tile].misses = sub_monitor_vals(vals_start.l2_stats[tile].misses, vals_end.l2_stats[tile].misses);
        }
    }
#endif

    //llc stats
    for (t = 0; t < SOC_NMEM; t++) {
        tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
        vals_diff.l2_stats[tile].hits = sub_monitor_vals(vals_start.l2_stats[tile].hits, vals_end.l2_stats[tile].hits);
        vals_diff.l2_stats[tile].misses = sub_monitor_vals(vals_start.l2_stats[tile].misses, vals_end.l2_stats[tile].misses);
    }

    //acc stats
#ifdef ACCS_PRESENT
    for (t = 0; t < SOC_NACC; t++) {
        tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
        //accelerator counters are cleared at the start of an invocation, so merely report the final count
        vals_diff.acc_stats[t].acc_tlb = vals_end.acc_stats[t].acc_tlb;
        vals_diff.acc_stats[t].acc_mem_lo = vals_end.acc_stats[t].acc_mem_lo;
        vals_diff.acc_stats[t].acc_mem_hi = vals_end.acc_stats[t].acc_mem_hi;
        vals_diff.acc_stats[t].acc_tot_lo = vals_end.acc_stats[t].acc_tot_lo;
        vals_diff.acc_stats[t].acc_tot_hi = vals_end.acc_stats[t].acc_tot_hi;
    }

#endif

    //dvfs
    for (p = 0; p < DVFS_OP_POINTS; p++)
        for (t = 0; t < SOC_NTILES; t++)
        vals_diff.dvfs_op[t][p] = sub_monitor_vals(vals_start.dvfs_op[t][p], vals_end.dvfs_op[t][p]);

    //noc inject
    for (p = 0; p < NOC_PLANES; p++)
        for (t = 0; t < SOC_NTILES; t++)
        vals_diff.noc_injects[t][p] = sub_monitor_vals(vals_start.noc_injects[t][p], vals_end.noc_injects[t][p]);

    //noc queue full tile
    for (p = 0; p < NOC_PLANES; p++)
        for (q = 0; q < NOC_QUEUES; q++)
            for (t = 0; t < SOC_NTILES; t++)
                vals_diff.noc_queue_full[t][p][q] = sub_monitor_vals(vals_start.noc_queue_full[t][p][q], vals_end.noc_queue_full[t][p][q]);

    return vals_diff;
}

void esp_monitor_print(esp_monitor_args_t args, esp_monitor_vals_t vals, FILE *fp)
{
    int t, p, q, tile;
    printf("Writing esp_monitor stats to specified file...\n");

    fprintf(fp, "***************************************************\n");
    fprintf(fp, "******************ESP MONITOR STATS****************\n");
    fprintf(fp, "***************************************************\n");

    fprintf(fp, "\n********************MEMORY STATS*******************\n");
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_DDR_ACCESSES)))
        for (t = 0; t < SOC_NMEM; t++)
            fprintf(fp, "Off-chip memory accesses at mem tile %d: %d\n", t, vals.ddr_accesses[t]);

    //mem_reqs
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_MEM_REQS)))
        for (t = 0; t < SOC_NMEM; t++){
            tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
            fprintf(fp, "Coherence requests to LLC %d: %d\n", t, vals.mem_reqs[t].coh_reqs);
            fprintf(fp, "Coherence forwards from LLC %d: %d\n", t, vals.mem_reqs[t].coh_fwds);
            fprintf(fp, "Coherence responses received by LLC %d: %d\n", t, vals.mem_reqs[t].coh_rsps_rcv);
            fprintf(fp, "Coherence responses sent by LLC %d: %d\n", t, vals.mem_reqs[t].coh_rsps_snd);
            fprintf(fp, "DMA requests to mem tile %d: %d\n", t, vals.mem_reqs[t].dma_reqs);
            fprintf(fp, "DMA responses from mem tile %d: %d\n", t, vals.mem_reqs[t].dma_rsps);
            fprintf(fp, "Coherent DMA requests to LLC %d: %d\n", t, vals.mem_reqs[t].coh_dma_reqs);
            fprintf(fp, "Coherent DMA responses from LLC %d: %d\n", t, vals.mem_reqs[t].coh_dma_rsps);
        }

    fprintf(fp, "\n********************CACHE STATS********************\n");
    //l2 stats
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_L2_STATS))){
        for (t = 0; t < SOC_NCPU; t++) {
            tile = cpu_locs[t].row * SOC_COLS + cpu_locs[t].col;
            fprintf(fp, "L2 hits for CPU %d: %d\n", t, vals.l2_stats[tile].hits);
            fprintf(fp, "L2 misses for CPU %d: %d\n", t, vals.l2_stats[tile].misses);
        }
#ifdef ACCS_PRESENT
        for (t = 0; t < SOC_NACC; t++) {
            if (acc_has_l2[t]) {
                tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
                fprintf(fp, "L2 hits for acc %d: %d\n", t, vals.l2_stats[tile].hits);
                fprintf(fp, "L2 misses for acc %d: %d\n", t, vals.l2_stats[tile].misses);
            }
        }
#endif
    }

    //llc stats
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_LLC_STATS)))
        for (t = 0; t < SOC_NMEM; t++) {
            tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
            fprintf(fp, "Hits at LLC %d: %d\n", t, vals.l2_stats[tile].hits);
            fprintf(fp, "Misses at LLC %d: %d\n", t, vals.l2_stats[tile].misses);
        }

    fprintf(fp, "\n****************ACCELERATOR STATS******************\n");
    //acc stats
#ifdef ACCS_PRESENT
    if (args.read_mode == ESP_MON_READ_ALL){
        for (t = 0; t < SOC_NACC; t++) {
            tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
            fprintf(fp, "Accelerator %d TLB-loading cycles: %d\n", t, vals.acc_stats[t].acc_tlb);
            fprintf(fp, "Accelerator %d mem cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[t].acc_mem_lo) + (((unsigned long long) vals.acc_stats[t].acc_mem_hi) << 32));
            fprintf(fp, "Accelerator %d total cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[t].acc_tot_lo) + (((unsigned long long) vals.acc_stats[t].acc_tot_hi) << 32));
        }
    } else if (args.read_mask & (1 << ESP_MON_READ_LLC_STATS)) {
        fprintf(fp, "Accelerator %d TLB-loading cycles: %d\n", t, vals.acc_stats[args.acc_index].acc_tlb);
        fprintf(fp, "Accelerator %d mem cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[args.acc_index].acc_mem_lo) + (((unsigned long long) vals.acc_stats[args.acc_index].acc_mem_hi) << 32));
        fprintf(fp, "Accelerator %d total cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[args.acc_index].acc_tot_lo) + (((unsigned long long) vals.acc_stats[args.acc_index].acc_tot_hi) << 32));
    }
#endif

    fprintf(fp, "\n*********************DVFS STATS********************\n");
    //dvfs
    if (args.read_mode == ESP_MON_READ_ALL) {
        for (t = 0; t < SOC_NTILES; t++)
            for (p = 0; p < DVFS_OP_POINTS; p++)
                fprintf(fp, "DVFS Cycles for tile %d at operating point %d: %d\n", t, p, vals.dvfs_op[t][p]);
    } else if (args.read_mask & (1 << ESP_MON_READ_DVFS_OP)) {
        for (p = 0; p < DVFS_OP_POINTS; p++)
            fprintf(fp, "DVFS Cycles for tile %d at operating point %d: %d\n", args.tile_index, p, vals.dvfs_op[args.tile_index][p]);
   }

    fprintf(fp, "\n*********************NOC STATS*********************\n");
    //noc inject
    if (args.read_mode == ESP_MON_READ_ALL) {
        for (t = 0; t < SOC_NTILES; t++)
            for (p = 0; p < NOC_PLANES; p++)
                fprintf(fp, "NoC packets injected at tile %d on plane %d: %d\n", t, p, vals.noc_injects[t][p]);
    } else if (args.read_mask & (1 << ESP_MON_READ_NOC_INJECTS)) {
        for (p = 0; p < NOC_PLANES; p++)
            fprintf(fp, "NoC packets injected at tile %d on plane %d: %d\n", args.tile_index, p, vals.noc_injects[args.tile_index][p]);
    }
    //noc queue full tile
    if (args.read_mode == ESP_MON_READ_ALL) {
        for (t = 0; t < SOC_NTILES; t++)
            for (p = 0; p < NOC_PLANES; p++)
                for (q = 0; q < NOC_QUEUES; q++)
                    fprintf(fp, "NoC backpressure cycles at tile %d on plane %d for queue %d: %d\n", t, p, q, vals.noc_queue_full[t][p][q]);
    } else if (args.read_mask & (1 << ESP_MON_READ_NOC_QUEUE_FULL_TILE)) {
         for (p = 0; p < NOC_PLANES; p++)
            for (q = 0; q < NOC_QUEUES; q++)
                fprintf(fp, "NoC backpressure cycles at tile %d on plane %d for queue %d: %d\n", args.tile_index, p, q, vals.noc_queue_full[args.tile_index][p][q]);
    } else if (args.read_mask & (1 << ESP_MON_READ_NOC_QUEUE_FULL_PLANE)) {
        for (t = 0; t < SOC_NTILES; t++)
            for (q = 0; q < NOC_QUEUES; q++)
                fprintf(fp, "NoC backpressure cycles at tile %d on plane %d for queue %d: %d\n", t, args.noc_index, q, vals.noc_queue_full[t][args.noc_index][q]);
    }
}

esp_monitor_vals_t* esp_monitor_vals_alloc()
{
    esp_monitor_vals_t *ptr = malloc(sizeof(esp_monitor_vals_t));
    esp_mon_alloc_node_t *node = malloc(sizeof(esp_mon_alloc_node_t));
    node->vals = ptr;
    node->next = mon_alloc_head;
    mon_alloc_head = node;
    return ptr;
}

void esp_monitor_free()
{
    munmap_monitors();

    esp_mon_alloc_node_t *cur = mon_alloc_head;
    esp_mon_alloc_node_t *next;
    while (cur) {
        next = cur->next;
        free(cur->vals);
        free(cur);
        cur = next;
    }
}
