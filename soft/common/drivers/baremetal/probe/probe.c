/*
 * Copyright (c) 2011-2021 Columbia University, System Level Design Group
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include <esp_probe.h>

#include "esplink.h"
#include "monitors.h"
#include "soc_locs.h"

#ifdef __riscv

uintptr_t dtb = DTB_ADDRESS;
/*
 * The RISC-V bare-metal toolchain does not have support for malloc
 * on unthethered systems. This simple hack is used to enable RTL
 * simulation of an accelerator invoked by bare-metal software.
 * Note that The RISC-V core in ESP is unthethered and cannot rely
 * proxy kernel running on a host system.
 */
#ifdef OVERRIDE_DRAM_SIZE
static uintptr_t uncached_area_ptr = DRAM_BASE + (OVERRIDE_DRAM_SIZE >> 1);
#else
static uintptr_t uncached_area_ptr = 0xa0100000;
#endif

#endif /* __riscv */

#ifdef __sparc
asm(
    "	.text\n"
    "	.align 4\n"
    "	.global get_pid\n"

    "get_pid:\n"
    "        mov  %asr17, %o0\n"
    "        srl  %o0, 28, %o0\n"
    "        retl\n"
    "        and %o0, 0xf, %o0\n"
    );
#elif __riscv
int get_pid()
{
	int hartid = (int) read_csr(mhartid);
	return hartid;
}
#else
#error Unsupported ISA
#endif

const char* const coherence_label[5] = {
	"non-coherent DMA",
	"LLC-coherent DMA",
	"coherent-DMA",
	"fully-coherent access",
	0 };

void *aligned_malloc(int size) {
#ifndef __riscv
	void *mem = malloc(size + CACHELINE_SIZE + sizeof(void*));
#else
	void *mem = (void *) uncached_area_ptr;
	uncached_area_ptr += size + CACHELINE_SIZE + sizeof(void*);
#endif

	void **ptr = (void**) ((uintptr_t) (mem + CACHELINE_SIZE + sizeof(void*)) & ~(CACHELINE_SIZE-1));
	ptr[-1] = mem;
	return ptr;
}

void aligned_free(void *ptr) {
	// On RISC-V we never free memory
	// This hack is intended for simulation only
#ifndef __riscv
	free(((void**)ptr)[-1]);
#endif
}


void esp_flush(int coherence)
{
	int i;
	const int cmd = 1 << ESP_CACHE_CMD_FLUSH_BIT;
	struct esp_device *llcs = NULL;
	struct esp_device *l2s = NULL;
	int nllc = 0;
	int nl2 = 0;
	int pid = get_pid();

	switch (coherence) {
	case ACC_COH_NONE   : printf("  -> Non-coherent DMA\n"); break;
	case ACC_COH_LLC    : printf("  -> LLC-coherent DMA\n"); break;
	case ACC_COH_RECALL : printf("  -> Coherent DMA\n"); break;
	case ACC_COH_FULL   : printf("  -> Fully-coherent cache access\n"); break;
	}


	if (coherence == ACC_COH_NONE)
		/* Look for LLC controller */
		nllc = probe(&llcs, VENDOR_CACHE, DEVID_LLC_CACHE, DEVNAME_LLC_CACHE);

	if (coherence < ACC_COH_RECALL)
		/* Look for L2 controller */
		nl2 = probe(&l2s, VENDOR_CACHE, DEVID_L2_CACHE, DEVNAME_L2_CACHE);

	if (coherence < ACC_COH_RECALL) {

		if (nl2 > 0) {
			/* Set L2 flush (waits for L1 to flush first) */
			for (i = 0; i < nl2; i++) {
				struct esp_device *l2 = &l2s[i];
				int cpuid = (ioread32(l2, ESP_CACHE_REG_STATUS) & ESP_CACHE_STATUS_CPUID_MASK) >> ESP_CACHE_STATUS_CPUID_SHIFT;
				if (cpuid == pid) {
					iowrite32(l2, ESP_CACHE_REG_CMD, cmd);
					break;
				}
			}

#ifdef __sparc
			/* Flush L1 - also execute L2 flush */
			__asm__ __volatile__("sta %%g0, [%%g0] %0\n\t" : :
					"i"(ASI_LEON_DFLUSH) : "memory");
#endif

			/* Wait for L2 flush to complete */
			struct esp_device *l2 = &l2s[i];
			/* Poll for completion */
			while (!(ioread32(l2, ESP_CACHE_REG_STATUS) & ESP_CACHE_STATUS_DONE_MASK));
			/* Clear IRQ */
			iowrite32(l2, ESP_CACHE_REG_CMD, 0);
		}

		if (nllc > 0) {

			/* Flus LLC */
			for (i = 0; i < nllc; i++) {
				struct esp_device *llc = &llcs[i];
				iowrite32(llc, ESP_CACHE_REG_CMD, cmd);
			}

			/* Wait for LLC flush to complete */
			for (i = 0; i < nllc; i++) {
				struct esp_device *llc = &llcs[i];
				/* Poll for completion */
				while (!(ioread32(llc, ESP_CACHE_REG_STATUS) & ESP_CACHE_STATUS_DONE_MASK));
				/* Clear IRQ */
				iowrite32(llc, ESP_CACHE_REG_CMD, 0);
			}
		}
	}

#ifndef __riscv
	if (llcs)
		free(llcs);
	if (l2s)
		free(l2s);
#endif

}

#ifdef __sparc
int probe(struct esp_device **espdevs, unsigned vendor, unsigned devid, const char *name)
{
	int i;
	int ndev = 0;
	unsigned id_reg, bank_addr_reg;
	unsigned *devtable = (unsigned *) APB_PLUGNPLAY;
	unsigned vend;
	unsigned id;
	unsigned number;
	unsigned irq;
	unsigned addr;
	for (i = 0; i < NAPBSLV; i++) {
		id_reg = devtable[2 * i];
		bank_addr_reg = devtable[2 * i + 1];
		vend = (id_reg >> 24);
		id   = (id_reg >> 12) & 0x00fff;

		if (vend == vendor && id == devid) {
			number = ndev;
			addr   = ((bank_addr_reg >> 20) << 8) + APB_BASE_ADDR;
			irq    = id_reg & 0x0000000f;

			ndev++;
			(*espdevs) = realloc((*espdevs), ndev * sizeof(struct esp_device));
			if (!(*espdevs)) {
				fprintf(stderr, "Error: cannot allocate esp_device list\n");
				exit(EXIT_FAILURE);
			}
			(*espdevs)[ndev-1].vendor = vend;
			(*espdevs)[ndev-1].id = id;
			(*espdevs)[ndev-1].number = number;
			(*espdevs)[ndev-1].irq = irq;
			(*espdevs)[ndev-1].addr = addr;
			printf("[probe]  %s.%u registered\n", name, (*espdevs)[ndev-1].number);
			printf("         Address   : 0x%08x\n", (unsigned) (*espdevs)[ndev-1].addr);
			printf("         Interrupt : %u\n", (*espdevs)[ndev-1].irq);
		}
	}
	printf("\n");
	return ndev;
}
#elif __riscv

static unsigned ndev = 0;

static void esp_open(const struct fdt_scan_node *node, void *extra)
{
}

static void esp_prop(const struct fdt_scan_prop *prop, void *extra)
{
	// Get pointer to last entry in espdevs. This has not been discovered yet.
	struct esp_device **espdevs = (struct esp_device **) extra;
	const char *name = (*espdevs)[0].name;

	if (!strcmp(prop->name, "compatible") && !strcmp((const char*)prop->value, name))
		(*espdevs)[ndev].compat = 1;
	else if (!strcmp(prop->name, "reg"))
		fdt_get_address(prop->node->parent, prop->value, (uint64_t *) &(*espdevs)[ndev].addr);
	else if (!strcmp(prop->name, "interrupts"))
		fdt_get_value(prop->value, (uint32_t *) &(*espdevs)[ndev].irq);
}

static void esp_done(const struct fdt_scan_node *node, void *extra)
{
	struct esp_device **espdevs = (struct esp_device **)extra;
	const char *name = (*espdevs)[0].name;

	if ((*espdevs)[ndev].compat != 0) {
		printf("[probe] %s.%d registered\n", name, ndev);
		printf("        Address   : 0x%08x\n", (unsigned) (*espdevs)[ndev].addr);
		printf("        Interrupt : %d\n", (*espdevs)[ndev].irq);
		ndev++;

		// Initialize new entry (may not be discovered!)
		(*espdevs)[ndev].vendor = (*espdevs)[ndev].vendor;
		(*espdevs)[ndev].id = (*espdevs)[ndev].id;
		(*espdevs)[ndev].number = ndev;
		(*espdevs)[ndev].compat = 0;
		strcpy((*espdevs)[ndev].name, name);
	}
}

int probe(struct esp_device **espdevs, unsigned vendor, unsigned devid, const char *name)
{
	struct fdt_cb cb;
	ndev = 0;

	// Initialize first entry of the device structure (may not be discovered!)
	(*espdevs) = (struct esp_device *) aligned_malloc(NACC_MAX * sizeof(struct esp_device));
	if (!(*espdevs)) {
		printf("Error: cannot allocate esp_device list\n");
		exit(EXIT_FAILURE);
	}
	memset((*espdevs), 0, NACC_MAX * sizeof(struct esp_device));

	(*espdevs)[0].vendor = vendor;
	(*espdevs)[0].id = devid;
	(*espdevs)[0].number = 0;
	(*espdevs)[0].compat = 0;
	strcpy((*espdevs)[0].name, name);

	memset(&cb, 0, sizeof(cb));
	cb.open = esp_open;
	cb.prop = esp_prop;
	cb.done = esp_done;
	cb.extra = espdevs;

	fdt_scan(dtb, &cb);

	return ndev;
}

#else /* !__riscv && !__sparc */

#error Unsupported ISA

#endif

unsigned ioread32(struct esp_device *dev, unsigned offset)
{
	const long unsigned addr = dev->addr + offset;
	volatile unsigned *reg = (unsigned *) addr;
	return *reg;
}

void iowrite32(struct esp_device *dev, unsigned offset, unsigned payload)
{
	const long unsigned addr = dev->addr + offset;
	volatile unsigned *reg = (unsigned *) addr;
	*reg = payload;
}

void esp_p2p_init(struct esp_device *dev, struct esp_device **srcs, unsigned nsrcs)
{
	unsigned i;

	esp_p2p_reset(dev);
	esp_p2p_enable_src(dev);
	esp_p2p_set_nsrcs(dev, nsrcs);
	for (i = 0; i < nsrcs; i++) {
		esp_p2p_enable_dst(srcs[i]);
		esp_p2p_set_y(dev, i, esp_get_y(srcs[i]));
		esp_p2p_set_x(dev, i, esp_get_x(srcs[i]));
	}
}

//BAREMETAL MONITORS API
unsigned int read_monitor(int tile_no, int mon_no)
{
    unsigned int offset = (MONITOR_TILE_SIZE / sizeof(unsigned int)) * tile_no;
    unsigned int *addr = ((unsigned int *) MONITOR_BASE_ADDR) + offset + mon_no + 1;
    return *addr;
}

void write_burst_reg(int tile_no, int val)
{
    unsigned int offset = (MONITOR_TILE_SIZE / sizeof(unsigned int)) * tile_no;
    unsigned int *addr = ((unsigned int *) MONITOR_BASE_ADDR) + offset;
    *addr = val;
}

unsigned int esp_monitor(esp_monitor_args_t args, esp_monitor_vals_t *vals)
{
    int t, p, q;
    unsigned int tile;

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

void esp_monitor_print(esp_monitor_args_t args, esp_monitor_vals_t vals)
{
    int t, p, q, tile;
    printf("Writing esp_monitor stats to specified file...\n");

    printf("***************************************************\n");
    printf("******************ESP MONITOR STATS****************\n");
    printf("***************************************************\n");

    printf("\n********************MEMORY STATS*******************\n");
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_DDR_ACCESSES)))
        for (t = 0; t < SOC_NMEM; t++)
            printf("Off-chip memory accesses at mem tile %d: %d\n", t, vals.ddr_accesses[t]);

    //mem_reqs
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_MEM_REQS)))
        for (t = 0; t < SOC_NMEM; t++){
            tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
            printf("Coherence requests to LLC %d: %d\n", t, vals.mem_reqs[t].coh_reqs);
            printf("Coherence forwards from LLC %d: %d\n", t, vals.mem_reqs[t].coh_fwds);
            printf("Coherence responses received by LLC %d: %d\n", t, vals.mem_reqs[t].coh_rsps_rcv);
            printf("Coherence responses sent by LLC %d: %d\n", t, vals.mem_reqs[t].coh_rsps_snd);
            printf("DMA requests to mem tile %d: %d\n", t, vals.mem_reqs[t].dma_reqs);
            printf("DMA responses from mem tile %d: %d\n", t, vals.mem_reqs[t].dma_rsps);
            printf("Coherent DMA requests to LLC %d: %d\n", t, vals.mem_reqs[t].coh_dma_reqs);
            printf("Coherent DMA responses from LLC %d: %d\n", t, vals.mem_reqs[t].coh_dma_rsps);
        }

    printf("\n********************CACHE STATS********************\n");
    //l2 stats
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_L2_STATS))){
        for (t = 0; t < SOC_NCPU; t++) {
            tile = cpu_locs[t].row * SOC_COLS + cpu_locs[t].col;
            printf("L2 hits for CPU %d: %d\n", t, vals.l2_stats[tile].hits);
            printf("L2 misses for CPU %d: %d\n", t, vals.l2_stats[tile].misses);
        }
#ifdef ACCS_PRESENT
        for (t = 0; t < SOC_NACC; t++) {
            if (acc_has_l2[t]) {
                tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
                printf("L2 hits for acc %d: %d\n", t, vals.l2_stats[tile].hits);
                printf("L2 misses for acc %d: %d\n", t, vals.l2_stats[tile].misses);
            }
        }
#endif
    }

    //llc stats
    if (args.read_mode == ESP_MON_READ_ALL || (args.read_mask & (1 << ESP_MON_READ_LLC_STATS)))
        for (t = 0; t < SOC_NMEM; t++) {
            tile = mem_locs[t].row * SOC_COLS + mem_locs[t].col;
            printf("Hits at LLC %d: %d\n", t, vals.l2_stats[tile].hits);
            printf("Misses at LLC %d: %d\n", t, vals.l2_stats[tile].misses);
        }

    printf("\n****************ACCELERATOR STATS******************\n");
    //acc stats
#ifdef ACCS_PRESENT
    if (args.read_mode == ESP_MON_READ_ALL){
        for (t = 0; t < SOC_NACC; t++) {
            tile = acc_locs[t].row * SOC_COLS + acc_locs[t].col;
            printf("Accelerator %d TLB-loading cycles: %d\n", t, vals.acc_stats[t].acc_tlb);
            printf("Accelerator %d mem cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[t].acc_mem_lo) + (((unsigned long long) vals.acc_stats[t].acc_mem_hi) << 32));
            printf("Accelerator %d total cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[t].acc_tot_lo) + (((unsigned long long) vals.acc_stats[t].acc_tot_hi) << 32));
        }
    } else if (args.read_mask & (1 << ESP_MON_READ_LLC_STATS)) {
        printf("Accelerator %d TLB-loading cycles: %d\n", t, vals.acc_stats[args.acc_index].acc_tlb);
        printf("Accelerator %d mem cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[args.acc_index].acc_mem_lo) + (((unsigned long long) vals.acc_stats[args.acc_index].acc_mem_hi) << 32));
        printf("Accelerator %d total cycles: %llu\n", t, ((unsigned long long) vals.acc_stats[args.acc_index].acc_tot_lo) + (((unsigned long long) vals.acc_stats[args.acc_index].acc_tot_hi) << 32));
    }
#endif

    printf("\n*********************DVFS STATS********************\n");
    //dvfs
    if (args.read_mode == ESP_MON_READ_ALL) {
        for (t = 0; t < SOC_NTILES; t++)
            for (p = 0; p < DVFS_OP_POINTS; p++)
                printf("DVFS Cycles for tile %d at operating point %d: %d\n", t, p, vals.dvfs_op[t][p]);
    } else if (args.read_mask & (1 << ESP_MON_READ_DVFS_OP)) {
        for (p = 0; p < DVFS_OP_POINTS; p++)
            printf("DVFS Cycles for tile %d at operating point %d: %d\n", args.tile_index, p, vals.dvfs_op[args.tile_index][p]);
   }

    printf("\n*********************NOC STATS*********************\n");
    //noc inject
    if (args.read_mode == ESP_MON_READ_ALL) {
        for (t = 0; t < SOC_NTILES; t++)
            for (p = 0; p < NOC_PLANES; p++)
                printf("NoC packets injected at tile %d on plane %d: %d\n", t, p, vals.noc_injects[t][p]);
    } else if (args.read_mask & (1 << ESP_MON_READ_NOC_INJECTS)) {
        for (p = 0; p < NOC_PLANES; p++)
            printf("NoC packets injected at tile %d on plane %d: %d\n", args.tile_index, p, vals.noc_injects[args.tile_index][p]);
    }
    //noc queue full tile
    if (args.read_mode == ESP_MON_READ_ALL) {
        for (t = 0; t < SOC_NTILES; t++)
            for (p = 0; p < NOC_PLANES; p++)
                for (q = 0; q < NOC_QUEUES; q++)
                    printf("NoC backpressure cycles at tile %d on plane %d for queue %d: %d\n", t, p, q, vals.noc_queue_full[t][p][q]);
    } else if (args.read_mask & (1 << ESP_MON_READ_NOC_QUEUE_FULL_TILE)) {
         for (p = 0; p < NOC_PLANES; p++)
            for (q = 0; q < NOC_QUEUES; q++)
                printf("NoC backpressure cycles at tile %d on plane %d for queue %d: %d\n", args.tile_index, p, q, vals.noc_queue_full[args.tile_index][p][q]);
    } else if (args.read_mask & (1 << ESP_MON_READ_NOC_QUEUE_FULL_PLANE)) {
        for (t = 0; t < SOC_NTILES; t++)
            for (q = 0; q < NOC_QUEUES; q++)
                printf("NoC backpressure cycles at tile %d on plane %d for queue %d: %d\n", t, args.noc_index, q, vals.noc_queue_full[t][args.noc_index][q]);
    }
}
