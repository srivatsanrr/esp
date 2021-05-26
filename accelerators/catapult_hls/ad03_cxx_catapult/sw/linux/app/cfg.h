// Copyright (c) 2011-2021 Columbia University, System Level Design Group
// SPDX-License-Identifier: Apache-2.0
#ifndef __ESP_CFG_H__
#define __ESP_CFG_H__

#include "libesp.h"
#include "softmax_cxx_catapult.h"

typedef int64_t token_t;

/* <<--params-def-->> */
#define BATCH 1

/* <<--params-->> */
const int32_t batch = BATCH;

/* << --hardcoded -->> */
const int32_t size = 128;

#define NACC 1

struct softmax_cxx_catapult_access softmax_cxx_cfg_000[] = {
	{
		/* <<--descriptor-->> */
		.batch = BATCH,
		.src_offset = 0,
		.dst_offset = 0,
		.esp.coherence = ACC_COH_NONE,
		.esp.p2p_store = 0,
		.esp.p2p_nsrcs = 0,
		.esp.p2p_srcs = {"", "", "", ""},
	}
};


esp_thread_info_t cfg_000[] = {
	{
		.run = true,
		.devname = "softmax_cxx_catapult.0",
		.ioctl_req = SOFTMAX_CXX_CATAPULT_IOC_ACCESS,
		.esp_desc = &(softmax_cxx_cfg_000[0].esp),
	}
};

esp_thread_info_t cfg_001[] = {
	{
		.run = true,
		.devname = "softmax_cxx_catapult.1",
		.ioctl_req = SOFTMAX_CXX_CATAPULT_IOC_ACCESS,
		.esp_desc = &(softmax_cxx_cfg_000[0].esp),
	}
};

#endif /* __ESP_CFG_H__ */
