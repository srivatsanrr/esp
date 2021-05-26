// Copyright (c) 2011-2021 Columbia University, System Level Design Group
// SPDX-License-Identifier: Apache-2.0
#ifndef _SOFTMAX_CXX_CATAPULT_H_
#define _SOFTMAX_CXX_CATAPULT_H_

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#ifndef __user
#define __user
#endif
#endif /* __KERNEL__ */

#include <esp.h>
#include <esp_accelerator.h>

struct softmax_cxx_catapult_access {
	struct esp_access esp;
	/* <<--regs-->> */
	unsigned batch;
	unsigned src_offset;
	unsigned dst_offset;
};

#define SOFTMAX_CXX_CATAPULT_IOC_ACCESS	_IOW ('S', 0, struct softmax_cxx_catapult_access)

#endif /* _SOFTMAX_CXX_CATAPULT_H_ */
