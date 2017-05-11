#ifndef _MONTER_DRV_H_
#define _MONTER_DRV_H_

#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "monter.h"
#include "monter_ioctl.h"

#define MONTER_NAME		"monter"
#define MONTER_MEM_SIZE		(MONTER_PAGE_NUM * MONTER_PAGE_SIZE)
#define MONTER_MMIO_SIZE	(4096)
#define MONTER_MAX_DEVICES	(256)

#define MONTER_CMD_TYPE_INVALID		(0xf)
#define MONTER_CMD_TYPE_ADDR_AB		(MONTER_CMD_KIND_ADDR_AB)
#define MONTER_CMD_TYPE_RUN_MULT	(MONTER_CMD_KIND_RUN | MONTER_CMD_SUBTYPE_RUN_MULT)
#define MONTER_CMD_TYPE_RUN_REDC	(MONTER_CMD_KIND_RUN | MONTER_CMD_SUBTYPE_RUN_REDC)

#define MONTER_ADDR_INVALID	(MONTER_MEM_SIZE - 1)

#define INDEX_CLAIM_FAILED	MONTER_MAX_DEVICES

/*
NOTE(sodar):
podstawowe rozwiązanie - synchroniczne, bez DMA dla poleceń
- polecenia wykonywane w trakcie write()
*/
struct monter_device_context {
	unsigned int device_index;
	struct {
		bool pci_enabled;
		bool pci_regions_reserved;
		bool pci_mastering;
		bool irq_registered;
		bool dev_enabled;
		bool cdev_added;
	} init;

	struct pci_dev *pdev;
	void __iomem *bar0;
	struct cdev cdev;
	dev_t devt;
	struct device *device;

	/* Fields used with synchronous approach */
	struct mutex dev_access_lock;
	wait_queue_head_t notify_queue;
	atomic_t notify;
	struct tasklet_struct notify_tasklet;
};

struct monter_device_context_entry {
	struct monter_device_context dev_ctx;
	bool taken;
};

/**
 * monter_context - device context allocated per each "file" opened
 *
 * @dev_ctx: pointer to associated device context
 * @size: amount of bytes in @data work-buffer
 * @data: pointer to work-buffer
 * @queue_lock: lock which has to be acquired before a thread wants to modify a @command_queue
 * @command_queue: head of the command queue
 */
struct monter_context {
	struct monter_device_context *dctx;
	size_t size;
	void *data;
	dma_addr_t handle;

	/* Used to validate RUN_MULT and RUN_REDC commands */
	bool addr_ab_issued;
	uint32_t last_addr_a;
	uint32_t last_addr_b;
};

#define CTX_INITIALIZED(ctx) ((ctx)->size > 0)

/*
 * Registers manipulation functions
 */

/** Read ENABLE register */
static inline uint32_t
__monter_reg_enable_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_ENABLE);
}

/** Send @value to ENABLE register */
static inline void
__monter_reg_enable_write(struct monter_device_context *ctx, uint32_t value)
{
	iowrite32(value, ctx->bar0 + MONTER_ENABLE);
}

/** Read STATUS register */
static inline uint32_t
__monter_reg_status_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_STATUS);
}

/** Read INTR register */
static inline uint32_t
__monter_reg_intr_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_INTR);
}

/** Send @value to INTR register */
static inline void
__monter_reg_intr_write(struct monter_device_context *ctx, uint32_t value)
{
	iowrite32(value, ctx->bar0 + MONTER_INTR);
}

/** Send @value to INTR_ENABLE register */
static inline void
__monter_reg_intr_enable_write(struct monter_device_context *ctx, uint32_t value)
{
	iowrite32(value, ctx->bar0 + MONTER_INTR_ENABLE);
}

/** Send @value to RESET register */
static inline void
__monter_reg_reset_write(struct monter_device_context *ctx, uint32_t value)
{
	iowrite32(value, ctx->bar0 + MONTER_RESET);
}

/** Send @value to FIFO_SEND register */
static inline void
__monter_reg_fifo_send_write(struct monter_device_context *ctx, uint32_t value)
{
	iowrite32(value, ctx->bar0 + MONTER_FIFO_SEND);
}

/** Read FIFO_FREE register */
static inline uint32_t
__monter_reg_fifo_free_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_FIFO_FREE);
}

/** Read COUNTER register */
static inline uint32_t
__monter_reg_counter_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_COUNTER);
}

/* TODO(sodar): CMD_READ_PTR functions */
/* TODO(sodar): CMD_WRITE_PTR functions */

#endif // _MONTER_DRV_H_
