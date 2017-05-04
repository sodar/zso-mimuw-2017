#ifndef _MONTER_DRV_H_
#define _MONTER_DRV_H_

#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#define DRIVER_NAME "monter"
#define MAX_DEVICES (256)

#define DRIVER_PAGE_SIZE	(4096)
#define DRIVER_CTX_MAX_SIZE	(16 * DRIVER_PAGE_SIZE)

#define MONTER_DMA_SIZE		(16 * DRIVER_PAGE_SIZE)

#define INDEX_CLAIM_FAILED MAX_DEVICES

/*
NOTE(sodar):
*/
struct monter_device_context {
	struct pci_dev *pdev;
	void __iomem *bar0;
	unsigned int entry_index;
	struct cdev cdev;
	dev_t devt;
};

struct monter_device_context_entry {
	struct monter_device_context dev_ctx;
	bool taken;
};

struct monter_command {
	u8 type;
	union {
		struct {
			u16 addr_a;
			u16 addr_b;
		} addr_ab;
		struct {
			u16 size;
			u16 addr_d;
		} run_mult;
		struct {
			u16 size;
			u16 addr_d;
		} run_redc;
	} cmd_u;
	struct list_head entry;
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
	struct monter_device_context *dev_ctx;
	size_t size;
	void *data;
	dma_addr_t dma_handle;
	spinlock_t queue_lock;
	struct list_head command_queue;
};

#define CTX_INITIALIZED(ctx) ((ctx)->size > 0)

static inline void
MONTER_CTX_LOCK_INIT(struct monter_context *ctx)
{
	spin_lock_init(&ctx->queue_lock);
}

static inline void
MONTER_CTX_LOCK(struct monter_context *ctx)
{
	spin_lock(&ctx->queue_lock);
}

static inline void
MONTER_CTX_UNLOCK(struct monter_context *ctx)
{
	spin_unlock(&ctx->queue_lock);
}

/*
 * Register manipulation functions
 */

/** Read ENABLE register */
static inline u32
__monter_reg_enable_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_ENABLE);
}

/** Send @value to ENABLE register */
static inline void
__monter_reg_enable_write(struct monter_device_context *ctx, u32 value)
{
	iowrite32(value, ctx->bar0 + MONTER_ENABLE);
}

/** Read STATUS register */
static inline u32
__monter_reg_status_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_STATUS);
}

/** Read INTR register */
static inline u32
__monter_reg_intr_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_INTR);
}

/** Send @value to INTR register */
static inline void
__monter_reg_intr_write(struct monter_device_context *ctx, u32 value)
{
	iowrite32(value, ctx->bar0 + MONTER_INTR);
}

/** Send @value to INTR_ENABLE register */
static inline void
__monter_reg_intr_enable_write(struct monter_device_context *ctx, u32 value)
{
	iowrite32(value, ctx->bar0 + MONTER_INTR_ENABLE);
}

/** Send @value to RESET register */
static inline void
__monter_reg_reset_write(struct monter_device_context *ctx, u32 value)
{
	iowrite32(value, ctx->bar0 + MONTER_RESET);
}

/** Send @value to FIFO_SEND register */
static inline void
__monter_reg_fifo_send_write(struct monter_device_context *ctx, u32 value)
{
	iowrite32(value, ctx->bar0 + MONTER_FIFO_SEND);
}

/** Read FIFO_FREE register */
static inline u32
__monter_reg_fifo_free_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_FIFO_FREE);
}

/** Read COUNTER register */
static inline u32
__monter_reg_counter_read(struct monter_device_context *ctx)
{
	return ioread32(ctx->bar0 + MONTER_COUNTER);
}

/* TODO(sodar): CMD_READ_PTR functions */
/* TODO(sodar): CMD_WRITE_PTR functions */

#endif // _MONTER_DRV_H_
