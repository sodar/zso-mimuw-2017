/*
 * Author: Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>
 */

/*
TODO(sodar):
- Analyze how MONTER_RESET register works
- Support multiple Monter devices
	- Dynamic allocation of minor numbers

NOTE(sodar):
- operacje na `monter_context.command_queue` - nie jestem pewien czy powinny być
  otoczene lockami
*/

#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/spinlock_types.h>
#include <linux/uaccess.h>

#include "monter.h"
#include "monter_drv.h"
#include "monter_ioctl.h"

MODULE_AUTHOR("Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>");
MODULE_DESCRIPTION("ZSO: task #2: monter device driver");
MODULE_LICENSE("GPL");

/* Major and minor numbers allocated for Monter device */
static dev_t monter_dev_numbers;

/* Device class used by udev to create cdevs */
static struct class *monter_dev_class;

/* Holds monter_device_context struct for each minor device number */
static struct monter_device_context_entry monter_entries[MONTER_MAX_DEVICES];
static DEFINE_SPINLOCK(monter_entries_lock);

/* TODO(sodar): Boże, jaki żal */
static atomic_t gnotify = ATOMIC_INIT(0);

static inline void
__monter_run_one_cmd(struct monter_device_context *dctx, u32 cmd)
{
	cmd |= MONTER_CMD_NOTIFY;  // ensure NOTIFY flag

	__monter_reg_fifo_send_write(dctx, cmd);
	__monter_reg_enable_write(dctx, MONTER_ENABLE_CALC);
	while (atomic_read(&gnotify) == 0) {}
	atomic_set(&gnotify, 0);
	__monter_reg_enable_write(dctx, 0);
}

static unsigned int
claim_context_entry(void)
{
	unsigned int index = INDEX_CLAIM_FAILED;
	unsigned int i;

	spin_lock(&monter_entries_lock);
	for (i = 0; i < MONTER_MAX_DEVICES; ++i) {
		if (!monter_entries[i].taken) {
			memset(&monter_entries[i].dev_ctx, 0, sizeof(struct monter_device_context));
			mutex_init(&monter_entries[i].dev_ctx.dev_access_lock);

			monter_entries[i].taken = true;
			index = i;
			break;
		}
	}
	spin_unlock(&monter_entries_lock);

	return index;
}

static void
release_context_entry(unsigned int index)
{
	BUG_ON(index > MONTER_MAX_DEVICES);

	spin_lock(&monter_entries_lock);
	monter_entries[index].taken = false;
	spin_unlock(&monter_entries_lock);
}

/**
 * __command_alloc - allocate memory for struct monter_command
 */
static inline struct monter_command *
__command_alloc(u32 _cmd)
{
	struct monter_command *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (cmd == NULL) {
		#if defined(DEBUG)
		printk(KERN_ERR "%s: %s(): out of memory\n", MONTER_NAME, __func__);
		#endif
		return NULL;
	}

	cmd->type = MONTER_SWCMD_TYPE(_cmd);

	return cmd;
}

/**
 * __verify_addr - TODO(sodar)
 */
static inline int
__verify_addr(struct monter_context *ctx, u32 addr)
{
	if (addr >= MONTER_MEM_SIZE)
		return -EINVAL;
	if (addr >= ctx->size)
		return -EINVAL;

	return 0;
}

/**
 * __command_addr_ab_create - create monter_command struct assuming
 * that @_cmd has ADDR_AB type
 */
static struct monter_command *
__command_addr_ab_create(struct monter_context *ctx, u32 _cmd)
{
	struct monter_command *cmd;
	u32 addr_a;
	u32 addr_b;
	int err;

	BUG_ON(MONTER_SWCMD_TYPE(_cmd) != MONTER_SWCMD_TYPE_ADDR_AB);

	addr_a = MONTER_SWCMD_ADDR_A(_cmd);
	if ((err = __verify_addr(ctx, addr_a)) < 0)
		return ERR_PTR(err);

	addr_b = MONTER_SWCMD_ADDR_B(_cmd);
	if ((err = __verify_addr(ctx, addr_b)) < 0)
		return ERR_PTR(err);

	cmd = __command_alloc(_cmd);
	if (cmd != NULL) {
		cmd->cmd_u.addr_ab.addr_a = addr_a;
		cmd->cmd_u.addr_ab.addr_b = addr_b;
		return cmd;
	} else {
		return ERR_PTR(-EINVAL);
	}
}

/**
 * __command_run_mult_create - create monter_command struct assuming
 * that @_cmd has RUN_MULT type
 */
static struct monter_command *
__command_run_mult_create(struct monter_context *ctx, u32 _cmd)
{
	struct monter_command *cmd;
	u32 size;
	u32 addr_d;
	int err;

	BUG_ON(MONTER_SWCMD_TYPE(_cmd) != MONTER_SWCMD_TYPE_RUN_MULT);

	size = MONTER_SWCMD_RUN_SIZE(_cmd);
	addr_d = MONTER_SWCMD_ADDR_D(_cmd);
	if ((err = __verify_addr(ctx, addr_d)) < 0)
		return ERR_PTR(err);

	if (ctx->size - ctx->last_addr_a < size * 4)
		return ERR_PTR(-EINVAL);
	if (ctx->size - ctx->last_addr_b < size * 4)
		return ERR_PTR(-EINVAL);
	if (ctx->size - addr_d < size * 8)
		return ERR_PTR(-EINVAL);

	cmd = __command_alloc(_cmd);
	if (cmd != NULL) {
		cmd->cmd_u.run_mult.size = size;
		cmd->cmd_u.run_mult.addr_d = addr_d;
		return cmd;
	} else {
		return ERR_PTR(-EINVAL);
	}
}

/**
 * __command_run_redc_create - create monter_command struct assuming
 * that @_cmd has RUN_REDC type
 */
static struct monter_command *
__command_run_redc_create(struct monter_context *ctx, u32 _cmd)
{
	struct monter_command *cmd;
	u32 size;
	u32 addr_d;
	int err;

	BUG_ON(MONTER_SWCMD_TYPE(_cmd) != MONTER_SWCMD_TYPE_RUN_REDC);

	size = MONTER_SWCMD_RUN_SIZE(_cmd);
	addr_d = MONTER_SWCMD_ADDR_D(_cmd);
	if ((err = __verify_addr(ctx, addr_d)) < 0)
		return ERR_PTR(err);

	if (ctx->size - ctx->last_addr_a < 4)
		return ERR_PTR(-EINVAL);
	if (ctx->size - ctx->last_addr_b < size * 4)
		return ERR_PTR(-EINVAL);
	if (ctx->size - addr_d < size * 8)
		return ERR_PTR(-EINVAL);

	cmd = __command_alloc(_cmd);
	if (cmd != NULL) {
		cmd->cmd_u.run_redc.size = size;
		cmd->cmd_u.run_redc.addr_d = addr_d;
		return cmd;
	} else {
		return ERR_PTR(-EINVAL);
	}
}

/**
 * command_create - create and initialize monter_command struct
 */
static struct monter_command *
command_create(struct monter_context *ctx, u32 cmd)
{
	switch (MONTER_SWCMD_TYPE(cmd)) {
	case MONTER_SWCMD_TYPE_ADDR_AB:
		return __command_addr_ab_create(ctx, cmd);

	case MONTER_SWCMD_TYPE_RUN_MULT:
		/* 17b should be cleared */
		if (unlikely(cmd & (1 << 17)))
			return ERR_PTR(-EINVAL);
		if (ctx->first_cmd_type != MONTER_SWCMD_TYPE_ADDR_AB)
			return ERR_PTR(-EINVAL);
		return __command_run_mult_create(ctx, cmd);

	case MONTER_SWCMD_TYPE_RUN_REDC:
		/* 17b should be cleared */
		if (unlikely(cmd & (1 << 17)))
			return ERR_PTR(-EINVAL);
		if (ctx->first_cmd_type != MONTER_SWCMD_TYPE_ADDR_AB)
			return ERR_PTR(-EINVAL);
		return __command_run_redc_create(ctx, cmd);

	default:
		return ERR_PTR(-EINVAL);
	}
}

/**
 * command_destroy - releases resources allocated for struct monter_command
 *
 * Does not remove cmd from context's queue.
 */
static void
command_destroy(struct monter_command *cmd)
{
	kfree(cmd);
}

static void
monter_dev_enable_intr(struct monter_device_context *ctx)
{
	u32 flags;
	u32 intr;

	/* Reset - mainly for clearing the queue */
	flags = MONTER_RESET_CALC | MONTER_RESET_FIFO;
	__monter_reg_reset_write(ctx, flags);

	/* Zero current interrupts */
	intr = MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW;
	__monter_reg_intr_write(ctx, intr);

	/* Enable interrupts */
	__monter_reg_intr_enable_write(ctx, intr);
}

static void
monter_dev_reset(struct monter_device_context *ctx)
{
	u32 flags;

	/* Disables each block */
	__monter_reg_enable_write(ctx, 0);

	/* Disables interrupts */
	flags = MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW;
	__monter_reg_intr_enable_write(ctx, flags);

	/* Reset device */
	flags = MONTER_RESET_FIFO | MONTER_RESET_CALC;
	__monter_reg_reset_write(ctx, flags);
}

static void
monter_set_paging(struct monter_device_context *dctx, struct monter_context *ctx)
{
	size_t pages;
	u32 bus_addr;
	u32 cmd;
	unsigned int i;

	printk(KERN_INFO "monter: FIFO_FREE=%u\n", __monter_reg_fifo_free_read(dctx));
	BUG_ON(__monter_reg_fifo_free_read(dctx) < 32);

	pages = ctx->size / MONTER_PAGE_SIZE;
	bus_addr = ctx->dma_handle & 0xffffffffULL;

	for (i = 0; i < pages; ++i, bus_addr += MONTER_PAGE_SIZE) {
		cmd = MONTER_CMD_PAGE(i, bus_addr, 1);
		__monter_run_one_cmd(dctx, cmd);
	}
}

static ssize_t
monter_fops_write(struct file *filp, const char __user *input,
		  size_t count, loff_t *off)
{
	struct monter_context *ctx;
	struct monter_device_context *dctx;
	size_t command_count;
	const u32 __user *input_p;
	unsigned int i;
	struct monter_command *cmd_object;
	u32 cmd;
	u32 monter_cmd;
	int err;

	LIST_HEAD(cmd_queue);

	ctx = filp->private_data;
	dctx = ctx->dev_ctx;

	if (!CTX_INITIALIZED(ctx)) {
		printk(KERN_ERR "%s: context size not set\n", MONTER_NAME);
		return -EINVAL;
	}

	/* Received commands are 32-bit words, thus count must be divisible by 4 */
	if (count & 0x3) {
		printk(KERN_ERR "%s: count is not a multiple of 4\n", MONTER_NAME);
		return -EINVAL;
	}
	command_count = count / 4;

	for (i = 0, input_p = (const u32 __user *)input;
	     i < command_count;
	     ++i, ++input_p) {
		err = get_user(cmd, input_p); // NOTE: determines size with `user-space` type
		if (err != 0)
			goto failure;

		cmd_object = command_create(ctx, cmd);
		if (IS_ERR(cmd_object)) {
			err = PTR_ERR(cmd_object);
			goto failure;
		}
		if (ctx->first_cmd_type == MONTER_SWCMD_TYPE_INVALID) {
			ctx->first_cmd_type = cmd_object->type;
		}
		list_add_tail(&cmd_object->entry, &cmd_queue);
	}

	// Simplest: only one write is allowed to access the device
	mutex_lock(&dctx->dev_access_lock);

	// If this filp is not one which accessed Monter the last,
	// then we must update paging info in Monter.
	if (dctx->current_filp != filp) {
		dctx->current_filp = filp;
		monter_set_paging(dctx, ctx);
	}

	BUG_ON(__monter_reg_fifo_free_read(dctx) < 32);
	while (!list_empty(&cmd_queue)) {
		cmd_object = list_entry(cmd_queue.next, struct monter_command, entry);
		list_del(cmd_queue.next);

		switch (cmd_object->type) {
		case MONTER_SWCMD_TYPE_ADDR_AB:
			ctx->last_addr_a = cmd_object->cmd_u.addr_ab.addr_a;
			ctx->last_addr_b = cmd_object->cmd_u.addr_ab.addr_b;
			monter_cmd = MONTER_CMD_ADDR_AB(cmd_object->cmd_u.addr_ab.addr_a,
							cmd_object->cmd_u.addr_ab.addr_b,
							1);
			break;
		case MONTER_SWCMD_TYPE_RUN_MULT:
			monter_cmd = MONTER_CMD_RUN_MULT(cmd_object->cmd_u.run_mult.size,
							 cmd_object->cmd_u.run_mult.addr_d,
							 1);
			break;
		case MONTER_SWCMD_TYPE_RUN_REDC:
			monter_cmd = MONTER_CMD_RUN_REDC(cmd_object->cmd_u.run_redc.size,
							 cmd_object->cmd_u.run_redc.addr_d,
							 1);
			break;
		default:
			BUG_ON(true);  // Should not happen!
			break;
		}

		__monter_run_one_cmd(dctx, monter_cmd);
		command_destroy(cmd_object);
	}

	mutex_unlock(&dctx->dev_access_lock);
	return count;

failure:
	while (!list_empty(&cmd_queue)) {
		cmd_object = list_entry(cmd_queue.next, struct monter_command, entry);
		list_del(cmd_queue.next);
		command_destroy(cmd_object);
	}
	return err;
}

static long
monter_fops_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct monter_context *ctx;
	struct pci_dev *pdev;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);

	if (cmd != MONTER_IOCTL_SET_SIZE) {
		printk(KERN_ERR "%s: unsupported ioctl\n", MONTER_NAME);
		return -ENOTTY;
	}

	if (CTX_INITIALIZED(ctx)) {
		printk(KERN_ERR "%s: context size was already set\n", MONTER_NAME);
		return -EINVAL;
	}

	if (arg == 0 || arg > MONTER_MEM_SIZE || arg % MONTER_PAGE_SIZE != 0) {
		printk(KERN_ERR "%s: incorrect context size\n", MONTER_NAME);
		return -EINVAL;
	}

	pdev = ctx->dev_ctx->pdev;
	ctx->size = arg;

	ctx->data = dma_alloc_coherent(&pdev->dev, ctx->size,
				       &ctx->dma_handle, GFP_KERNEL);
	if (IS_ERR_OR_NULL(ctx->data)) {
		printk(KERN_ERR "%s: out of memory\n", MONTER_NAME);
		return -EINVAL;
	}

	return 0;
}

static int
monter_fops_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct monter_context *ctx;
	unsigned long kaddr;
	unsigned long uaddr;
	struct page *page;
	int err;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);

	if (!CTX_INITIALIZED(ctx))
		return -EINVAL;

	kaddr = (unsigned long)ctx->data + PAGE_SIZE * vma->vm_pgoff;
	uaddr = vma->vm_start;

	for (; uaddr < vma->vm_end; kaddr += PAGE_SIZE, uaddr += PAGE_SIZE) {
		page = virt_to_page(kaddr);
		get_page(page);

		err = vm_insert_page(vma, uaddr, page);
		if (err < 0)
			return err;
	}

	return 0;
}

static int
monter_fops_open(struct inode *inode, struct file *filp)
{
	struct monter_context *ctx;
	unsigned int entry_index;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		printk(KERN_ERR "%s: out of memory\n", MONTER_NAME);
		return -ENOMEM;
	}

	entry_index = iminor(inode);
	ctx->dev_ctx = &monter_entries[entry_index].dev_ctx;
	ctx->first_cmd_type = MONTER_SWCMD_TYPE_INVALID;

	filp->private_data = ctx;

	return 0;
}

static int
monter_fops_release(struct inode *inode, struct file *filp)
{
	struct monter_context *ctx;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);
	kfree(ctx);

	return 0;
}

static int
monter_fops_fsync(struct file *filp, loff_t off1, loff_t off2, int datasync)
{
	/* TODO(sodar): Implement asynchronous version */
	return 0;
}

static struct file_operations monter_fops = {
	.owner		= THIS_MODULE,
	.write		= monter_fops_write,
	.unlocked_ioctl	= monter_fops_ioctl,
	.mmap		= monter_fops_mmap,
	.open		= monter_fops_open,
	.release	= monter_fops_release,
	.fsync		= monter_fops_fsync,
};

static irqreturn_t
monter_irq_handler(int irq, void *data)
{
	struct monter_device_context *dctx = data;
	u32 intr;
	u32 ack;

	intr = __monter_reg_intr_read(dctx);
	if (!intr)
		return IRQ_NONE;

	ack = 0;
	if (intr & MONTER_INTR_NOTIFY) {
		ack |= MONTER_INTR_NOTIFY;
		/* Wait until device clears CALC status bit */
		while (__monter_reg_status_read(dctx) & MONTER_STATUS_CALC) {}
		atomic_set(&gnotify, 1);
	}
	if (intr & MONTER_INTR_INVALID_CMD) {
		#ifdef DEBUG
		printk(KERN_INFO "%s: %s(): INVALID_CMD received\n", MONTER_NAME, __func__);
		#endif
		ack |= MONTER_INTR_INVALID_CMD;
	}
	if (intr & MONTER_INTR_FIFO_OVERFLOW) {
		#ifdef DEBUG
		printk(KERN_INFO "%s: %s(): FIFO_OVERFLOW received\n", MONTER_NAME, __func__);
		#endif
		ack |= MONTER_INTR_FIFO_OVERFLOW;
	}

	__monter_reg_intr_write(dctx, ack);

	return IRQ_HANDLED;
}

static int
monter_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct monter_device_context *ctx;
	unsigned int entry_index;
	int ret;

	entry_index = claim_context_entry();
	if (entry_index == INDEX_CLAIM_FAILED)
		return -EINVAL;

	ctx = &monter_entries[entry_index].dev_ctx;
	ctx->pdev = pdev;
	ctx->entry_index = entry_index;

	/* Setup PCI device */
	ret = pci_enable_device(pdev);
	if (ret < 0) {
		printk(KERN_ERR "%s: pci_enable_device() failed err=%d\n", MONTER_NAME, ret);
		return ret;
	}

	/* Reserve PCI and I/O memory resources */
	ret = pci_request_regions(pdev, MONTER_NAME);
	if (ret < 0) {
		printk(KERN_ERR "%s: pci_request_regions() failed err=%d\n", MONTER_NAME, ret);
		return ret;
	}

	/* Map MMIO */
	ctx->bar0 = pci_iomap(pdev, 0, MONTER_MMIO_SIZE);
	if (IS_ERR_OR_NULL(ctx->bar0)) {
		printk(KERN_ERR "%s: pci_iomap() failed\n", MONTER_NAME);
		return -EINVAL;
	}

	/* Enable bus-mastering for this device */
	pci_set_master(pdev);

	/* Register IRQ handler for this device */
	ret = request_irq(pdev->irq, monter_irq_handler, IRQF_SHARED, MONTER_NAME, ctx);
	if (ret < 0) {
		printk(KERN_ERR "%s: request_ird() failed; err=%d\n", MONTER_NAME, ret);
		return ret;
	}

	monter_dev_enable_intr(ctx);

	cdev_init(&ctx->cdev, &monter_fops);
	ctx->cdev.owner = THIS_MODULE;
	ctx->devt = MKDEV(MAJOR(monter_dev_numbers), ctx->entry_index);

	ret = cdev_add(&ctx->cdev, ctx->devt, 1);
	if (ret < 0) {
		printk(KERN_ERR "%s: cdev_add failed\n", MONTER_NAME);
		return -EINVAL;
	}

	// TODO(sodar): Check parameters?
	ctx->device = device_create(monter_dev_class, NULL, ctx->devt, NULL,
			       "monter%u", ctx->entry_index);
	if (IS_ERR_OR_NULL(ctx->device)) {
		printk(KERN_ERR "%s: device_create() failed\n", MONTER_NAME);
		return -EINVAL;
	}

	pci_set_drvdata(pdev, ctx);

	#ifdef DEBUG
	printk(KERN_INFO "%s: %s() success\n", MONTER_NAME, __func__);
	#endif

	return 0;
}

static void
monter_pci_remove(struct pci_dev *pdev)
{
	struct monter_device_context *ctx;

	ctx = pci_get_drvdata(pdev);
	BUG_ON(ctx == NULL);
	pci_set_drvdata(pdev, NULL);

	device_destroy(monter_dev_class, ctx->devt);
	cdev_del(&ctx->cdev);

	/* Reset the Monter device to clean state */
	monter_dev_reset(ctx);

	/*
	 * According to Documentation/PCI/pci.txt pci_release_regions() must be called
	 * after pci_disable_device()
	 */
	free_irq(pdev->irq, ctx);
	pci_clear_master(pdev);
	pci_iounmap(pdev, ctx->bar0);
	pci_disable_device(pdev);
	pci_release_regions(pdev);

	release_context_entry(ctx->entry_index);

	#ifdef DEBUG
	printk(KERN_INFO "%s: %s() success\n", MONTER_NAME, __func__);
	#endif
}

static const struct pci_device_id pci_id_list[] = {
	{ PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID) },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, pci_id_list);

static struct pci_driver monter_pci_driver = {
	.name = MONTER_NAME,
	.id_table = pci_id_list,
	.probe = monter_pci_probe,
	.remove = monter_pci_remove,
};

static int __init monter_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&monter_dev_numbers, 0, MONTER_MAX_DEVICES, MONTER_NAME);
	if (ret < 0) {
		printk(KERN_ERR "%s: error on chrdev region allocation\n", MONTER_NAME);
		return ret;
	}

	monter_dev_class = class_create(THIS_MODULE, MONTER_NAME);
	if (IS_ERR(monter_dev_class)) {
		printk(KERN_ERR "%s: error create device class\n", MONTER_NAME);
		return PTR_ERR(monter_dev_class);
	}

	ret = pci_register_driver(&monter_pci_driver);
	if (ret < 0) {
		printk(KERN_ERR "%s: error registering PCI driver\n", MONTER_NAME);
		return ret;
	}

	return 0;
}

static void __exit monter_exit(void)
{
	pci_unregister_driver(&monter_pci_driver);

	if (monter_dev_class)
		class_destroy(monter_dev_class);

	if (monter_dev_numbers)
		unregister_chrdev_region(monter_dev_numbers, MONTER_MAX_DEVICES);
}

module_init(monter_init);
module_exit(monter_exit);
