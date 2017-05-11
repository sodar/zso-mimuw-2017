/*
 * Author: Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>
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

static dev_t monter_numbers;
static struct class *monter_class;
static bool monter_pci_driver_registered;

static struct monter_device_context_entry monter_entries[MONTER_MAX_DEVICES];
static DEFINE_SPINLOCK(monter_entries_lock);

static void monter_tasklet_handler(unsigned long data);

static void
release_device_context(struct monter_device_context *dctx)
{
	spin_lock(&monter_entries_lock);
	tasklet_disable(&dctx->notify_tasklet);
	monter_entries[dctx->device_index].taken = false;
	spin_unlock(&monter_entries_lock);
}

static struct monter_device_context *
claim_device_context(void)
{
	struct monter_device_context *dctx;
	unsigned int index = INDEX_CLAIM_FAILED;
	unsigned int i;

	spin_lock(&monter_entries_lock);
	for (i = 0; i < MONTER_MAX_DEVICES; ++i) {
		if (!monter_entries[i].taken) {
			monter_entries[i].taken = true;
			index = i;
			break;
		}
	}
	spin_unlock(&monter_entries_lock);

	if (index != INDEX_CLAIM_FAILED) {
		dctx = &monter_entries[index].dev_ctx;
		memset(dctx, 0, sizeof(*dctx));

		dctx->device_index = index;
		mutex_init(&dctx->dev_access_lock);
		init_waitqueue_head(&dctx->notify_queue);
		atomic_set(&dctx->notify, 0);

		tasklet_init(&dctx->notify_tasklet, monter_tasklet_handler,
			     (unsigned long)dctx);

		return dctx;
	} else {
		return NULL;
	}
}

static struct monter_device_context *
minor_to_device(unsigned int minor)
{
	struct monter_device_context *dctx = &monter_entries[minor].dev_ctx;

	BUG_ON(!monter_entries[minor].taken);
	return dctx;
}

static void
monter_dev_enable(struct monter_device_context *dctx)
{
	/* Reset device - clear command queue */
	__monter_reg_reset_write(dctx, MONTER_RESET_CALC | MONTER_RESET_FIFO);

	/* Clear interrupt lines before enabling them */
	__monter_reg_intr_write(dctx, MONTER_INTR_NOTIFY);

	/* Enable required interrupts */
	__monter_reg_intr_enable_write(dctx, MONTER_INTR_NOTIFY);
}

static void
monter_dev_reset(struct monter_device_context *ctx)
{
	/* Disables each block */
	__monter_reg_enable_write(ctx, 0);

	/* Disables interrupts */
	__monter_reg_intr_enable_write(ctx, 0);

	/* Reset device */
	__monter_reg_reset_write(ctx, MONTER_RESET_FIFO | MONTER_RESET_CALC);
}

static int
monter_set_paging(struct monter_context *ctx)
{
	struct monter_device_context *dctx = ctx->dctx;
	size_t pages;
	uint32_t bus_addr;
	uint32_t cmd;
	unsigned int i;
	int ret;

	pages = ctx->size / MONTER_PAGE_SIZE;
	bus_addr = ctx->handle & 0xffffffffULL;

	for (i = 0; i < pages; ++i, bus_addr += MONTER_PAGE_SIZE) {
		cmd = MONTER_CMD_PAGE(i, bus_addr, 0);
		__monter_reg_fifo_send_write(dctx, cmd);

		cmd = MONTER_CMD_COUNTER(0, 1);
		__monter_reg_fifo_send_write(dctx, cmd);

		__monter_reg_enable_write(dctx, MONTER_ENABLE_CALC);

		/* Wait for notify signal */
		ret = wait_event_interruptible(dctx->notify_queue, atomic_read(&dctx->notify) == 1);
		if (ret < 0)
			return ret;
		atomic_set(&dctx->notify, 0);
	}

	return 0;
}

static int
validate_and_parse_commands(struct monter_context *ctx,
			    const char __user *input, size_t count,
			    uint32_t *output_cmd)
{
	const uint32_t *input_cmd;
	uint32_t cmd;
	uint32_t addr_a;
	uint32_t addr_b;
	uint32_t addr_d;
	uint32_t size;
	uint32_t last_addr_a;
	uint32_t last_addr_b;
	unsigned int i;
	int ret;

	input_cmd = (const uint32_t __user *)input;
	BUG_ON((uintptr_t)input_cmd & 0x3); // aligned to 4-byte

	last_addr_a = ctx->last_addr_a;
	last_addr_b = ctx->last_addr_b;

	for (i = 0; i < count; ++i, ++input_cmd) {
		ret = get_user(cmd, input_cmd);
		if (ret < 0)
			return -EINVAL;
		switch (MONTER_SWCMD_TYPE(cmd)) {
		case MONTER_SWCMD_TYPE_ADDR_AB:
			addr_a = MONTER_SWCMD_ADDR_A(cmd);
			if (addr_a >= ctx->size)
				return -EINVAL;
			addr_b = MONTER_SWCMD_ADDR_B(cmd);
			if (addr_b >= ctx->size)
				return -EINVAL;
			output_cmd[i] = MONTER_CMD_ADDR_AB(addr_a, addr_b, 0);
			last_addr_a = addr_a;
			last_addr_b = addr_b;
			break;

		case MONTER_SWCMD_TYPE_RUN_MULT:
			size = MONTER_SWCMD_RUN_SIZE(cmd);
			addr_d = MONTER_SWCMD_ADDR_D(cmd);
			if (addr_d >= ctx->size)
				return -EINVAL;
			if (!ctx->addr_ab_issued)
				return -EINVAL;
			if (ctx->size - last_addr_a < size * 4)
				return -EINVAL;
			if (ctx->size - last_addr_b < size * 4)
				return -EINVAL;
			if (ctx->size - addr_d < size * 8)
				return -EINVAL;
			if (cmd & (1 << 17)) // invalid bit
				return -EINVAL;
			output_cmd[i] = MONTER_CMD_RUN_MULT(size, addr_d, 0);
			break;

		case MONTER_SWCMD_TYPE_RUN_REDC:
			size = MONTER_SWCMD_RUN_SIZE(cmd);
			addr_d = MONTER_SWCMD_ADDR_D(cmd);
			if (addr_d >= ctx->size)
				return -EINVAL;
			if (!ctx->addr_ab_issued)
				return -EINVAL;
			if (ctx->size - last_addr_a < 4)
				return -EINVAL;
			if (ctx->size - last_addr_b < size * 4)
				return -EINVAL;
			if (ctx->size - addr_d < size * 8)
				return -EINVAL;
			if (cmd & (1 << 17)) // invalid bit
				return -EINVAL;
			output_cmd[i] = MONTER_CMD_RUN_REDC(size, addr_d, 0);
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

static ssize_t
monter_fops_write(struct file *filp, const char __user *input,
		  size_t count, loff_t *off)
{
	struct monter_context *ctx = filp->private_data;
	uint32_t *commands = NULL;
	size_t command_count;
	unsigned int i;
	int ret;

	if (!CTX_INITIALIZED(ctx)) {
		ret = -EINVAL;
		goto fail;
	}

	if (count == 0 || count % 4 != 0) {
		ret = -EINVAL;
		goto fail;
	}

	commands = kzalloc(count, GFP_KERNEL);
	if (commands == NULL) {
		ret = -EINVAL;
		goto fail;
	}

	command_count = count / 4;
	ret = validate_and_parse_commands(ctx, input, command_count, commands);
	if (ret) {
		goto fail;
	}

	ret = mutex_lock_interruptible(&ctx->dctx->dev_access_lock);
	if (ret < 0)
		goto fail;

	ret = monter_set_paging(ctx);
	if (ret < 0) {
		mutex_unlock(&ctx->dctx->dev_access_lock);
		goto fail;
	}
	for (i = 0; i < command_count; ++i) {
		if (MONTER_CMD_KIND(commands[i]) == MONTER_CMD_KIND_ADDR_AB) {
			ctx->addr_ab_issued = true;
			ctx->last_addr_a = MONTER_CMD_ADDR_A(commands[i]);
			ctx->last_addr_b = MONTER_CMD_ADDR_B(commands[i]);
		}

		__monter_reg_fifo_send_write(ctx->dctx, commands[i]);
		__monter_reg_fifo_send_write(ctx->dctx, MONTER_CMD_COUNTER(0, 1));
		__monter_reg_enable_write(ctx->dctx, MONTER_ENABLE_CALC);

		/* Wait for notify signal */
		ret = wait_event_interruptible(ctx->dctx->notify_queue,
					       atomic_read(&ctx->dctx->notify) == 1);
		if (ret < 0) {
			mutex_unlock(&ctx->dctx->dev_access_lock);
			goto fail;
		}
		atomic_set(&ctx->dctx->notify, 0);
	}

	mutex_unlock(&ctx->dctx->dev_access_lock);

	return count;

fail:
	if (commands)
		kfree(commands);

	return ret;
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

	pdev = ctx->dctx->pdev;
	ctx->data = dma_alloc_coherent(&pdev->dev, arg, &ctx->handle, GFP_KERNEL);
	if (IS_ERR_OR_NULL(ctx->data)) {
		printk(KERN_ERR "%s: out of memory\n", MONTER_NAME);
		return -EINVAL;
	}

	ctx->size = arg;

	ctx->addr_ab_issued = false;
	ctx->last_addr_a = ctx->size - 1;
	ctx->last_addr_b = ctx->size - 1;

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

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		printk(KERN_ERR "%s: out of memory\n", MONTER_NAME);
		return -ENOMEM;
	}

	ctx->dctx = minor_to_device(iminor(inode));
	filp->private_data = ctx;

	return 0;
}

static int
monter_fops_release(struct inode *inode, struct file *filp)
{
	struct monter_context *ctx;
	struct monter_device_context *dctx;
	struct pci_dev *pdev;

	ctx = filp->private_data;
	if (ctx == NULL)
		return 0;

	dctx = ctx->dctx;
	pdev = dctx->pdev;

	if (ctx->data)
		dma_free_coherent(&pdev->dev, ctx->size, ctx->data, ctx->handle);

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

static void
monter_tasklet_handler(unsigned long data)
{
	struct monter_device_context *dctx = (struct monter_device_context *)data;

	__monter_reg_enable_write(dctx, 0);
	atomic_set(&dctx->notify, 1);
	wake_up_interruptible(&dctx->notify_queue);
}

static irqreturn_t
monter_irq_handler(int irq, void *data)
{
	struct monter_device_context *dctx = data;
	uint32_t intr;

	intr = __monter_reg_intr_read(dctx);
	if (!intr)
		return IRQ_NONE;

	if (intr & MONTER_INTR_NOTIFY) {
		tasklet_schedule(&dctx->notify_tasklet);
	}

	__monter_reg_intr_write(dctx, intr);

	return IRQ_HANDLED;
}

static void
monter_pci_cleanup(struct pci_dev *pdev, struct monter_device_context *dctx)
{
	if (dctx->device)
		device_destroy(monter_class, dctx->devt);

	if (dctx->init.cdev_added)
		cdev_del(&dctx->cdev);

	if (dctx->init.dev_enabled)
		monter_dev_reset(dctx);

	if (dctx->init.irq_registered) {
		free_irq(pdev->irq, dctx);
	}

	if (dctx->init.pci_mastering)
		pci_clear_master(pdev);

	if (dctx->bar0)
		pci_iounmap(pdev, dctx->bar0);

	if (dctx->init.pci_enabled)
		pci_disable_device(pdev);

	if (dctx->init.pci_regions_reserved)
		pci_release_regions(pdev);

	if (dctx)
		release_device_context(dctx);
}

static int
monter_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct monter_device_context *dctx;
	struct cdev *cdev;
	int ret;

	dctx = claim_device_context();
	if (dctx == NULL) {
		ret = -EINVAL;
		goto fail;
	}

	dctx->pdev = pdev;

	/* Setup PCI device */
	ret = pci_enable_device(pdev);
	if (!ret) {
		dctx->init.pci_enabled = true;
	} else {
		goto fail;
	}

	/* Reserve PCI and I/O memory resources */
	ret = pci_request_regions(pdev, MONTER_NAME);
	if (!ret) {
		dctx->init.pci_regions_reserved = true;
	} else {
		goto fail;
	}

	/* Map MMIO */
	dctx->bar0 = pci_iomap(pdev, 0, MONTER_MMIO_SIZE);
	if (IS_ERR_OR_NULL(dctx->bar0)) {
		ret = -EINVAL;
		goto fail;
	}

	/* Enable bus-mastering for this device */
	pci_set_master(pdev);
	dctx->init.pci_mastering = true;

	/* Register IRQ handler for this device */
	ret = request_irq(pdev->irq, monter_irq_handler, IRQF_SHARED, MONTER_NAME, dctx);
	if (!ret) {
		dctx->init.irq_registered = true;
	} else {
		goto fail;
	}

	/* Enable device */
	monter_dev_enable(dctx);
	dctx->init.dev_enabled = true;

	/* Initialize and attach character device */
	cdev = &dctx->cdev;
	cdev_init(cdev, &monter_fops);
	cdev->owner = THIS_MODULE;
	dctx->devt = MKDEV(MAJOR(monter_numbers), dctx->device_index);
	ret = cdev_add(cdev, dctx->devt, 1);
	if (!ret) {
		dctx->init.cdev_added = true;
	} else {
		goto fail;
	}

	/* Create device noce */
	dctx->device = device_create(monter_class, NULL, dctx->devt, NULL,
				     "monter%u", dctx->device_index);
	if (IS_ERR_OR_NULL(dctx->device)) {
		ret = -EINVAL;
		goto fail;
	} else {
		#ifdef DEBUG
		printk(KERN_INFO "%s: attached /dev/monter%u\n", MONTER_NAME,
		       dctx->device_index);
		#endif
	}

	pci_set_drvdata(pdev, dctx);

	return 0;

fail:
	monter_pci_cleanup(pdev, dctx);
	return ret;
}

static void
monter_pci_remove(struct pci_dev *pdev)
{
	struct monter_device_context *dctx = pci_get_drvdata(pdev);

	monter_pci_cleanup(pdev, dctx);
}

static const struct pci_device_id monter_pci_id_list[] = {
	{ PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID) },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, monter_pci_id_list);

static struct pci_driver monter_pci_driver = {
	.name = MONTER_NAME,
	.id_table = monter_pci_id_list,
	.probe = monter_pci_probe,
	.remove = monter_pci_remove,
};

static void
monter_cleanup(void)
{
	if (monter_pci_driver_registered)
		pci_unregister_driver(&monter_pci_driver);
	if (monter_class)
		class_destroy(monter_class);
	if (monter_numbers)
		unregister_chrdev_region(monter_numbers, MONTER_MAX_DEVICES);
}

static int __init
monter_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&monter_numbers, 0, MONTER_MAX_DEVICES, MONTER_NAME);
	if (ret < 0) {
		goto fail;
	}

	monter_class = class_create(THIS_MODULE, MONTER_NAME);
	if (IS_ERR(monter_class)) {
		ret = PTR_ERR(monter_class);
		goto fail;
	}

	ret = pci_register_driver(&monter_pci_driver);
	if (!ret) {
		monter_pci_driver_registered = true;
	} else {
		goto fail;
	}

	return 0;

fail:
	monter_cleanup();
	return ret;
}

static void __exit
monter_exit(void)
{
	monter_cleanup();
}

module_init(monter_init);
module_exit(monter_exit);
