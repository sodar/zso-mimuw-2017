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
static struct monter_device_context_entry monter_entries[MAX_DEVICES];
static DEFINE_SPINLOCK(monter_entries_lock);

static unsigned int
claim_context_entry(void)
{
	unsigned int index = INDEX_CLAIM_FAILED;
	unsigned int i;

	spin_lock(&monter_entries_lock);
	for (i = 0; i < MAX_DEVICES; ++i) {
		if (!monter_entries[i].taken) {
			memset(&monter_entries[i].dev_ctx, 0, sizeof(struct monter_device_context));
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
	BUG_ON(index > MAX_DEVICES);

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
		printk(KERN_ERR "%s: %s(): out of memory\n", DRIVER_NAME, __func__);
		#endif
		return NULL;
	}

	cmd->type = MONTER_SWCMD_TYPE(_cmd);

	return cmd;
}

/**
 * __command_addr_ab_create - create monter_command struct assuming
 * that @_cmd has ADDR_AB type
 */
static struct monter_command *
__command_addr_ab_create(u32 _cmd)
{
	struct monter_command *cmd;

	BUG_ON(MONTER_SWCMD_TYPE(_cmd) != MONTER_SWCMD_TYPE_ADDR_AB);

	cmd = __command_alloc(_cmd);
	if (cmd != NULL) {
		cmd->cmd_u.addr_ab.addr_a = MONTER_SWCMD_ADDR_A(_cmd);
		cmd->cmd_u.addr_ab.addr_b = MONTER_SWCMD_ADDR_B(_cmd);
		return cmd;
	} else {
		return ERR_PTR(-ENOMEM);
	}
}

/**
 * __command_run_mult_create - create monter_command struct assuming
 * that @_cmd has RUN_MULT type
 */
static struct monter_command *
__command_run_mult_create(u32 _cmd)
{
	struct monter_command *cmd;

	BUG_ON(MONTER_SWCMD_TYPE(_cmd) != MONTER_SWCMD_TYPE_RUN_MULT);

	cmd = __command_alloc(_cmd);
	if (cmd != NULL) {
		cmd->cmd_u.run_mult.size = MONTER_SWCMD_RUN_SIZE(_cmd);
		cmd->cmd_u.run_mult.addr_d = MONTER_SWCMD_ADDR_D(_cmd);
		return cmd;
	} else {
		return ERR_PTR(-ENOMEM);
	}
}

/**
 * __command_run_redc_create - create monter_command struct assuming
 * that @_cmd has RUN_REDC type
 */
static struct monter_command *
__command_run_redc_create(u32 _cmd)
{
	struct monter_command *cmd;

	BUG_ON(MONTER_SWCMD_TYPE(_cmd) != MONTER_SWCMD_TYPE_RUN_REDC);

	cmd = __command_alloc(_cmd);
	if (cmd != NULL) {
		cmd->cmd_u.run_redc.size = MONTER_SWCMD_RUN_SIZE(_cmd);
		cmd->cmd_u.run_redc.addr_d = MONTER_SWCMD_ADDR_D(_cmd);
		return cmd;
	} else {
		return ERR_PTR(-ENOMEM);
	}
}

/**
 * command_create - create and initialize monter_command struct
 */
static struct monter_command *
command_create(u32 cmd)
{
	switch (MONTER_SWCMD_TYPE(cmd)) {
	case MONTER_SWCMD_TYPE_ADDR_AB:
		return __command_addr_ab_create(cmd);
	case MONTER_SWCMD_TYPE_RUN_MULT:
		return __command_run_mult_create(cmd);
	case MONTER_SWCMD_TYPE_RUN_REDC:
		return __command_run_redc_create(cmd);
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
	u32 intr;

	intr = MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW;

	/* Zero current interrupts */
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

static ssize_t
monter_fops_write(struct file *filp, const char __user *input,
		  size_t count, loff_t *off)
{
	struct monter_context *ctx;
	size_t command_count;
	const u32 __user *input_p;
	unsigned int i;
	struct monter_command *cmd_object;
	u32 cmd;
	int ret;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);

	if (!CTX_INITIALIZED(ctx)) {
		printk(KERN_ERR "%s: context size not set\n", DRIVER_NAME);
		return -EINVAL;
	}

	/* Received commands are 32-bit words, thus count must be divisible by 4 */
	if (count % 4 != 0) {
		printk(KERN_ERR "%s: count is not a multiple of 4\n", DRIVER_NAME);
		return -EINVAL;
	}
	command_count = count / 4;

	for (i = 0, input_p = (const u32 __user *)input;
	     i < command_count;
	     ++i, ++input_p) {
		ret = get_user(cmd, input_p); // NOTE: determines size with `user-space` type
		if (ret != 0) {
			printk(KERN_ERR "%s: get_user failed\n", DRIVER_NAME);
			return ret;
		}

		cmd_object = command_create(cmd);
		if (IS_ERR(cmd_object)) {
			printk(KERN_ERR "%s: command_create failed\n", DRIVER_NAME);
			return PTR_ERR(cmd_object);
		}

		// TODO(sodar): some testing if it works
		#if 0
		// URGENT
		u32 cmd;
		switch (cmd_object->type) {
		case MONTER_SWCMD_TYPE_ADDR_AB:
			printk(KERN_INFO "%s: fifo_send ADDR_AB(%#x,%#x)\n",
			       DRIVER_NAME,
			       cmd_object->cmd_u.addr_ab.addr_a,
			       cmd_object->cmd_u.addr_ab.addr_b);
			cmd = MONTER_CMD_ADDR_AB(cmd_object->cmd_u.addr_ab.addr_a,
						 cmd_object->cmd_u.addr_ab.addr_b,
						 1);
			__monter_reg_fifo_send_write(monter_dev_ctx, cmd);
			break;
		case MONTER_SWCMD_TYPE_RUN_MULT:
			printk(KERN_INFO "%s: fifo_send RUN_MULT(%#x,%#x)\n",
			       DRIVER_NAME,
			       cmd_object->cmd_u.run_mult.size,
			       cmd_object->cmd_u.run_mult.addr_d);
			cmd = MONTER_CMD_RUN_MULT(cmd_object->cmd_u.run_mult.size,
						  cmd_object->cmd_u.run_mult.addr_d,
						  1);
			__monter_reg_fifo_send_write(monter_dev_ctx, cmd);
			break;
		default:
			break;
		}
		#endif

		// TODO(sodar): Before enqueuing commands, try to do it synchronously
		#if 0
		MONTER_CTX_LOCK(ctx);
		list_add_tail(&cmd_object->entry, &ctx->command_queue);
		MONTER_CTX_UNLOCK(ctx);
		#endif
	}

	return count;
}

static long
monter_fops_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct monter_context *ctx;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);

	if (cmd != MONTER_IOCTL_SET_SIZE) {
		printk(KERN_ERR "%s: unsupported ioctl\n", DRIVER_NAME);
		return -EINVAL;
	}

	if (ctx->size > 0) {
		printk(KERN_ERR "%s: context size was already set\n", DRIVER_NAME);
		return -EINVAL;
	}

	if (arg > 0 && arg % DRIVER_PAGE_SIZE == 0 && arg <= DRIVER_CTX_MAX_SIZE) {
		ctx->size = arg;
		ctx->data = dma_alloc_coherent(&ctx->dev_ctx->pdev->dev,
					       arg,
					       &ctx->dma_handle,
					       GFP_KERNEL);
		if (IS_ERR_OR_NULL(ctx->data)) {
			printk(KERN_ERR "%s: out of memory\n", DRIVER_NAME);
			return -ENOMEM;
		}

		return 0;
	} else {
		printk(KERN_ERR "%s: incorrect context size: %lu\n", DRIVER_NAME, ctx->size);
		return -EINVAL;
	}
}

static int
monter_fops_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct monter_context *ctx;
	unsigned long kpfn;
	int ret;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);

	if (!CTX_INITIALIZED(ctx))
		return -EINVAL;

	kpfn = __pa(ctx->data) >> PAGE_SHIFT;
	ret = remap_pfn_range(vma, vma->vm_start, kpfn,
			      vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if (ret < 0) {
		printk(KERN_ERR "%s: %s(): remap_pfn_range() failed; err=%d\n",
		       DRIVER_NAME, __func__, ret);
		return -ENOMEM;
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
		printk(KERN_ERR "%s: out of memory\n", DRIVER_NAME);
		return -ENOMEM;
	}

	entry_index = iminor(inode);
	ctx->dev_ctx = &monter_entries[entry_index].dev_ctx;

	ctx->size = 0;
	ctx->data = NULL;

	/* Initializes queue_lock and command_queue fields */
	MONTER_CTX_LOCK_INIT(ctx);
	MONTER_CTX_LOCK(ctx);
	INIT_LIST_HEAD(&ctx->command_queue);
	MONTER_CTX_UNLOCK(ctx);

	filp->private_data = ctx;

	return 0;
}

static int
monter_fops_release(struct inode *inode, struct file *filp)
{
	struct monter_context *ctx;
	struct list_head *head;
	struct list_head *entry;
	struct monter_command *cmd;

	ctx = filp->private_data;
	BUG_ON(ctx == NULL);

	MONTER_CTX_LOCK(ctx);
	head = &ctx->command_queue;
	while (!list_empty(head)) {
		entry = head->next;
		cmd = list_entry(entry, struct monter_command, entry);
		list_del(entry);
		#if defined(DEBUG)
		printk(KERN_INFO "%s: remove command; type=%u\n", DRIVER_NAME, cmd->type);
		#endif
		command_destroy(cmd);
	}
	MONTER_CTX_UNLOCK(ctx);

	if (ctx->data) {
		dma_free_coherent(&ctx->dev_ctx->pdev->dev, ctx->size,
				  ctx->data, ctx->dma_handle);
	}

	kfree(ctx);

	return 0;
}

static int
monter_fops_fsync(struct file *filp, loff_t off1, loff_t off2, int datasync)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	return -EINVAL;
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
monter_irq_handler(int irq, void *dev)
{
	struct monter_device_context *ctx;
	u32 intr;
	u32 ack;

	ctx = (struct monter_device_context *)dev;
	if (ctx != &monter_entries[ctx->entry_index].dev_ctx)
		return IRQ_NONE;

	#ifdef DEBUG
	printk(KERN_INFO "%s: %s() called\n", DRIVER_NAME, __func__);
	#endif

	ack = 0;
	intr = __monter_reg_intr_read(ctx);
	if (intr & MONTER_INTR_NOTIFY) {
		#ifdef DEBUG
		printk(KERN_INFO "%s: %s(): NOTIFY received\n", DRIVER_NAME, __func__);
		#endif
		ack |= MONTER_INTR_NOTIFY;
	}
	if (intr & MONTER_INTR_INVALID_CMD) {
		#ifdef DEBUG
		printk(KERN_INFO "%s: %s(): INVALID_CMD received\n", DRIVER_NAME, __func__);
		#endif
		ack |= MONTER_INTR_INVALID_CMD;
	}
	if (intr & MONTER_INTR_FIFO_OVERFLOW) {
		#ifdef DEBUG
		printk(KERN_INFO "%s: %s(): FIFO_OVERFLOW received\n", DRIVER_NAME, __func__);
		#endif
		ack |= MONTER_INTR_FIFO_OVERFLOW;
	}

	__monter_reg_intr_write(ctx, ack);

	return IRQ_HANDLED;
}

static int
monter_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	void __iomem *bar0;
	struct monter_device_context *ctx;
	struct device *device;
	unsigned int entry_index;
	int ret;

	entry_index = claim_context_entry();
	if (entry_index == INDEX_CLAIM_FAILED)
		return -EINVAL;

	ctx = &monter_entries[entry_index].dev_ctx;

	/* Setup PCI device */
	ret = pci_enable_device(pdev);
	if (ret < 0) {
		printk(KERN_ERR "%s: pci_enable_device() failed err=%d\n", DRIVER_NAME, ret);
		return ret;
	}

	ret = pci_request_regions(pdev, DRIVER_NAME);
	if (ret < 0) {
		printk(KERN_ERR "%s: pci_request_regions() failed err=%d\n", DRIVER_NAME, ret);
		return ret;
	}

	/* Map BAR0 (for monter it has 4096 bytes */
	bar0 = pci_iomap(pdev, 0, 4096);
	if (IS_ERR_OR_NULL(bar0)) {
		printk(KERN_ERR "%s: pci_iomap() failed\n", DRIVER_NAME);
		return -EINVAL;
	}

	/* Enable bus-mastering for this device */
	pci_set_master(pdev);
	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	if (ret < 0) {
		printk(KERN_ERR "%s: pci_set_dma_mask() failed err=%d\n", DRIVER_NAME, ret);
		return ret;
	}

	/* Notify Linux that this device has 32-bit DMA address space */
	ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
	if (ret < 0) {
		printk(KERN_ERR "%s: pci_set_consistent_dma_mask() failed err=%d\n",
		       DRIVER_NAME, ret);
		return ret;
	}

	/* Register IRQ handler for this device */
	ret = request_irq(pdev->irq, monter_irq_handler, IRQF_SHARED, DRIVER_NAME, ctx);
	if (ret < 0) {
		printk(KERN_ERR "%s: request_ird() failed; err=%d\n", DRIVER_NAME, ret);
		return ret;
	}

	/* Device context initialization begins here */
	ctx->pdev = pdev;
	ctx->bar0 = bar0;
	ctx->entry_index = entry_index;

	monter_dev_enable_intr(ctx);

	cdev_init(&ctx->cdev, &monter_fops);
	ctx->cdev.owner = THIS_MODULE;

	/* TODO(sodar): For the beginning only support /dev/monter1 */
	ctx->devt = MKDEV(MAJOR(monter_dev_numbers), ctx->entry_index);

	ret = cdev_add(&ctx->cdev, ctx->devt, 1);
	if (ret < 0) {
		printk(KERN_ERR "%s: cdev_add failed\n", DRIVER_NAME);
		return -EINVAL;
	}

	// TODO(sodar): Check parameters?
	device = device_create(monter_dev_class, NULL, ctx->devt, NULL,
			       "monter%u", ctx->entry_index);
	BUG_ON(device == NULL);

	pci_set_drvdata(pdev, ctx);

	#ifdef DEBUG
	printk(KERN_INFO "%s: %s() success\n", DRIVER_NAME, __func__);
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
	printk(KERN_INFO "%s: %s() success\n", DRIVER_NAME, __func__);
	#endif
}

static const struct pci_device_id pci_id_list[] = {
	{ PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID) },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, pci_id_list);

static struct pci_driver monter_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = pci_id_list,
	.probe = monter_pci_probe,
	.remove = monter_pci_remove,
};

static int __init monter_init_module(void)
{
	int ret;

	ret = alloc_chrdev_region(&monter_dev_numbers, 0, MAX_DEVICES, DRIVER_NAME);
	if (ret < 0) {
		printk(KERN_ERR "%s: error on chrdev region allocation\n", DRIVER_NAME);
		return ret;
	}

	monter_dev_class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(monter_dev_class)) {
		printk(KERN_ERR "%s: error create device class\n", DRIVER_NAME);
		return PTR_ERR(monter_dev_class);
	}

	ret = pci_register_driver(&monter_pci_driver);
	if (ret < 0) {
		printk(KERN_ERR "%s: error registering PCI driver\n", DRIVER_NAME);
		return ret;
	}

	return 0;
}

static void __exit monter_exit_module(void)
{
	pci_unregister_driver(&monter_pci_driver);

	if (monter_dev_class)
		class_destroy(monter_dev_class);

	if (monter_dev_numbers)
		unregister_chrdev_region(monter_dev_numbers, MAX_DEVICES);
}

module_init(monter_init_module);
module_exit(monter_exit_module);
