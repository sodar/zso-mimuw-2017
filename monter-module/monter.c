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
#include <linux/workqueue.h>

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

static void monter_ctx_work_handler(struct work_struct *work);
static void monter_tasklet_handler(unsigned long data);

static void
release_device_context(struct monter_device_context *dctx)
{
	BUG_ON(dctx == NULL);

	spin_lock(&monter_entries_lock);
	monter_entries[dctx->device_index].taken = false;
	monter_entries[dctx->device_index].dev_ctx = NULL;
	spin_unlock(&monter_entries_lock);

	if (dctx->dev_workqueue) {
		flush_workqueue(dctx->dev_workqueue);
		destroy_workqueue(dctx->dev_workqueue);
	}
	tasklet_disable(&dctx->notify_tasklet);
	kfree(dctx);
}

static struct monter_device_context *
claim_device_context(void)
{
	struct monter_device_context *dctx = NULL;
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
		dctx = kzalloc(sizeof(*dctx), GFP_KERNEL);
		if (dctx == NULL) {
			spin_lock(&monter_entries_lock);
			monter_entries[index].taken = false;
			monter_entries[index].dev_ctx = NULL;
			spin_unlock(&monter_entries_lock);
			return NULL;
		}

		monter_entries[index].dev_ctx = dctx;

		dctx->device_index = index;
		mutex_init(&dctx->dev_access_lock);
		init_waitqueue_head(&dctx->notify_queue);
		atomic_set(&dctx->notify, 0);
		init_waitqueue_head(&dctx->fsync_queue);

		tasklet_init(&dctx->notify_tasklet, monter_tasklet_handler,
			     (unsigned long)dctx);

		spin_lock_init(&dctx->index_lock);
		dctx->index = 1;

		dctx->dev_workqueue = create_singlethread_workqueue(MONTER_NAME);
		if (dctx->dev_workqueue == NULL)
			goto fail;

		return dctx;
	} else {
		return NULL;
	}

fail:
	release_device_context(dctx);
	return NULL;
}

static struct monter_device_context *
minor_to_device(unsigned int minor)
{
	struct monter_device_context *dctx = monter_entries[minor].dev_ctx;

	BUG_ON(!monter_entries[minor].taken);
	return dctx;
}

static uint32_t
fetch_and_incr_command_index(struct monter_device_context *dctx)
{
	uint32_t index;

	spin_lock(&dctx->index_lock);
	index = dctx->index;
	dctx->index = (dctx->index + 1) % (1 << 24);
	if (dctx->index == 0)
		dctx->index += 1;
	spin_unlock(&dctx->index_lock);

	return index;
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

	/* Enable monter blocks */
	__monter_reg_enable_write(dctx, MONTER_ENABLE_CALC);
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

#if 0
static int
monter_set_paging(struct monter_context *ctx)
{
	struct monter_device_context *dctx = ctx->dctx;
	size_t pages;
	uint32_t bus_addr;
	uint32_t cmd;
	unsigned int i;

	pages = ctx->size / MONTER_PAGE_SIZE;
	bus_addr = ctx->handle & 0xffffffffULL;

	for (i = 0; i < pages; ++i, bus_addr += MONTER_PAGE_SIZE) {
		cmd = MONTER_CMD_PAGE(i, bus_addr, 0);
		__monter_reg_fifo_send_write(dctx, cmd);
	}

	return 0;
}
#endif

static size_t
prepare_page_cmd(struct monter_context *ctx,
		 struct monter_command *page_cmd, const size_t count)
{
	size_t pages;
	uint32_t bus_addr;
	unsigned int i;

	pages = ctx->size / MONTER_PAGE_SIZE;
	BUG_ON(pages > count);

	bus_addr = ctx->handle & 0xffffffffULL;
	for (i = 0; i < pages; ++i, bus_addr += MONTER_PAGE_SIZE) {
		page_cmd[i].index = 0;
		page_cmd[i].cmd = MONTER_CMD_PAGE(i, bus_addr, 0);
		list_init(&page_cmd[i].list_entry);
	}

	return pages;
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

	bool addr_ab_issued;
	uint32_t last_addr_a;
	uint32_t last_addr_b;

	unsigned int i;
	int ret;

	input_cmd = (const uint32_t __user *)input;
	BUG_ON((uintptr_t)input_cmd & 0x3); // aligned to 4-byte

	addr_ab_issued = ctx->addr_ab_issued;
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
			addr_ab_issued = true;
			last_addr_a = addr_a;
			last_addr_b = addr_b;
			break;

		case MONTER_SWCMD_TYPE_RUN_MULT:
			size = MONTER_SWCMD_RUN_SIZE(cmd);
			addr_d = MONTER_SWCMD_ADDR_D(cmd);
			if (addr_d >= ctx->size)
				return -EINVAL;
			if (!addr_ab_issued)
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
			if (!addr_ab_issued)
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

static int
create_command_list(const uint32_t *commands, const size_t command_count,
		    struct list_head *head)
{
	struct monter_command *cmd;
	struct monter_command *cmd_next;
	unsigned int i;

	BUG_ON(!list_empty(head));

	for (i = 0; i < command_count; ++i) {
		cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
		if (cmd == NULL)
			goto fail;
		cmd->cmd = commands[i];
		list_add_tail(&cmd->list_entry, head);
	}

	return 0;

fail:
	list_for_each_entry_safe(cmd, cmd_next, head, list_entry) {
		list_del(&cmd->list_entry);
		kfree(cmd);
	}
	return -ENOMEM;
}

static ssize_t
monter_fops_write(struct file *filp, const char __user *input,
		  size_t count, loff_t *off)
{
	struct monter_context *ctx = filp->private_data;
	uint32_t *commands = NULL;
	size_t command_count;
	struct list_head command_list;
	struct monter_command *cmd;
	struct monter_command *tmp;
	int ret;

	list_init(&command_list);

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

	ret = create_command_list(commands, command_count, &command_list);
	if (ret)
		goto fail;

	list_for_each_entry(cmd, &command_list, list_entry) {
		cmd->index = fetch_and_incr_command_index(ctx->dctx);
	}

	ret = mutex_lock_interruptible(&ctx->cmd_queue_lock);
	if (ret < 0)
		goto fail;

	list_for_each_entry(cmd, &command_list, list_entry) {
		ctx->last_index = cmd->index;
		if (MONTER_CMD_KIND(cmd->cmd) == MONTER_CMD_KIND_ADDR_AB) {
			ctx->addr_ab_issued = true;
			ctx->last_addr_a = MONTER_CMD_ADDR_A(cmd->cmd);
			ctx->last_addr_b = MONTER_CMD_ADDR_B(cmd->cmd);
		}
	}
	list_splice_tail(&command_list, &ctx->cmd_queue);

	mutex_unlock(&ctx->cmd_queue_lock);

	if (!work_pending(&ctx->cmd_work)) {
		queue_work(ctx->dctx->dev_workqueue, &ctx->cmd_work);
	}

	return count;

fail:
	list_for_each_entry_safe(cmd, tmp, &command_list, list_entry) {
		list_del(&cmd->list_entry);
		kfree(cmd);
	}
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

	mutex_init(&ctx->cmd_queue_lock);
	list_init(&ctx->cmd_queue);
	ctx->last_index = 0;
	atomic_set(&ctx->last_run_index, 0);
	ctx->last_issued_addr_ab = 0;

	INIT_WORK(&ctx->cmd_work, monter_ctx_work_handler);

	filp->private_data = ctx;

	return 0;
}

static int
monter_fops_release(struct inode *inode, struct file *filp)
{
	struct monter_context *ctx;
	struct monter_device_context *dctx;
	struct pci_dev *pdev;
	struct monter_command *cmd;
	struct monter_command *next_cmd;

	ctx = filp->private_data;
	if (ctx == NULL)
		return 0;

	dctx = ctx->dctx;
	pdev = dctx->pdev;

	cancel_work_sync(&ctx->cmd_work);

	mutex_lock(&ctx->cmd_queue_lock);
	list_for_each_entry_safe(cmd, next_cmd, &ctx->cmd_queue, list_entry) {
		list_del(&cmd->list_entry);
		kfree(cmd);
	}
	mutex_unlock(&ctx->cmd_queue_lock);

	if (ctx->data)
		dma_free_coherent(&pdev->dev, ctx->size, ctx->data, ctx->handle);

	kfree(ctx);

	return 0;
}

static int
monter_fops_fsync(struct file *filp, loff_t off1, loff_t off2, int datasync)
{
	struct monter_context *ctx = filp->private_data;
	int ret;

	ret = wait_event_interruptible(ctx->dctx->fsync_queue,
				       atomic_read(&ctx->last_run_index) == ctx->last_index);
	if (ret < 0)
		return ret;

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
monter_ctx_work_handler(struct work_struct *work)
{
	struct monter_context *ctx = container_of(work, struct monter_context, cmd_work);
	struct monter_command page_cmd[MONTER_PAGE_NUM];
	size_t page_cmd_count;
	size_t available_cmd;

	struct monter_command *cmd;
	struct monter_command *next_cmd;
	struct list_head work_cmd_queue;

	uint32_t enable_reg;
	uint32_t last_index = 0;
	uint32_t counter_reg;
	unsigned int i;

	list_init(&work_cmd_queue);

	/* In the single work driver expects to issue a maximum of 32 commands */
	page_cmd_count = prepare_page_cmd(ctx, page_cmd, ARRAY_SIZE(page_cmd));
	BUG_ON(page_cmd_count == 0 || page_cmd_count > 16);

	/* PAGE commands, one COUNTER commands, one last ADDR_AB */
	available_cmd = 32 - page_cmd_count - 2;

	/* Take maximum amount of commands to push to queue */
	mutex_lock(&ctx->cmd_queue_lock);
	if (list_empty(&ctx->cmd_queue)) {
		mutex_unlock(&ctx->cmd_queue_lock);
		atomic_set(&ctx->last_run_index, ctx->last_index);
		wake_up_interruptible(&ctx->dctx->fsync_queue);
		return;
	}
	list_for_each_entry_safe(cmd, next_cmd, &ctx->cmd_queue, list_entry) {
		if (available_cmd == 0)
			break;

		list_move_tail(&cmd->list_entry, &work_cmd_queue);
		available_cmd--;
	}
	mutex_unlock(&ctx->cmd_queue_lock);

	/* Set notify flag to 0 */
	atomic_set(&ctx->dctx->notify, 0);

	/* Ensure that monter CALC is set to 1 */
	enable_reg = __monter_reg_enable_read(ctx->dctx);
	enable_reg |= MONTER_ENABLE_CALC;
	__monter_reg_enable_write(ctx->dctx, enable_reg);

	/* Push PAGE commands*/
	for (i = 0; i < page_cmd_count; ++i)
		__monter_reg_fifo_send_write(ctx->dctx, page_cmd[i].cmd);
	
	/* One last ADDR_AB (if any) */
	if (ctx->last_issued_addr_ab)
		__monter_reg_fifo_send_write(ctx->dctx, ctx->last_issued_addr_ab);

	/* Run commands */
	list_for_each_entry_safe(cmd, next_cmd, &work_cmd_queue, list_entry) {
		if (MONTER_CMD_KIND(cmd->cmd) == MONTER_CMD_KIND_ADDR_AB) {
			ctx->last_issued_addr_ab = cmd->cmd;
		}
		__monter_reg_fifo_send_write(ctx->dctx, cmd->cmd);
		last_index = cmd->index;
		list_del(&cmd->list_entry);
		kfree(cmd);
	}

	/* Push COUNTER command */
	__monter_reg_fifo_send_write(ctx->dctx, MONTER_CMD_COUNTER(last_index, 1));

	wait_event(ctx->dctx->notify_queue, atomic_read(&ctx->dctx->notify) == 1);

	counter_reg = __monter_reg_counter_read(ctx->dctx);
	atomic_set(&ctx->last_run_index, counter_reg);

	mutex_lock(&ctx->cmd_queue_lock);
	if (list_empty(&ctx->cmd_queue)) {
		wake_up_interruptible(&ctx->dctx->fsync_queue);
	} else {
		queue_work(ctx->dctx->dev_workqueue, &ctx->cmd_work);
	}
	mutex_unlock(&ctx->cmd_queue_lock);
}

static void
monter_tasklet_handler(unsigned long data)
{
	struct monter_device_context *dctx = (struct monter_device_context *)data;
	atomic_set(&dctx->notify, 1);
	wake_up(&dctx->notify_queue);
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
