/*
TODO(sodar):

- Support multiple Monter devices
	- Dynamic allocation of minor numbers
*/

/*
 * Author: Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>
 */
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

#include "monter.h"
#include "monter_ioctl.h"

#define DRIVER_NAME "monter"
#define MAX_DEVICES (256)

MODULE_AUTHOR("Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>");
MODULE_DESCRIPTION("ZSO: task #2: monter device driver");
MODULE_LICENSE("GPL");

struct monter_device_context {
	struct cdev cdev;
	dev_t devt;
};

static dev_t monter_dev_numbers;
static struct class *monter_dev_class;

static ssize_t
monter_fops_write(struct file *file, const char __user *input,
		  size_t count, loff_t *off)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	/* TODO(sodar): Implement */

	return count;
}

static long
monter_fops_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	/* TODO(sodar): Implement */

	return -EINVAL;
}

static int
monter_fops_mmap(struct file *file, struct vm_area_struct *vm)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	/* TODO(sodar): Implement */

	return -EINVAL;
}

static int
monter_fops_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	/* TODO(sodar): Implement */

	return 0;
}

static int
monter_fops_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	/* TODO(sodar): Implement */

	return 0;
}

static int
monter_fops_fsync(struct file *file, loff_t off1, loff_t off2, int datasync)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	/* TODO(sodar): Implement */

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

static int
monter_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct monter_device_context *ctx;
	struct device *device;
	dev_t cdev_major;
	dev_t cdev_minor;
	dev_t cdev_numbers;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		printk(KERN_ERR "%s: out of memory\n", DRIVER_NAME);
		return -ENOMEM;
	}

	cdev_init(&ctx->cdev, &monter_fops);
	ctx->cdev.owner = THIS_MODULE;

	cdev_major = MAJOR(monter_dev_numbers);
	cdev_minor = MINOR(monter_dev_numbers);
	cdev_numbers = MKDEV(cdev_major, cdev_minor + 1); // TODO(sodar): For the beginning, /dev/monter1
	ctx->devt = cdev_numbers;

	ret = cdev_add(&ctx->cdev, ctx->devt, 1);
	if (ret < 0) {
		printk(KERN_ERR "%s: cdev_add failed\n", DRIVER_NAME);
		return -EINVAL;
	}

	// TODO(sodar): Check parameters?
	device = device_create(monter_dev_class, NULL, cdev_numbers, NULL,
				    "monter%u", MINOR(ctx->devt));
	BUG_ON(device == NULL);

	pci_set_drvdata(dev, ctx);

	return 0;
}

static void
monter_pci_remove(struct pci_dev *dev)
{
	struct monter_device_context *ctx;

	ctx = pci_get_drvdata(dev);
	BUG_ON(ctx == NULL);
	pci_set_drvdata(dev, NULL);

	device_destroy(monter_dev_class, ctx->devt);
	cdev_del(&ctx->cdev);
	kfree(ctx);
}

static const struct pci_device_id pci_id_list[] = {
	{
	PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID),
	.class = 0,
	.class_mask = 0,
	},
	{0, 0, 0},
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

	/* NOTE(sodar): Only for debug */
	printk(KERN_INFO "%s: major=%u minor=%u\n", DRIVER_NAME,
		MAJOR(monter_dev_numbers), MINOR(monter_dev_numbers));

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
