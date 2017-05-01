/*
 * Author: Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "monter.h"
#include "monter_ioctl.h"

MODULE_AUTHOR("Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>");
MODULE_DESCRIPTION("monter device driver");
MODULE_LICENSE("GPL");

static unsigned int next_chr_dev_num = 0;

static int
monter_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	/*
	 * TODO(sodar):
	 * - create character device for attached device
	 *   - select device number from range <0,255>
	 */

	unsigned int *chr_dev_num;

	chr_dev_num = (unsigned int *)kmalloc(sizeof(*chr_dev_num), GFP_KERNEL);
	if (chr_dev_num == NULL) {
		return -ENODEV;
	}

	*chr_dev_num = next_chr_dev_num++;
	next_chr_dev_num %= 256;
	pci_set_drvdata(dev, chr_dev_num);

	printk(KERN_INFO "monter: PCI device probe; chr_dev_num = %u\n", *chr_dev_num);

	return 0;
}

static void
monter_pci_remove(struct pci_dev *dev)
{
	/*
	 * TODO(sodar):
	 * - remove assigned character device and free up number slot
	 */

	unsigned int *chr_dev_num_ptr;
	unsigned int chr_dev_num;

	chr_dev_num_ptr = (unsigned int *)pci_get_drvdata(dev);
	BUG_ON(chr_dev_num_ptr == NULL);

	chr_dev_num = *chr_dev_num_ptr;
	kfree(chr_dev_num_ptr);

	printk(KERN_INFO "monter: PCI device remove; chr_dev_num = %u\n", chr_dev_num);
}

static struct pci_device_id monter_pci_device_id = {
	PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID),
	.class = 0,
	.class_mask = 0,
};

static struct pci_driver monter_pci_driver = {
	.name = "monter",
	.id_table = &monter_pci_device_id,
	.probe = monter_pci_probe,
	.remove = monter_pci_remove,
};

static int __init monter_init_module(void)
{
	int ret;

	ret = pci_register_driver(&monter_pci_driver);
	if (ret < 0) {
		printk(KERN_INFO "monter: error registering PCI driver\n");
		return ret;
	}

	printk(KERN_INFO "monter: initialised\n");
	return 0;
}

static void __exit monter_exit_module(void)
{
	pci_unregister_driver(&monter_pci_driver);

	printk(KERN_INFO "monter: exit\n");
}

module_init(monter_init_module);
module_exit(monter_exit_module);
