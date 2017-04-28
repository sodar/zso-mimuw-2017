/*
 * Author: Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>
 */
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_AUTHOR("Dariusz Sosnowski <ds384373@students.mimuw.edu.pl>");
MODULE_DESCRIPTION("monter device driver");
MODULE_LICENSE("GPL");

static int __init monter_init_module(void)
{
	printk(KERN_INFO "monter: %s called\n", __func__);

	return 0;
}

static void __exit monter_exit_module(void)
{
	printk(KERN_INFO "monter: %s called\n", __func__);
}

module_init(monter_init_module);
module_exit(monter_exit_module);
