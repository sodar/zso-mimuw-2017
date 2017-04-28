#ifndef MONTER_IOCTL_H
#define MONTER_IOCTL_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdint.h>
#endif

#include <linux/ioctl.h>

#define MONTER_IOCTL_SET_SIZE _IO('m', 0x00)

/* Commands */

#define MONTER_SWCMD_TYPE(cmd)		((cmd) & 0xf)
#define MONTER_SWCMD_TYPE_ADDR_AB	0x0
#define MONTER_SWCMD_TYPE_RUN_MULT	0x1
#define MONTER_SWCMD_TYPE_RUN_REDC	0x2

#define MONTER_SWCMD_ADDR_AB(a, b)	(MONTER_SWCMD_TYPE_ADDR_AB | ((a) >> 2) << 4 | ((b) >> 2) << 18)
#define MONTER_SWCMD_RUN_MULT(sz, d)	(MONTER_SWCMD_TYPE_RUN_MULT | ((sz) - 1) << 4 | ((d) >> 2) << 18)
#define MONTER_SWCMD_RUN_REDC(sz, d)	(MONTER_SWCMD_TYPE_RUN_REDC | ((sz) - 1) << 4 | ((d) >> 2) << 18)

#define MONTER_SWCMD_ADDR_A(cmd)	(((cmd) >> 4 & 0x3fff) << 2)
#define MONTER_SWCMD_ADDR_B(cmd)	(((cmd) >> 18 & 0x3fff) << 2)
#define MONTER_SWCMD_RUN_SIZE(cmd)	(((cmd) >> 4 & 0x1fff) + 1)
#define MONTER_SWCMD_ADDR_D(cmd)	(((cmd) >> 18 & 0x3fff) << 2)

#endif
