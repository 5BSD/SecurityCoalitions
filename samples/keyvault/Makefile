# SPDX-License-Identifier: BSD-2-Clause
#
# KeyVault sample module Makefile
#

KMOD=	vbsd_keyvault
SRCS=	vbsd_keyvault.c

# Include coalition header from our tree
CFLAGS+= -I${.CURDIR}/../../sys/vbsd

# For development, also check system headers
CFLAGS+= -I/usr/include

.include <bsd.kmod.mk>
