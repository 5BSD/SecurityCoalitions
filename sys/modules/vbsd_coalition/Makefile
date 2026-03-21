# SPDX-License-Identifier: BSD-2-Clause
#
# vBSD Coalition kernel module Makefile
#

.PATH: ${SRCTOP}/sys/vbsd

KMOD=	vbsd_coalition
SRCS=	vbsd_coalition.c

# For development outside sys tree, use local path
.if !defined(SRCTOP)
.PATH: ${.CURDIR}/../../vbsd
.endif

CFLAGS+= -I${.CURDIR}/../../vbsd

# Debug options
.if defined(VBSD_DEBUG)
CFLAGS+= -DVBSD_DEBUG -g -O0
.endif

.include <bsd.kmod.mk>
