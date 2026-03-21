# SPDX-License-Identifier: BSD-2-Clause
#
# vBSD Coalition - Top-level Makefile
#

.PHONY: all module tests samples clean install install-headers

DESTDIR?=
INCLUDEDIR?= /usr/include

# Default target
all: module tests

# Build kernel module
module:
	$(MAKE) -C sys/modules/vbsd_coalition

# Build test suite
tests:
	$(MAKE) -C tests

# Build sample modules
samples:
	$(MAKE) -C samples

# Clean everything
clean:
	$(MAKE) -C sys/modules/vbsd_coalition clean
	$(MAKE) -C tests clean
	-$(MAKE) -C samples clean 2>/dev/null || true

# Install headers to /usr/include/sys/
install-headers:
	install -d $(DESTDIR)$(INCLUDEDIR)/sys
	install -m 644 sys/vbsd/vbsd_coalition.h $(DESTDIR)$(INCLUDEDIR)/sys/

# Install module and headers (requires root)
install: install-headers
	$(MAKE) -C sys/modules/vbsd_coalition install

# Load module for testing
load: module
	kldload ./sys/modules/vbsd_coalition/vbsd_coalition.ko

# Unload module
unload:
	kldunload vbsd_coalition

# Run tests (requires module loaded)
test: tests
	$(MAKE) -C tests run
