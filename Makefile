# SPDX-License-Identifier: BSD-2-Clause
#
# vBSD Coalition - Top-level Makefile
#

.PHONY: all module tests samples clean install install-headers install-man \
	uninstall load unload test stress lint help

DESTDIR?=
PREFIX?=	/usr/local
INCLUDEDIR?=	/usr/include
MANDIR?=	$(PREFIX)/man

# Default target
all: module tests

# Show help
help:
	@echo "vBSD Coalition Build System"
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build module and tests (default)"
	@echo "  module       - Build kernel module"
	@echo "  tests        - Build test suite"
	@echo "  samples      - Build sample modules (e.g., keyvault)"
	@echo ""
	@echo "Install targets:"
	@echo "  install      - Install module, headers, and man pages"
	@echo "  install-headers - Install headers to $(INCLUDEDIR)/sys/"
	@echo "  install-man  - Install man pages to $(MANDIR)/"
	@echo "  uninstall    - Remove installed files"
	@echo ""
	@echo "Test targets:"
	@echo "  test         - Run test suite (requires module loaded)"
	@echo "  stress       - Run stress tests"
	@echo "  load         - Load kernel module"
	@echo "  unload       - Unload kernel module"
	@echo ""
	@echo "Maintenance targets:"
	@echo "  clean        - Remove build artifacts"
	@echo "  lint         - Run static analysis"
	@echo ""
	@echo "Variables:"
	@echo "  DESTDIR      - Installation root (default: empty)"
	@echo "  PREFIX       - Installation prefix (default: /usr/local)"
	@echo "  INCLUDEDIR   - Header installation dir (default: /usr/include)"
	@echo "  MANDIR       - Man page installation dir (default: $(PREFIX)/man)"

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

# Install man pages
install-man:
	install -d $(DESTDIR)$(MANDIR)/man4
	install -d $(DESTDIR)$(MANDIR)/man9
	install -m 644 man/man4/vbsd_coalition.4 $(DESTDIR)$(MANDIR)/man4/
	install -m 644 man/man9/vbsd_coalition.9 $(DESTDIR)$(MANDIR)/man9/

# Install module, headers, and man pages (requires root)
install: install-headers install-man
	$(MAKE) -C sys/modules/vbsd_coalition install

# Uninstall everything
uninstall:
	rm -f $(DESTDIR)$(INCLUDEDIR)/sys/vbsd_coalition.h
	rm -f $(DESTDIR)$(MANDIR)/man4/vbsd_coalition.4
	rm -f $(DESTDIR)$(MANDIR)/man9/vbsd_coalition.9
	rm -f $(DESTDIR)/boot/modules/vbsd_coalition.ko
	@echo "Note: Run 'makewhatis $(MANDIR)' to update man database"

# Load module for testing
load: module
	kldload ./sys/modules/vbsd_coalition/vbsd_coalition.ko

# Unload module
unload:
	kldunload vbsd_coalition

# Run tests (requires module loaded)
test: tests
	$(MAKE) -C tests run

# Run stress tests
stress: tests
	$(MAKE) -C tests stress

# Static analysis / linting
lint:
	@echo "=== Checking kernel module ==="
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,style --quiet \
			-I/usr/src/sys -I sys/vbsd \
			sys/vbsd/vbsd_coalition.c; \
	else \
		echo "cppcheck not found, skipping"; \
	fi
	@echo ""
	@echo "=== Checking for common issues ==="
	@grep -n "TODO\|FIXME\|XXX\|HACK" sys/vbsd/*.c sys/vbsd/*.h 2>/dev/null || echo "No TODO/FIXME found"
	@echo ""
	@echo "=== Checking man pages ==="
	@for f in man/man4/*.4 man/man9/*.9; do \
		echo "Checking $$f..."; \
		mandoc -Tlint "$$f" 2>&1 | grep -v "skipping" || true; \
	done
