# SPDX-License-Identifier: BSD-2-Clause
#
# vBSD Coalition - Test Suite Makefile
#

PROG=		coalition_test
SRCS=		coalition_test.c test_harness.c

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I../sys/vbsd
CFLAGS+=	-g

LDFLAGS+=	-ljail

# Test binaries directory
BINDIR=		bin

.PHONY: all clean run

all: $(BINDIR) $(BINDIR)/$(PROG) $(BINDIR)/test_helper

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/$(PROG): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

$(BINDIR)/test_helper: test_helper.c
	$(CC) $(CFLAGS) -o $@ test_helper.c

clean:
	rm -rf $(BINDIR) *.o *.core

run: all
	@echo "=== vBSD Coalition Test Suite ==="
	@echo "Ensure module is loaded: kldstat | grep vbsd_coalition"
	@echo ""
	sudo $(BINDIR)/$(PROG)