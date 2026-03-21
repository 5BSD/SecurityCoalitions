# SPDX-License-Identifier: BSD-2-Clause
#
# vBSD Coalition - Test Suite Makefile
#

PROG=		coalition_test
STRESS_PROG=	stress_test
SRCS=		coalition_test.c test_harness.c
STRESS_SRCS=	stress_test.c

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I../sys/vbsd
CFLAGS+=	-g

LDFLAGS+=	-ljail

# Test binaries directory
BINDIR=		bin

.PHONY: all clean run stress

all: $(BINDIR) $(BINDIR)/$(PROG) $(BINDIR)/$(STRESS_PROG) $(BINDIR)/test_helper

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/$(PROG): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

$(BINDIR)/$(STRESS_PROG): $(STRESS_SRCS)
	$(CC) $(CFLAGS) -o $@ $(STRESS_SRCS)

$(BINDIR)/test_helper: test_helper.c
	$(CC) $(CFLAGS) -o $@ test_helper.c

clean:
	rm -rf $(BINDIR) *.o *.core

run: all
	@echo "=== vBSD Coalition Test Suite ==="
	@echo "Ensure module is loaded: kldstat | grep vbsd_coalition"
	@echo ""
	sudo $(BINDIR)/$(PROG)

stress: all
	@echo "=== vBSD Coalition Stress Tests ==="
	@echo "Ensure module is loaded: kldstat | grep vbsd_coalition"
	@echo ""
	sudo $(BINDIR)/$(STRESS_PROG)