#!/bin/sh
#
# VM Test Script for SecurityCoalitions
#
# Run this on the FreeBSD VM after deploying.
# Loads pre-built modules, runs tests, then cleans up.
#

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}==>${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}==> WARNING:${NC} %s\n" "$1"
}

error() {
    printf "${RED}==> ERROR:${NC} %s\n" "$1"
}

cleanup() {
    info "Cleaning up..."

    # Unload modules (ignore errors if not loaded)
    kldunload vbsd_keyvault 2>/dev/null || true
    kldunload vbsd_coalition 2>/dev/null || true

    info "Cleanup complete"
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Check we're root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root"
    exit 1
fi

# Check binaries exist
if [ ! -f ./sys/modules/vbsd_coalition/vbsd_coalition.ko ]; then
    error "vbsd_coalition.ko not found - build locally first"
    exit 1
fi

if [ ! -f ./tests/bin/coalition_test ]; then
    error "tests/bin/coalition_test not found - build locally first"
    exit 1
fi

# Unload any existing modules first
info "Unloading any existing modules..."
kldunload vbsd_keyvault 2>/dev/null || true
kldunload vbsd_coalition 2>/dev/null || true

info "Loading vbsd_coalition module..."
kldload ./sys/modules/vbsd_coalition/vbsd_coalition.ko

# Verify module loaded
if ! kldstat | grep -q vbsd_coalition; then
    error "Failed to load vbsd_coalition module"
    exit 1
fi

# Check device exists
if [ ! -c /dev/vbsd_coalition ]; then
    error "/dev/vbsd_coalition not found"
    exit 1
fi

info "Module loaded successfully"
info "  Device: /dev/vbsd_coalition"
sysctl kern.vbsd_coalition.count 2>/dev/null || true

if [ -f ./samples/keyvault/vbsd_keyvault.ko ]; then
    info "Loading vbsd_keyvault sample module..."
    kldload ./samples/keyvault/vbsd_keyvault.ko || warn "Failed to load keyvault (optional)"

    if kldstat | grep -q vbsd_keyvault; then
        info "  Device: /dev/keyvault"
    fi
fi

echo ""
info "Running coalition tests..."
echo ""

# Run main test suite
./tests/bin/coalition_test
TEST_RESULT=$?

echo ""

# Run stress test (shorter version for quick verification)
if [ -f ./tests/bin/stress_test ]; then
    info "Running quick stress test..."
    ./tests/bin/stress_test -i 10 -d 2 lifecycle
    STRESS_RESULT=$?
else
    STRESS_RESULT=0
fi

echo ""

# Show final module state
info "Final module state:"
sysctl kern.vbsd_coalition.count 2>/dev/null || true
sysctl kern.vbsd_coalition.member_count 2>/dev/null || true

echo ""

if [ $TEST_RESULT -eq 0 ] && [ $STRESS_RESULT -eq 0 ]; then
    info "All tests passed!"
    exit 0
else
    error "Some tests failed"
    exit 1
fi
