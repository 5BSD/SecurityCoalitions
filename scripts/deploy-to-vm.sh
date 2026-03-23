#!/bin/sh
#
# Deploy SecurityCoalitions to a FreeBSD VM for testing
#
# Builds locally, then copies binaries to VM and runs tests.
#
# Usage: ./scripts/deploy-to-vm.sh <vm-ip> [user]
#

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <vm-ip> [user]"
    echo "Example: $0 192.168.1.100"
    echo "Example: $0 192.168.1.100 root"
    exit 1
fi

VM_IP="$1"
VM_USER="${2:-root}"
VM_DIR="/root/SecurityCoalitions"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "==> Building locally..."
make clean
make
make -C samples

echo "==> Deploying to ${VM_USER}@${VM_IP}:${VM_DIR}"

# Create a tarball with built binaries
TMPTAR="/tmp/seccoal_deploy_$$.tar.gz"
trap "rm -f ${TMPTAR}" EXIT

echo "==> Creating archive..."
tar -czf "$TMPTAR" \
    --exclude '.git' \
    --exclude '*.o' \
    --exclude '.depend*' \
    --exclude 'machine' \
    --exclude 'x86' \
    --exclude 'i386' \
    --exclude 'opt_global.h' \
    --exclude 'export_syms' \
    --exclude '*.core' \
    .

echo "==> Copying to VM..."
scp "$TMPTAR" "${VM_USER}@${VM_IP}:/tmp/seccoal_deploy.tar.gz"

echo "==> Extracting on VM..."
ssh "${VM_USER}@${VM_IP}" "rm -rf ${VM_DIR} && mkdir -p ${VM_DIR} && tar -C ${VM_DIR} -xzf /tmp/seccoal_deploy.tar.gz && rm /tmp/seccoal_deploy.tar.gz"

echo "==> Running tests on VM..."

# Run the test script on the VM
ssh -t "${VM_USER}@${VM_IP}" "cd ${VM_DIR} && sh scripts/vm-test.sh"
