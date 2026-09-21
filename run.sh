#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Hetzner VM Provisioner — container wrapper
#
# Usage:
#   ./run.sh                         # Provision a new VM
#   ./run.sh destroy <name-or-ip>    # Destroy a VM and its resources
#   ./run.sh destroy <name-or-ip> --yes  # Non-interactive destroy
#   ./run.sh preflight               # Validate local config without creating resources
#   ./run.sh test                    # Run unit tests + coverage report
#
# Logs are saved to ./logs/<mode>-<timestamp>.log
# ─────────────────────────────────────────────────────────────

set -euo pipefail

if [ ! -f .env ]; then
    echo "Error: .env not found. Copy .env.example to .env and fill in HCLOUD_TOKEN."
    exit 1
fi

mkdir -p ./keys ./logs
chmod 700 ./keys ./logs

echo "Building provisioner image..."
podman build --target prod -t cloud-vm-provisioner . --quiet

MODE="${1:-provision}"
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
LOGFILE="./logs/${MODE}-${TIMESTAMP}.log"

case "$MODE" in
    provision)
        echo "Starting VM provisioning..."
        echo "Log: $LOGFILE"
        podman run -it --rm \
            -v "$(pwd)/.env:/app/.env:ro" \
            -v "$(pwd)/keys:/workspace" \
            cloud-vm-provisioner provision.py 2>&1 | tee "$LOGFILE"
        ;;
    preflight)
        echo "Running preflight checks..."
        echo "Log: $LOGFILE"
        podman run --rm \
            -v "$(pwd)/.env:/app/.env:ro" \
            cloud-vm-provisioner preflight.py 2>&1 | tee "$LOGFILE"
        ;;
    destroy)
        TARGET="${2:?Usage: ./run.sh destroy <server-name-or-ip> [--yes]}"
        EXTRA="${3:-}"
        DESTROY_ARGS=("$TARGET")
        if [ -n "$EXTRA" ]; then
            DESTROY_ARGS+=("$EXTRA")
        fi
        LOGFILE="./logs/destroy-${TARGET//[^a-zA-Z0-9._-]/_}-${TIMESTAMP}.log"
        echo "Destroying server: $TARGET"
        echo "Log: $LOGFILE"
        podman run -it --rm \
            -v "$(pwd)/.env:/app/.env:ro" \
            -v "$(pwd)/keys:/workspace" \
            cloud-vm-provisioner destroy.py "${DESTROY_ARGS[@]}" 2>&1 | tee "$LOGFILE"
        ;;
    test)
        LOGFILE="./logs/test-${TIMESTAMP}.log"
        echo "Building test image..."
        podman build --target test -t cloud-vm-provisioner-test . --quiet
        echo "Running unit tests + coverage..."
        echo "Log: $LOGFILE"
        podman run --rm cloud-vm-provisioner-test 2>&1 | tee "$LOGFILE"
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: ./run.sh [provision|preflight|destroy <name-or-ip> [--yes]|test]"
        exit 1
        ;;
esac
