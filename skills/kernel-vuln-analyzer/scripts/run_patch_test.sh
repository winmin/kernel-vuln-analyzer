#!/bin/bash
# run_patch_test.sh - Automated patch verification in QEMU
#
# Usage:
#   ./run_patch_test.sh <bzImage> <rootfs> <poc_binary> [timeout_seconds]
#
# This script:
# 1. Boots the kernel in QEMU
# 2. Waits for boot to complete
# 3. Runs the PoC
# 4. Checks dmesg for crash indicators
# 5. Reports pass/fail
#
# Exit codes:
#   0 - Patch verified (no crash)
#   1 - Crash detected (patch failed or PoC still triggers bug)
#   2 - Boot failure or timeout

set -euo pipefail

BZIMAGE="${1:?Usage: $0 <bzImage> <rootfs> <poc_binary> [timeout_seconds]}"
ROOTFS="${2:?Usage: $0 <bzImage> <rootfs> <poc_binary> [timeout_seconds]}"
POC_BINARY="${3:?Usage: $0 <bzImage> <rootfs> <poc_binary> [timeout_seconds]}"
TIMEOUT="${4:-120}"

WORK_DIR=$(mktemp -d)
RESULT_LOG="$WORK_DIR/result.log"
SERIAL_LOG="$WORK_DIR/serial.log"

cleanup() {
    # Kill QEMU if still running
    if [ -n "${QEMU_PID:-}" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    echo ""
    echo "[*] Serial log saved to: $SERIAL_LOG"
}
trap cleanup EXIT

# ============================================================
# Step 1: Build rootfs with PoC embedded and auto-run
# ============================================================
echo "[*] Preparing rootfs with PoC..."

ROOTFS_WORK=$(mktemp -d)
cd "$ROOTFS_WORK"

# Extract existing rootfs
zcat "$ROOTFS" | cpio -idm 2>/dev/null

# Copy PoC
cp "$POC_BINARY" ./root/poc
chmod +x ./root/poc

# Create auto-run init that executes PoC and reports result
cat > ./init << 'INITEOF'
#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev 2>/dev/null || true
/bin/busybox mount -t tmpfs none /tmp
/bin/busybox --install -s /bin 2>/dev/null
/bin/busybox --install -s /sbin 2>/dev/null

echo "BOOT_COMPLETE"

# Run PoC
echo "POC_START"
timeout 30 /root/poc
POC_EXIT=$?
echo "POC_EXIT_CODE=$POC_EXIT"

# Check dmesg for crash indicators
echo "DMESG_CHECK_START"
dmesg | grep -iE "BUG|KASAN|UBSAN|panic|Oops|WARNING.*RCU|general protection fault|unable to handle|double.free|use.after.free|out.of.bounds" || echo "DMESG_CLEAN"
echo "DMESG_CHECK_END"

# Signal completion
echo "TEST_COMPLETE"
sleep 1

# Power off
echo o > /proc/sysrq-trigger
INITEOF
chmod +x ./init

# Repack rootfs
find . | cpio -o --format=newc 2>/dev/null | gzip > "$WORK_DIR/test-rootfs.cpio.gz"
cd /
rm -rf "$ROOTFS_WORK"

# ============================================================
# Step 2: Boot QEMU and capture output
# ============================================================
echo "[*] Booting kernel in QEMU (timeout: ${TIMEOUT}s)..."

qemu-system-x86_64 \
    -kernel "$BZIMAGE" \
    -initrd "$WORK_DIR/test-rootfs.cpio.gz" \
    -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr oops=panic panic=1 kasan.fault=panic" \
    -nographic \
    -m 2G \
    -smp 2 \
    -cpu qemu64,+smep,+smap \
    -no-reboot \
    -monitor none \
    -serial stdio 2>&1 | tee "$SERIAL_LOG" &
QEMU_PID=$!

# Wait for completion or timeout
SECONDS=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$TIMEOUT" ]; then
        echo ""
        echo "[-] Timeout after ${TIMEOUT} seconds"
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true

        if grep -q "TEST_COMPLETE" "$SERIAL_LOG"; then
            break
        fi

        echo "[-] RESULT: TIMEOUT (kernel may have hung)"
        cp "$SERIAL_LOG" "${POC_BINARY%/*}/../logs/patch-verification.log" 2>/dev/null || true
        exit 2
    fi

    # Check if test completed
    if grep -q "TEST_COMPLETE" "$SERIAL_LOG"; then
        sleep 2
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        break
    fi

    sleep 1
done

# ============================================================
# Step 3: Analyze results
# ============================================================
echo ""
echo "============================================"
echo " Patch Verification Results"
echo "============================================"

PASS=true

# Check if boot completed
if ! grep -q "BOOT_COMPLETE" "$SERIAL_LOG"; then
    echo "[-] Boot failed — kernel did not reach init"
    PASS=false
fi

# Check if PoC ran
if ! grep -q "POC_START" "$SERIAL_LOG"; then
    echo "[-] PoC did not start"
    PASS=false
fi

# Check PoC exit code
POC_EXIT=$(grep -o "POC_EXIT_CODE=[0-9]*" "$SERIAL_LOG" | cut -d= -f2 || echo "unknown")
echo "[*] PoC exit code: $POC_EXIT"

# Check for crash indicators in dmesg
if grep -q "DMESG_CLEAN" "$SERIAL_LOG"; then
    echo "[+] No crash indicators in dmesg"
else
    # Check between DMESG_CHECK_START and DMESG_CHECK_END
    CRASH_LINES=$(sed -n '/DMESG_CHECK_START/,/DMESG_CHECK_END/p' "$SERIAL_LOG" | grep -v "DMESG_CHECK" || true)
    if [ -n "$CRASH_LINES" ]; then
        echo "[-] Crash indicators found in dmesg:"
        echo "$CRASH_LINES" | head -20
        PASS=false
    fi
fi

# Check for kernel panics in the serial log
if grep -qiE "Kernel panic|---\[ end Kernel panic" "$SERIAL_LOG"; then
    echo "[-] Kernel panic detected!"
    PASS=false
fi

if grep -qiE "BUG: KASAN" "$SERIAL_LOG"; then
    echo "[-] KASAN bug detected!"
    PASS=false
fi

echo ""
if $PASS; then
    echo "[+] RESULT: PASS — Patch appears to fix the vulnerability"
    echo "[+] The PoC ran without triggering a crash"
    exit 0
else
    echo "[-] RESULT: FAIL — Crash or error detected"
    echo "[-] The patch may not fully fix the vulnerability"
    exit 1
fi
