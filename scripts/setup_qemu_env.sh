#!/bin/bash
# setup_qemu_env.sh - Set up a QEMU kernel debugging environment
#
# Usage:
#   ./setup_qemu_env.sh <kernel_source_dir> <output_dir> [poc_binary]
#
# This script:
# 1. Configures and builds the kernel with debug options
# 2. Creates a minimal busybox-based rootfs
# 3. Generates run scripts for vulnerable and patched kernels
# 4. Optionally includes a PoC binary in the rootfs

set -euo pipefail

KERNEL_SRC="${1:?Usage: $0 <kernel_source_dir> <output_dir> [poc_binary]}"
OUTPUT_DIR="${2:?Usage: $0 <kernel_source_dir> <output_dir> [poc_binary]}"
POC_BINARY="${3:-}"

NPROC=$(nproc)

echo "[*] Setting up QEMU environment"
echo "    Kernel source: $KERNEL_SRC"
echo "    Output dir:    $OUTPUT_DIR"
echo "    PoC binary:    ${POC_BINARY:-none}"

mkdir -p "$OUTPUT_DIR"/{kernel,env,poc,logs}

# ============================================================
# Step 1: Configure kernel with debug options
# ============================================================
echo "[*] Configuring kernel..."

cd "$KERNEL_SRC"

# Start with defconfig if no .config exists
if [ ! -f .config ]; then
    make defconfig
fi

# Enable debug options
./scripts/config --enable CONFIG_DEBUG_INFO
./scripts/config --enable CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
./scripts/config --enable CONFIG_GDB_SCRIPTS
./scripts/config --enable CONFIG_FRAME_POINTER
./scripts/config --enable CONFIG_KASAN
./scripts/config --enable CONFIG_KASAN_INLINE
./scripts/config --enable CONFIG_UBSAN
./scripts/config --enable CONFIG_UBSAN_BOUNDS
./scripts/config --enable CONFIG_DEBUG_KERNEL
./scripts/config --enable CONFIG_SLUB_DEBUG
./scripts/config --enable CONFIG_SLUB_DEBUG_ON
./scripts/config --enable CONFIG_LOCKDEP
./scripts/config --enable CONFIG_PROVE_LOCKING
./scripts/config --enable CONFIG_HARDENED_USERCOPY
./scripts/config --enable CONFIG_FORTIFY_SOURCE
./scripts/config --enable CONFIG_BUG_ON_DATA_CORRUPTION
./scripts/config --enable CONFIG_DEBUG_LIST
./scripts/config --enable CONFIG_VMAP_STACK
./scripts/config --enable CONFIG_STACKPROTECTOR
./scripts/config --enable CONFIG_STACKPROTECTOR_STRONG

# Network-related (commonly needed)
./scripts/config --enable CONFIG_NET
./scripts/config --enable CONFIG_INET
./scripts/config --enable CONFIG_NETFILTER
./scripts/config --enable CONFIG_USER_NS
./scripts/config --enable CONFIG_NET_NS

# Virtio for QEMU
./scripts/config --enable CONFIG_VIRTIO
./scripts/config --enable CONFIG_VIRTIO_PCI
./scripts/config --enable CONFIG_VIRTIO_NET
./scripts/config --enable CONFIG_VIRTIO_BLK
./scripts/config --enable CONFIG_VIRTIO_CONSOLE
./scripts/config --enable CONFIG_HW_RANDOM_VIRTIO
./scripts/config --enable CONFIG_E1000

# Serial console
./scripts/config --enable CONFIG_SERIAL_8250
./scripts/config --enable CONFIG_SERIAL_8250_CONSOLE

# Initramfs support
./scripts/config --enable CONFIG_BLK_DEV_INITRD
./scripts/config --enable CONFIG_BLK_DEV_RAM

make olddefconfig

# ============================================================
# Step 2: Build kernel
# ============================================================
echo "[*] Building kernel (this may take a while)..."
make -j"$NPROC" bzImage 2>&1 | tail -5

# Copy kernel artifacts
cp arch/x86/boot/bzImage "$OUTPUT_DIR/kernel/test-bzImage"
cp vmlinux "$OUTPUT_DIR/kernel/test-vmlinux"
cp .config "$OUTPUT_DIR/kernel/.config"

echo "[+] Kernel built successfully"

# ============================================================
# Step 3: Create rootfs
# ============================================================
echo "[*] Creating rootfs..."

ROOTFS_DIR=$(mktemp -d)
mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,proc,sys,dev,tmp,root,lib,lib64}

# Find busybox
BUSYBOX=$(which busybox 2>/dev/null || echo "")
if [ -z "$BUSYBOX" ]; then
    echo "[!] busybox not found. Attempting to download static busybox..."
    BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
    BUSYBOX="$OUTPUT_DIR/busybox"
    if command -v curl &>/dev/null; then
        curl -sL "$BUSYBOX_URL" -o "$BUSYBOX"
    elif command -v wget &>/dev/null; then
        wget -q "$BUSYBOX_URL" -O "$BUSYBOX"
    else
        echo "[-] Cannot download busybox. Please install busybox-static and try again."
        exit 1
    fi
    chmod +x "$BUSYBOX"
fi

cp "$BUSYBOX" "$ROOTFS_DIR/bin/busybox"
chmod +x "$ROOTFS_DIR/bin/busybox"

# Create init script
cat > "$ROOTFS_DIR/init" << 'INITEOF'
#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

/bin/busybox mkdir -p /proc /sys /dev /tmp /run
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev 2>/dev/null || true
/bin/busybox mount -t tmpfs none /tmp

# Create busybox symlinks
/bin/busybox --install -s /bin 2>/dev/null
/bin/busybox --install -s /sbin 2>/dev/null

# Set hostname
hostname kernel-debug

# Network setup (if available)
ifconfig lo 127.0.0.1 up 2>/dev/null || true

echo "============================================"
echo " Kernel Debug Environment"
echo " $(uname -r)"
echo "============================================"

# Run PoC if it exists
if [ -f /root/poc ]; then
    echo ""
    echo "[*] PoC binary found at /root/poc"
    echo "[*] Run './root/poc' to trigger the vulnerability"
    echo ""
fi

# Drop to shell
exec /bin/sh
INITEOF
chmod +x "$ROOTFS_DIR/init"

# Copy PoC binary if provided
if [ -n "$POC_BINARY" ] && [ -f "$POC_BINARY" ]; then
    cp "$POC_BINARY" "$ROOTFS_DIR/root/poc"
    chmod +x "$ROOTFS_DIR/root/poc"
    echo "[+] PoC binary included in rootfs"

    # Also copy to output dir
    cp "$POC_BINARY" "$OUTPUT_DIR/poc/"
fi

# Create rootfs cpio archive
cd "$ROOTFS_DIR"
find . | cpio -o --format=newc 2>/dev/null | gzip > "$OUTPUT_DIR/env/rootfs.cpio.gz"
rm -rf "$ROOTFS_DIR"

echo "[+] Rootfs created"

# ============================================================
# Step 4: Generate run scripts
# ============================================================
echo "[*] Generating run scripts..."

cat > "$OUTPUT_DIR/env/run-vulnerable.sh" << 'RUNEOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$SCRIPT_DIR/../kernel"

echo "[*] Booting VULNERABLE kernel..."
echo "[*] Press Ctrl-A X to exit QEMU"
echo ""

qemu-system-x86_64 \
    -kernel "$KERNEL_DIR/test-bzImage" \
    -initrd "$SCRIPT_DIR/rootfs.cpio.gz" \
    -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr oops=panic panic=1 kasan.fault=panic" \
    -nographic \
    -m 2G \
    -smp 2 \
    -cpu qemu64,+smep,+smap \
    -no-reboot \
    -net nic,model=e1000 \
    -net user,hostfwd=tcp::10022-:22
RUNEOF
chmod +x "$OUTPUT_DIR/env/run-vulnerable.sh"

cat > "$OUTPUT_DIR/env/run-patched.sh" << 'RUNEOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$SCRIPT_DIR/../kernel"

if [ ! -f "$KERNEL_DIR/patched-bzImage" ]; then
    echo "[-] Patched kernel not found at $KERNEL_DIR/patched-bzImage"
    echo "    Build the patched kernel first and copy bzImage there."
    exit 1
fi

echo "[*] Booting PATCHED kernel..."
echo "[*] Press Ctrl-A X to exit QEMU"
echo ""

qemu-system-x86_64 \
    -kernel "$KERNEL_DIR/patched-bzImage" \
    -initrd "$SCRIPT_DIR/rootfs.cpio.gz" \
    -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr oops=panic panic=1 kasan.fault=panic" \
    -nographic \
    -m 2G \
    -smp 2 \
    -cpu qemu64,+smep,+smap \
    -no-reboot \
    -net nic,model=e1000 \
    -net user,hostfwd=tcp::10022-:22
RUNEOF
chmod +x "$OUTPUT_DIR/env/run-patched.sh"

cat > "$OUTPUT_DIR/env/run-debug.sh" << 'RUNEOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$SCRIPT_DIR/../kernel"
KERNEL_IMAGE="${1:-$KERNEL_DIR/test-bzImage}"

echo "[*] Booting kernel with GDB stub..."
echo "[*] In another terminal, run:"
echo "    gdb $KERNEL_DIR/test-vmlinux -ex 'target remote :1234'"
echo "[*] Press Ctrl-A X to exit QEMU"
echo ""

qemu-system-x86_64 \
    -kernel "$KERNEL_IMAGE" \
    -initrd "$SCRIPT_DIR/rootfs.cpio.gz" \
    -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr oops=panic panic=1" \
    -nographic \
    -m 2G \
    -smp 2 \
    -cpu qemu64,+smep,+smap \
    -no-reboot \
    -s -S
RUNEOF
chmod +x "$OUTPUT_DIR/env/run-debug.sh"

echo ""
echo "[+] QEMU environment setup complete!"
echo ""
echo "    Output directory: $OUTPUT_DIR"
echo ""
echo "    To boot the vulnerable kernel:"
echo "      $OUTPUT_DIR/env/run-vulnerable.sh"
echo ""
echo "    To debug with GDB:"
echo "      Terminal 1: $OUTPUT_DIR/env/run-debug.sh"
echo "      Terminal 2: gdb $OUTPUT_DIR/kernel/test-vmlinux -ex 'target remote :1234'"
echo ""
echo "    After patching, copy patched kernel:"
echo "      cp <patched-bzImage> $OUTPUT_DIR/kernel/patched-bzImage"
echo "      cp <patched-vmlinux> $OUTPUT_DIR/kernel/patched-vmlinux"
echo "      $OUTPUT_DIR/env/run-patched.sh"
