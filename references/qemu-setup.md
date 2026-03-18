# QEMU + GDB Kernel Debugging Environment Setup

## Table of Contents
1. [Quick Start with virtme-ng](#quick-start-with-virtme-ng)
2. [Full QEMU Setup](#full-qemu-setup)
3. [Kernel Build Configuration](#kernel-build-configuration)
4. [Creating a Rootfs](#creating-a-rootfs)
5. [GDB Kernel Debugging](#gdb-kernel-debugging)
6. [Debugging Workflow](#debugging-workflow)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start with virtme-ng

`virtme-ng` (vng) is the fastest way to boot a kernel for testing. It uses your
host's filesystem, so you don't need a separate rootfs.

```bash
# Install
pip install virtme-ng

# Build and boot the kernel in one command
vng --build --run

# Boot with specific kernel source
vng -r /path/to/kernel-src

# Boot with a specific command (e.g., run PoC)
vng --run -- /path/to/poc

# Boot with GDB support
vng --run -d  # Starts GDB stub, then attach with: gdb vmlinux -ex "target remote :1234"
```

**Pros**: Fast, no rootfs needed, easy to use
**Cons**: Shares host FS (may not match target environment), some features need extra config

---

## Full QEMU Setup

For full control over the environment (matching target kernel config, isolated rootfs, etc.).

### Basic QEMU Command

```bash
#!/bin/bash
# run.sh - Boot kernel in QEMU

KERNEL_DIR="$(cd "$(dirname "$0")" && pwd)"

qemu-system-x86_64 \
    -kernel "${KERNEL_DIR}/bzImage" \
    -initrd "${KERNEL_DIR}/rootfs.cpio.gz" \
    -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr oops=panic panic=1" \
    -nographic \
    -m 2G \
    -smp 2 \
    -cpu qemu64,+smep,+smap \
    -no-reboot \
    -net nic,model=e1000 \
    -net user,hostfwd=tcp::10022-:22
```

### QEMU with GDB Support

Add `-s -S` to enable GDB stub:
- `-s`: Shorthand for `-gdb tcp::1234`
- `-S`: Freeze CPU at startup (wait for GDB to continue)

```bash
qemu-system-x86_64 \
    -kernel bzImage \
    -initrd rootfs.cpio.gz \
    -append "console=ttyS0 nokaslr oops=panic panic=1" \
    -nographic -m 2G -smp 2 \
    -s -S
```

### Important QEMU Options

| Option | Purpose |
|---|---|
| `-kernel bzImage` | Kernel image to boot |
| `-initrd rootfs.cpio.gz` | Initial ramdisk (rootfs) |
| `-append "..."` | Kernel command line |
| `nokaslr` | Disable KASLR (needed for stable GDB addresses) |
| `oops=panic panic=1` | Panic on oops and reboot after 1 second |
| `-nographic` | Console on serial port (no GUI) |
| `-m 2G` | 2GB RAM |
| `-smp 2` | 2 CPUs (important for race condition testing) |
| `-cpu qemu64,+smep,+smap` | Enable SMEP/SMAP (match production) |
| `-no-reboot` | Exit QEMU on kernel panic instead of rebooting |
| `-s` | GDB stub on port 1234 |
| `-S` | Halt at start, wait for GDB |
| `-net user,hostfwd=...` | Network with port forwarding |
| `-drive file=disk.img,format=raw` | Persistent disk image |

### Kernel Command Line Options

| Option | Purpose |
|---|---|
| `nokaslr` | Disable address randomization (for GDB) |
| `oops=panic` | Panic on any oops (don't try to continue) |
| `panic=1` | Reboot 1 second after panic |
| `kasan.fault=panic` | KASAN: panic immediately on bug |
| `slub_debug=FZPU` | Enable SLUB debugging (F=Poison, Z=RedZone, P=Sanity, U=Track) |
| `console=ttyS0` | Serial console output |
| `root=/dev/ram rdinit=/init` | Boot from initramfs |
| `loglevel=7` | Verbose kernel logging |

---

## Kernel Build Configuration

### Minimal Debug Config

Start with your target's defconfig, then enable debugging:

```bash
# Start with defconfig or the target's config
make defconfig
# Or: cp target.config .config && make olddefconfig

# Enable critical debug options
./scripts/config --enable CONFIG_DEBUG_INFO
./scripts/config --enable CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
./scripts/config --enable CONFIG_GDB_SCRIPTS
./scripts/config --enable CONFIG_FRAME_POINTER
./scripts/config --enable CONFIG_KASAN
./scripts/config --enable CONFIG_KASAN_INLINE
./scripts/config --enable CONFIG_UBSAN
./scripts/config --enable CONFIG_DEBUG_KERNEL
./scripts/config --enable CONFIG_LOCKDEP
./scripts/config --enable CONFIG_PROVE_LOCKING
./scripts/config --enable CONFIG_HARDENED_USERCOPY
./scripts/config --enable CONFIG_FORTIFY_SOURCE

# For reproduction of specific bugs, also enable:
./scripts/config --enable CONFIG_SLUB_DEBUG
./scripts/config --enable CONFIG_SLUB_DEBUG_ON
./scripts/config --enable CONFIG_DEBUG_LIST
./scripts/config --enable CONFIG_DEBUG_SG
./scripts/config --enable CONFIG_BUG_ON_DATA_CORRUPTION

# Rebuild
make olddefconfig
make -j$(nproc)
```

### Key Configs by Bug Type

| Bug Type | Required Configs |
|---|---|
| UAF | `KASAN`, `SLUB_DEBUG`, `SLUB_DEBUG_ON` |
| OOB | `KASAN`, `FORTIFY_SOURCE` |
| Race condition | `KCSAN`, `LOCKDEP`, `PROVE_LOCKING` |
| Usercopy | `HARDENED_USERCOPY` |
| Integer overflow | `UBSAN` |
| Stack overflow | `STACKPROTECTOR`, `VMAP_STACK` |
| Info leak | `INIT_ON_ALLOC_DEFAULT_ON` (makes leaks disappear — useful for confirming) |

### Building Kernel

```bash
# Full build
make -j$(nproc)

# Just the bzImage (faster if you don't need modules)
make -j$(nproc) bzImage

# The vmlinux (for GDB symbols) is at:
ls -la vmlinux

# The bzImage (for QEMU) is at:
ls -la arch/x86/boot/bzImage
```

---

## Creating a Rootfs

### Minimal initramfs with busybox

```bash
#!/bin/bash
# create_rootfs.sh - Build a minimal rootfs

ROOTFS_DIR=$(mktemp -d)
BUSYBOX_BIN="/path/to/busybox"  # Static-linked busybox

mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,proc,sys,dev,tmp,root}

# Install busybox
cp "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"
chmod +x "$ROOTFS_DIR/bin/busybox"

# Create init script
cat > "$ROOTFS_DIR/init" << 'INITEOF'
#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev
/bin/busybox mount -t tmpfs none /tmp

# Create busybox symlinks
/bin/busybox --install -s /bin
/bin/busybox --install -s /sbin

# Set hostname
hostname kernel-debug

# Run PoC if it exists
if [ -f /root/poc ]; then
    echo "[*] Running PoC..."
    /root/poc
    echo "[*] PoC exit code: $?"
fi

# Drop to shell
echo "[*] Dropping to shell..."
exec /bin/sh
INITEOF
chmod +x "$ROOTFS_DIR/init"

# Copy PoC binary if available
# cp /path/to/poc "$ROOTFS_DIR/root/poc"

# Create cpio archive
cd "$ROOTFS_DIR"
find . | cpio -o --format=newc | gzip > /output/rootfs.cpio.gz
echo "Rootfs created: /output/rootfs.cpio.gz"

# Cleanup
rm -rf "$ROOTFS_DIR"
```

### Using debootstrap (Debian-based rootfs)

```bash
# Create a Debian rootfs
sudo debootstrap --include=build-essential,gdb,strace,file \
    bullseye /tmp/rootfs

# Create ext4 disk image
dd if=/dev/zero of=rootfs.img bs=1M count=2048
mkfs.ext4 rootfs.img
sudo mount rootfs.img /mnt
sudo cp -a /tmp/rootfs/* /mnt/
sudo umount /mnt

# Boot with disk image instead of initramfs:
# -drive file=rootfs.img,format=raw -append "root=/dev/sda rw console=ttyS0"
```

---

## GDB Kernel Debugging

### Starting a GDB Session

```bash
# Terminal 1: Start QEMU with GDB stub
qemu-system-x86_64 -kernel bzImage -initrd rootfs.cpio.gz \
    -append "console=ttyS0 nokaslr" -nographic -m 2G -smp 2 -s -S

# Terminal 2: Attach GDB
gdb vmlinux
(gdb) target remote :1234
(gdb) continue
```

### Essential GDB Commands for Kernel

```gdb
# Load kernel helper scripts (if compiled with GDB_SCRIPTS)
source vmlinux-gdb.py

# Kernel-specific commands (from GDB scripts)
lx-symbols              # Load all module symbols
lx-dmesg                # Print kernel log ring buffer
lx-ps                   # List all tasks
lx-lsmod               # List loaded modules
lx-cmdline             # Show kernel command line
lx-version             # Show kernel version
lx-fdtdump             # Dump flattened device tree

# Breakpoints
break function_name           # Break at function entry
break file.c:123             # Break at file:line
break *0xffffffff81234567    # Break at address
hbreak *0xaddr               # Hardware breakpoint (limited to 4)

# Conditional breakpoints
break function_name if condition == value

# Watchpoints (hardware-assisted, very useful for UAF)
watch *(int *)0xffff888012345678        # Break when memory is written
rwatch *(int *)0xffff888012345678       # Break when memory is read
awatch *(int *)0xffff888012345678       # Break on read or write

# Examining data
print *(struct sk_buff *)$rdi          # Print structure
print ((struct task_struct *)$current)->comm  # Current task name
x/20gx 0xaddr                         # Examine memory (20 giant hex words)
x/10i $rip                            # Disassemble at instruction pointer

# Stack
bt                    # Backtrace
frame N               # Select frame
info locals           # Local variables in current frame
info args             # Function arguments

# Threads/CPUs
info threads          # List all CPUs
thread N              # Switch to CPU N

# Stepping
si                    # Step one instruction
ni                    # Next instruction (step over calls)
finish                # Run until current function returns
continue              # Resume execution
```

### GDB Init File for Kernel Debugging

Create `~/.gdbinit` or a per-project `.gdbinit`:

```gdb
set pagination off
set confirm off
set print pretty on
set print array on
set print array-indexes on
set output-radix 16

# Auto-load kernel GDB scripts
add-auto-load-safe-path /path/to/kernel-src

# Connect shortcut
define qemu
    target remote :1234
end

# Print current task
define curtask
    print ((struct task_struct *)$lx_current())->comm
end
```

---

## Debugging Workflow

### Step 1: Reproduce the Crash

1. Boot vulnerable kernel in QEMU (without `-S`)
2. Run the PoC and confirm the crash
3. Save the full crash log from the serial console
4. Note the exact faulting address and function

### Step 2: Set Strategic Breakpoints

Based on the crash analysis, set breakpoints BEFORE the crash:

```gdb
# Break at the function that crashes
break vulnerable_function

# Break at the allocation of the vulnerable object
break kmem_cache_alloc  # Too generic, use specific allocator if known

# Break at the suspected free path
break kfree
```

### Step 3: Trace the Object Lifecycle

For UAF bugs:
```gdb
# 1. Break at object allocation
break kmem_cache_alloc_trace if size == 256  # if you know the size

# 2. When allocation happens, set a hardware watchpoint
watch *(long *)0x<object_addr + offset_of_interesting_field>

# 3. Continue — the watchpoint fires when the field is modified
# First hit: initialization
# Second hit: might be the write-after-free
```

### Step 4: Verify the Fix

1. Apply the patch
2. Rebuild the kernel
3. Boot the patched kernel in QEMU
4. Run the PoC
5. Verify no crash occurs
6. Check dmesg for any warnings

---

## Troubleshooting

### QEMU Hangs on Boot

- Check kernel config includes appropriate console driver
- Ensure `-append "console=ttyS0"` is set
- Try adding `earlyprintk=serial,ttyS0` to see early boot messages

### GDB Can't Find Symbols

- Make sure `CONFIG_DEBUG_INFO=y` is in the kernel config
- Use the `vmlinux` from the SAME build (not a different one)
- For modules: `lx-symbols` or manually `add-symbol-file`

### KASAN Doesn't Report Anything

- Verify `CONFIG_KASAN=y` is enabled
- Check that the slab allocator is SLUB (KASAN requires SLUB)
- KASAN may not catch bugs in `kmalloc` < 8 bytes or in page allocator

### PoC Doesn't Trigger the Bug

- Verify kernel version matches (the bug might be version-specific)
- Check if relevant kernel config options are enabled
- For race conditions: increase CPU count (`-smp 4`), add stress
- For network bugs: ensure the network stack is configured correctly
- Some bugs need specific syscall sequences — check if the PoC needs `unshare(CLONE_NEWUSER)`

### GDB Breaks at Wrong Locations

- With KASLR, addresses shift — use `nokaslr` in kernel command line
- With optimizations, source-level debugging may be inaccurate
- Use `si`/`ni` (instruction-level) instead of `s`/`n` when source mapping is wrong
