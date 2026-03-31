# Syzbot Interaction Workflow

## Table of Contents
1. [Reading a Syzbot Report](#reading-a-syzbot-report)
2. [Extracting Reproducers](#extracting-reproducers)
3. [Testing Patches via Syzbot](#testing-patches-via-syzbot)
4. [Marking Bugs as Fixed](#marking-bugs-as-fixed)
5. [Using Syzbot Assets](#using-syzbot-assets)
6. [Compiler Version Tracking](#compiler-version-tracking)

---

## Reading a Syzbot Report

Syzbot reports are at `https://syzkaller.appspot.com/`. A typical report contains:

```
Title:          KASAN: use-after-free Read in tcp_retransmit_skb
Crashes:        142
First crash:    2024-01-15
Last crash:     2024-03-10
Kernel:         upstream / linux-6.8-rc3
Compiler:       gcc (Debian 12.2.0-14) 12.2.0
Config:         https://syzkaller.appspot.com/text?tag=KernelConfig&x=...
Reproducer (C): https://syzkaller.appspot.com/text?tag=ReproC&x=...
Reproducer (syz): https://syzkaller.appspot.com/text?tag=ReproSyz&x=...
Bisect:         caused by commit abc123...
```

**Key fields to extract**:
- **Reproducer (C)**: Standalone C program — the primary PoC
- **Reproducer (syz)**: Syzkaller DSL format — needs `syz-execprog` to run
- **Config**: The exact kernel config used when the crash was found
- **Compiler**: Exact compiler version — some bugs are compiler-specific
- **Bisect result**: The commit that introduced the bug (if bisection succeeded)

---

## Extracting Reproducers

### C Reproducer (Preferred)

```bash
# Download the C reproducer
curl -sL 'https://syzkaller.appspot.com/text?tag=ReproC&x=...' -o poc.c

# Compile statically (for use in minimal rootfs / QEMU)
gcc -o poc -static -lpthread poc.c

# Syzbot C reproducers often use:
# - Raw syscalls via syscall()
# - /dev/loop, /dev/vhci, network namespaces
# - Multithreading (pthreads) for race conditions
# - Specific timing with usleep()
```

**Common build issues with syzbot reproducers**:
- Missing headers: add `#define _GNU_SOURCE` at the top
- Missing `-lpthread`: syzbot reproducers often use threads
- Static linking: some features need `-static`
- Missing `syz_*` helper functions: these are syzkaller-specific, the C repro
  should already include them inline

### Syzkaller Reproducer

If only `.syz` format is available:

```bash
# You need syzkaller tools to run .syz reproducers:
# 1. Build syzkaller
git clone https://github.com/google/syzkaller
cd syzkaller && make

# 2. Run the reproducer
./bin/syz-execprog -executor=./bin/syz-executor \
    -repeat=0 -procs=8 -sandbox=none poc.syz
```

Alternatively, manually translate the `.syz` to C — syzbot's `.syz` files are
sequences of syscalls that can be converted to `syscall()` calls.

### No Reproducer Available

If syzbot reports "no reproducer", the bug was found by fuzzing but not minimized:
- Read the crash log carefully — the syscall sequence may be visible in the stack trace
- Write a minimal PoC based on the call trace analysis
- Try the syzbot kernel config — some bugs only trigger with specific configs

---

## Testing Patches via Syzbot

Syzbot can automatically test your patch against the exact environment that triggered the bug.

### `#syz test` Command

Reply to the syzbot email notification with:

```
#syz test: <git-repo> <branch>

<your patch inline or attached>
```

Or test against a specific tree:

```
#syz test: git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git master

From: Your Name <your@email.com>
Subject: [PATCH] subsystem: fix the bug

<patch content>
---
 file.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/file.c b/file.c
...
```

**What happens**:
1. Syzbot applies your patch to the specified tree
2. Builds the kernel with the original crash config
3. Runs the reproducer against the patched kernel
4. Reports back whether the crash is fixed

**Important**: The patch must apply cleanly to the specified tree. If it doesn't,
syzbot will report a build failure.

### `#syz test` Result Interpretation

- **OK**: Patch applied, kernel built, reproducer ran, no crash — your fix works!
- **BUG**: Patch applied, but reproducer still crashes — fix is incomplete
- **build error**: Patch doesn't apply cleanly or causes compilation errors

After successful `#syz test`, add to your commit message:
```
Tested-by: syzbot+<hash>@syzkaller.appspotmail.com
```

---

## Marking Bugs as Fixed

### `#syz fix` Command

When your patch is committed to a tree that syzbot monitors:

```
#syz fix: subsystem: fix the null ptr deref in func_name
```

The argument is the **commit subject line** (first line of commit message).
Syzbot will monitor for this commit and close the bug when it appears.

### `#syz dup` Command

If the bug is a duplicate of another syzbot report:

```
#syz dup: KASAN: use-after-free in other_function
```

### `#syz invalid` Command

If the crash is not a real bug (e.g., test infrastructure issue):

```
#syz invalid
```

---

## Using Syzbot Assets

### Bootable Disk Images

Syzbot provides disk images for reproducing the exact environment:

```bash
# Download the disk image from the syzbot dashboard
# (click "Assets" → "disk image" on the bug page)

# Boot with QEMU:
qemu-system-x86_64 \
    -kernel bzImage \
    -drive file=disk.raw,format=raw \
    -append "root=/dev/sda console=ttyS0" \
    -nographic -m 2G -smp 2
```

### Kernel Config

Always download the exact config syzbot used — the bug may be config-dependent:

```bash
curl -sL 'https://syzkaller.appspot.com/text?tag=KernelConfig&x=...' -o .config
make olddefconfig
make -j$(nproc)
```

### Crash Log with Symbolized Trace

Syzbot usually provides already-decoded traces. If not, download the vmlinux
from the assets page and decode manually.

---

## Compiler Version Tracking

Some kernel bugs are compiler-specific:
- GCC vs Clang may generate different code for the same source
- Optimization levels (-O2 vs -O0) can mask or reveal race conditions
- Specific compiler versions may have codegen bugs

**Always record** the compiler version in your analysis:

```bash
# Check compiler used for the crash
# (from syzbot report: "Compiler: gcc (Debian 12.2.0-14) 12.2.0")

# Check your local compiler
gcc --version | head -1
# or
clang --version | head -1

# If syzbot used a different compiler, try to match it
# for accurate reproduction
```

**If a bug only reproduces with a specific compiler**:
- Note this in the report
- Test your patch with both GCC and Clang if possible
- Some codegen-dependent bugs may need different fix strategies

---

## Quick Reference

| Action | Command |
|---|---|
| Test a patch | `#syz test: <repo> <branch>` + patch inline |
| Mark as fixed | `#syz fix: <commit subject line>` |
| Mark as duplicate | `#syz dup: <other bug title>` |
| Mark as invalid | `#syz invalid` |
| Dashboard | `https://syzkaller.appspot.com/upstream` |
| Bug page | `https://syzkaller.appspot.com/bug?extid=<hash>` |
