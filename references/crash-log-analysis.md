# Crash Log Analysis Reference

## Table of Contents
1. [KASAN Reports](#kasan-reports)
2. [UBSAN Reports](#ubsan-reports)
3. [Kernel BUG/Oops](#kernel-bugoops)
4. [NULL Pointer Dereference](#null-pointer-dereference)
5. [General Protection Fault](#general-protection-fault)
6. [Stack Trace Decoding](#stack-trace-decoding)
7. [Syzbot Reports](#syzbot-reports)

---

## KASAN Reports

KASAN (Kernel Address Sanitizer) is the most informative bug detector. It provides:
- Bug type (UAF, OOB, double-free)
- Faulting address and access size
- Allocation and free call stacks

### KASAN Report Structure

```
BUG: KASAN: <bug-type> in <function>+<offset>/<size> [<module>]
<Read/Write> of size <N> at addr <address> by task <task>/<pid>

CPU: <cpu> PID: <pid> Comm: <command> Not tainted <version>
Hardware name: <hardware>
Call Trace:
 <stack frames>

Allocated by task <pid>:
 <allocation stack>

Freed by task <pid>:
 <free stack>

The buggy address belongs to the object at <addr>
 which belongs to the cache <cache-name> of size <size>
The buggy address is located <offset> bytes inside of
 <size>-byte region [<start>, <end>)
```

### Key Fields to Extract

| Field | What it tells you |
|---|---|
| `slab-use-after-free` | Object was freed, then accessed |
| `slab-out-of-bounds` | Access beyond allocated object boundary |
| `use-after-free` | Generic UAF (could be page-level) |
| `out-of-bounds` | Generic OOB |
| `double-free` / `invalid-free` | Free of already-freed or invalid pointer |
| `Read of size N` | Read access — likely info leak or crash |
| `Write of size N` | Write access — more likely exploitable |
| `cache <name>` | Slab cache — tells you object type and kmalloc bucket |

### Interpreting Addresses

```
0000000000000000 - 00000000000000ff  → NULL page dereference
dead000000000100 - dead0000000001ff  → KASAN freed object (0xdead prefix)
ffff888000000000 - ffffc87fffffffff  → Direct mapping of physical memory
ffffffff80000000 - ffffffff9fffffff  → Kernel text
0x6b6b6b6b6b6b6b6b                  → Slab poison (freed memory)
0xa5a5a5a5a5a5a5a5                  → Slab red zone
0x5a5a5a5a5a5a5a5a                  → SLUB: Poison free
```

### KASAN Bug Type Deep Dive

**slab-use-after-free**: The most interesting for exploitation.
- Check the "Freed by task" stack — who freed it and why?
- Check the "Allocated by task" stack — what kind of object is it?
- Calculate the offset within the object where the access happens — is it a function pointer? A linked list pointer?

**slab-out-of-bounds**: Check:
- Is the access just past the end? (off-by-one)
- Is the access far past the end? (wrong size calculation, integer overflow)
- What's the adjacent object in the slab? (what gets corrupted)

**double-free**: Two code paths freed the same object.
- Check both free stacks — is there a missing flag/state check?
- Is there a reference counting error?

---

## UBSAN Reports

UBSAN (Undefined Behavior Sanitizer) catches C undefined behavior.

```
UBSAN: <type> in <file>:<line>:<col>
<description>
```

Common types:
- `shift-out-of-bounds`: Shift by negative or too-large value
- `signed-integer-overflow`: `INT_MAX + 1` etc.
- `array-index-out-of-bounds`: Array access past declared size
- `null-ptr-deref`: Dereference of NULL
- `load of value X is not a valid value for type 'bool'`: Type confusion

UBSAN bugs are often less directly exploitable but can indicate deeper issues
(integer overflow → wrong allocation size → heap overflow).

---

## Kernel BUG/Oops

```
kernel BUG at <file>:<line>!
```
or
```
BUG: unable to handle page fault for address: <addr>
```

A BUG() is an explicit assertion failure — the developer put it there because
an "impossible" condition was reached. Understanding WHY the invariant was violated
is the key to root cause.

An Oops is an unexpected fault. Check `Oops: <code>` flags:
- Bit 0: 0 = no page found, 1 = protection fault
- Bit 1: 0 = read, 1 = write
- Bit 2: 0 = kernel mode, 1 = user mode
- Bit 3: 0 = not instruction fetch, 1 = instruction fetch

---

## NULL Pointer Dereference

```
BUG: kernel NULL pointer dereference, address: 0000000000000040
```

The offset from NULL is crucial:
- `0x0` — Direct NULL dereference, likely a missing NULL check
- Small offset (0x8, 0x10, 0x40, etc.) — Structure member access through NULL pointer
  → The pointer to the struct is NULL, and the access is at `offsetof(struct, member)`
- This can mask a UAF: if the freed memory is zeroed (or the object was in a cache
  that gets zeroed), accessing a pointer field reads NULL

**To determine if a NULL deref is actually a UAF**:
1. Check if the pointer should have been valid at this point in the code
2. Look for concurrent free paths
3. Check if KASAN was enabled — if not, a UAF to zeroed memory looks like NULL deref
4. Use `pahole` or manual calculation to see which struct field is at that offset

---

## General Protection Fault

```
general protection fault, probably for non-canonical address 0x6b6b6b6b6b6b6b6b
```

This is almost always a UAF:
- `0x6b` is the SLUB_RED_ACTIVE poison byte (freed memory pattern)
- The kernel tried to use a freed object's field as a pointer
- The "non-canonical address" means the value isn't a valid x86-64 address

Other GPF poison patterns:
- `0xdead000000000000` — KASAN shadow
- `0x5a5a5a5a` — SLUB poison free
- `0xa5a5a5a5` — SLUB red zone

---

## Stack Trace Decoding

### Raw vs. Decoded

If the stack trace has raw addresses:
```bash
./scripts/decode_stacktrace.sh vmlinux < raw_crash.txt
```

### Reading the Call Trace

```
Call Trace:
 <IRQ>                        ← in interrupt context
 function_name+0x1a/0x30      ← offset/total_size
 ? maybe_function+0x5/0x10    ← unreliable frame (? prefix)
 </IRQ>                       ← back to process context
 entry_SYSCALL_64+0x5a/0x80   ← syscall entry
```

- Focus on frames WITHOUT the `?` prefix — those are reliable
- The first frame after `<IRQ>` or at the top is usually closest to the crash
- `entry_SYSCALL_64` tells you this came from a syscall
- Frames from `__schedule`, `schedule`, `wait_*` are usually not relevant (sleeping)

### Identifying the Relevant Function

Work up the stack from the crash point:
1. The faulting function (top of trace) — where the crash happened
2. Its caller — often more interesting (the function that passed the bad pointer)
3. The syscall or entry point — how user space triggered this

---

## Syzbot Reports

Syzbot provides:
- A crash title (e.g., "KASAN: use-after-free Read in tcp_retransmit_skb")
- The full crash log
- A C reproducer and/or syzkaller reproducer
- The kernel commit where it was first found
- Bisection results (if available)

### Using Syzbot Reproducers

```c
// Syzbot C reproducers often use:
#define _GNU_SOURCE
#include <sys/syscall.h>
// ... raw syscall sequences

// These can be compiled with:
gcc -o poc -static -lpthread poc.c
```

Syzkaller reproducers (`.syz` files) need the `syz-execprog` tool:
```bash
syz-execprog -executor=./syz-executor -repeat=0 -procs=8 poc.syz
```
