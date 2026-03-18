---
name: kernel-vuln-analyzer
description: >
  Analyze Linux kernel vulnerabilities from KASAN/UBSAN/BUG crash logs or CVE descriptions.
  Performs full root cause analysis, exploitability assessment, patch development, and verification.
  Use this skill whenever the user provides a kernel crash log, KASAN report, kernel panic trace,
  syzbot report, or asks to analyze/patch a kernel vulnerability. Also trigger when the user mentions
  kernel CVEs, kernel exploit analysis, kernel bug triage, or wants to understand if a kernel bug
  is exploitable. Even if the user just pastes a raw stack trace from dmesg, this skill applies.
---

# Kernel Vulnerability Analyzer

A comprehensive skill for analyzing Linux kernel vulnerabilities — from crash log triage through
root cause analysis, exploitability assessment, patch development, and verified fix delivery.

This skill is designed around a **hive-mode subagent architecture**: break the analysis into
parallel workstreams, plan before executing, and coordinate results across agents.

## Core Workflow Overview

The analysis follows seven phases. Each phase builds on the previous, but many sub-tasks within
a phase can run in parallel via subagents.

```
Phase 1: Triage & Planning ──→ Phase 2: Source Acquisition
    ↓                              ↓
Phase 3: Root Cause Analysis ←── Phase 4: Dynamic Analysis (QEMU+GDB)
    ↓
Phase 5: Exploitability Assessment
    ↓
Phase 6: Patch Development & Verification
    ↓
Phase 7: Report Generation & Artifact Packaging
```

---

## Phase 1: Triage & Planning

**Goal**: Understand what we're dealing with and plan the analysis strategy.

Before writing a single line of analysis, enter Plan mode and create a structured plan.
This is non-negotiable — kernel bugs are complex and a wrong turn wastes significant time.

### 1.1 Parse the Input

The user may provide:
- A raw KASAN/UBSAN/BUG/panic log (most common)
- A syzbot report URL or crash description
- A CVE identifier
- A verbal description of a kernel bug
- A PoC (C code, syzkaller repro, etc.)

**For crash logs**, extract these key signals:
- **Bug type**: KASAN (UAF, OOB-read, OOB-write, double-free), UBSAN, BUG(), WARNING, NULL ptr deref, GPF, etc.
- **Faulting address and access type**: Read/Write, address pattern (NULL page, kernel text, slab, etc.)
- **Call stack**: The full decoded call trace — this is the most important piece
- **Slab cache name**: e.g., `kmalloc-256`, `skbuff_head_cache`, `task_struct` — hints at the object type
- **Allocated/Freed stacks**: KASAN often shows where the object was allocated and freed
- **Kernel version and config**: What kernel is this running? What configs are relevant?
- **Subsystem**: Derived from the call stack — is this networking (net/), filesystem (fs/), drivers, etc.?

### 1.1.1 Decode the Stack Trace (Required)

If the crash log contains raw addresses (not resolved to source lines), decode it immediately:

```bash
./scripts/decode_stacktrace.sh vmlinux < crash.log > decoded_crash.log
```

If `vmlinux` is not available, use `addr2line` on individual addresses:

```bash
addr2line -e vmlinux -fip 0xffffffff81234567
```

The **decoded backtrace** is a critical artifact — it is needed for:
1. The root cause analysis (Phase 3) — source file:line references
2. The commit message (Phase 6) — upstream convention requires the decoded trace in the commit body
3. The final report (Phase 7) — annotated trace with file:line

Save the decoded trace to `logs/decoded_crash.log` in the report directory. Keep both the
raw and decoded versions — raw for reproduction, decoded for analysis.

Read `references/crash-log-analysis.md` for detailed patterns and parsing guidance.

### 1.2 Identify the Kernel Subsystem and Source Tree

Based on the call stack and file paths in the crash:

1. Identify the **subsystem** (net, fs, mm, drivers/gpu, sound, etc.)
2. Determine the correct **git tree** to clone:
   - Networking bugs → `git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git` (fixes) or `net-next.git` (features)
   - General kernel → `git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`
   - Subsystem-specific trees — use `MAINTAINERS` file or `scripts/get_maintainer.pl`
3. Identify the **relevant kernel version** — check if the bug exists in mainline, stable, or LTS

### 1.3 Create the Analysis Plan

Use Plan mode to structure the work. A typical plan:

```
1. Clone source tree and checkout relevant version
2. [Parallel] Spawn subagents for:
   a. Static analysis: read the vulnerable code path, trace data flow
   b. Git archaeology: find the commit that introduced the bug (git log, git bisect)
   c. Cross-reference: search kernelctf knowledge base for similar vulnerability patterns
3. Set up QEMU environment with matching kernel config
4. Reproduce the crash with PoC
5. Dynamic analysis with GDB to confirm root cause
6. Assess exploitability
7. Develop and test patch
8. Package report and artifacts
```

### 1.4 Subagent Dispatch Strategy

This skill makes heavy use of subagents (the Agent tool) to parallelize work.
The guiding principle: **plan centrally, execute in parallel, synthesize results**.

**Parallel-safe tasks** (can run as concurrent subagents):
- Source code reading of different files/functions
- Git log / git blame on different paths
- Searching the kernelctf knowledge base
- Compiling kernel in a worktree
- Web research for related CVEs or patches

**Sequential tasks** (must wait for prior results):
- Dynamic analysis depends on QEMU environment being ready
- Patch writing depends on confirmed root cause
- Patch verification depends on patch being applied

When spawning subagents, always provide:
- Clear, self-contained task description
- All file paths and context needed (the subagent has no memory of your conversation)
- Expected output format
- Use `isolation: "worktree"` for tasks that modify files (compilation, patching)

---

## Phase 2: Source Acquisition & Static Analysis

### 2.1 Clone and Prepare Source

```bash
# Clone the appropriate tree
git clone --depth=1 --branch <version-tag> <tree-url> /path/to/analysis/kernel-src

# Or for full history (needed for git bisect):
git clone <tree-url> /path/to/analysis/kernel-src
git checkout <version-tag>
```

### 2.2 Static Analysis (Spawn as Subagents)

Launch these in parallel:

**Subagent A — Code Path Analysis**:
- Read the functions in the call stack, starting from the crash point
- Trace the data flow: where does the faulting pointer come from?
- Identify the object lifecycle: allocation, use, free
- Look for missing locks, reference count issues, error path leaks

**Subagent B — Git Archaeology**:
- `git log --oneline <file>` for recent changes to the affected files
- `git blame` on the vulnerable lines to find the introducing commit
- Check if there are already patches in mainline or -next that fix this
- Look for related fixes in the same area (often bugs cluster)

**Subagent C — Knowledge Base Cross-Reference**:
- Search `references/kernelctf-knowledge-base.md` for similar vulnerability patterns
- Search `references/vuln-classification.md` to classify the bug type
- Check if this subsystem has known exploit primitives

---

## Phase 3: Root Cause Analysis

This is the most critical phase. The symptom (what the crash log shows) often differs from
the actual bug.

### Common Symptom-vs-Root-Cause Mismatches

| Crash Symptom | Possible True Root Cause |
|---|---|
| NULL pointer dereference | UAF (object freed, memory reused/zeroed) |
| General Protection Fault | UAF (object freed, slab poisoned with 0x6b6b6b6b) |
| KASAN: slab-use-after-free | Straightforward UAF, but find the race condition |
| KASAN: slab-out-of-bounds | Off-by-one, integer overflow leading to undersized allocation |
| BUG: unable to handle page fault | UAF, double-free, or type confusion |
| WARNING in refcount_t | Reference count underflow — likely a UAF waiting to happen |
| UBSAN: shift-out-of-bounds | Integer handling bug, possibly exploitable for info leak |

**Always ask**: "What is the actual invariant violation, not just the symptom?"

Read `references/vuln-classification.md` for the full taxonomy of kernel vulnerability classes
and how to distinguish them.

### 3.1 Determine the True Bug Class

To identify the real root cause:

1. **Trace object lifetime**: When was the object allocated? When freed? Who still holds a reference?
2. **Identify the race window**: For concurrency bugs, what's the race between? (syscall vs IRQ, two CPUs, etc.)
3. **Check error paths**: Many kernel bugs live in error handling — a `goto err` that forgets to unlock or drop a reference
4. **Verify with KASAN alloc/free stacks**: If KASAN provides them, the allocation and free call stacks tell you exactly who created and destroyed the object

### 3.2 Build the Bug Narrative

Write a clear, chronological description:
1. Thread A does X, acquiring a reference to object O
2. Thread B does Y, freeing object O (the bug — missing lock/refcount)
3. Thread A accesses O → crash

This narrative is essential for the report and for writing a correct patch.

### 3.3 ASCII Art Diagrams (Required)

Every root cause analysis MUST include ASCII art diagrams to make complex data flows and
structures visually clear. Flat text descriptions of protocols, call chains, and memory
layouts are insufficient — diagrams make the analysis immediately understandable.

**Required diagrams** (include whichever are relevant):

#### Packet / Data Structure Layout

Show byte-level layout of attacker-controlled input, field offsets, and sizes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP/ECN   |         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|    Fragment Offset      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live | Protocol ←─── |        Header Checksum        |
+-+-+-+-+-+-+-+-+ ATTACKER      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Source Address                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Kernel Struct Layout (pahole-style)

Show struct field offsets, especially the field involved in the crash:

```
struct net_protocol {
    int (*handler)();              /*   0   8 */
    int (*err_handler)();          /*   8   8 */
    unsigned int no_policy:1;      /*  16: 0  */
    unsigned int icmp_strict_      /*  16: 1  */  ← crash dereferences NULL + 0x10
        tag_validation:1;                            to read this field
    u32 secret;                    /*  20   4 */
    /* total size: 24 */
};
```

#### Call Chain with Data Transformation

Show how data flows and transforms through each function, not just a list of function names:

```
ip_rcv()                          skb->data → [Outer IP | ICMP | Inner IP | Payload]
   │                                           ^^^^^^^^^^
   │  validates outer IP header                    │
   ▼                                               │
ip_local_deliver_finish()         __skb_pull()──────┘
   │                              skb->data → [ICMP | Inner IP | Payload]
   │  dispatches via inet_protos[1]                   │
   ▼                                                  │
icmp_rcv()                        pskb_pull()─────────┘
   │                              skb->data → [Inner IP | Payload]
   │  dispatches via icmp_pointers[3]        ←── ATTACKER CONTROLLED
   ▼
icmp_unreach()
   │  iph = (struct iphdr *)skb->data
   │  reads iph->protocol (attacker value)
   ▼
icmp_tag_validation(proto=253)
   │  inet_protos[253] → NULL
   │  NULL->icmp_strict_tag_validation
   ▼
╔═══════════════════╗
║  NULL DEREFERENCE  ║
╚═══════════════════╝
```

#### Object Lifecycle (for UAF bugs)

```
     CPU 0 (Thread A)              CPU 1 (Thread B)
          │                             │
    obj = alloc()                       │
          │                             │
    obj->refcnt = 1                     │
          │                        get_ref(obj)
          │                        obj->refcnt = 2
          │                             │
    put_ref(obj)  ─── BUG: ────   put_ref(obj)
    refcnt = 1        race on     refcnt = 0 → kfree(obj)
          │           refcnt            │
    obj->field  ←── UAF! ──────── (freed memory)
          │
     ╔════════╗
     ║ CRASH  ║
     ╚════════╝
```

#### Memory / Slab Layout (for heap bugs)

```
kmalloc-256 slab page:
┌──────────┬──────────┬──────────┬──────────┐
│ Object 0 │ Object 1 │ Object 2 │ Object 3 │
│ (freed)  │ VULN OBJ │ msg_msg  │ (free)   │
│          │ ←─ UAF ──│← spray ──│          │
└──────────┴──────────┴──────────┴──────────┘
                 │          ▲
                 └── realloc with controlled data
```

These diagrams are not optional decoration — they are the core of a clear analysis.
The report should be understandable from the diagrams alone, with the text providing
additional detail.

---

## Phase 4: Dynamic Analysis (QEMU + GDB)

### 4.1 Set Up QEMU Environment

Read `references/qemu-setup.md` for detailed setup instructions.

Key requirements:
- Build kernel with: `CONFIG_KASAN=y`, `CONFIG_DEBUG_INFO=y`, `CONFIG_GDB_SCRIPTS=y`,
  `CONFIG_FRAME_POINTER=y`, `CONFIG_HARDENED_USERCOPY=y` (and relevant subsystem configs)
- Use `virtme-ng` for quick boot if applicable, or full QEMU with custom rootfs
- Prepare a minimal rootfs with the PoC compiled and ready

```bash
# Example QEMU launch (adjust as needed)
qemu-system-x86_64 \
  -kernel arch/x86/boot/bzImage \
  -initrd rootfs.cpio.gz \
  -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr" \
  -nographic \
  -m 2G \
  -smp 2 \
  -s -S  # GDB stub on port 1234, halt at start
```

### 4.2 Reproduce and Debug

1. Boot the vulnerable kernel in QEMU
2. Run the PoC and confirm the crash reproduces
3. Attach GDB: `gdb vmlinux -ex "target remote :1234"`
4. Set breakpoints at key functions identified in static analysis
5. Step through the vulnerable code path
6. Confirm the root cause hypothesis from Phase 3

### 4.3 Key GDB Commands for Kernel Debugging

```
# Kernel-specific
lx-symbols                    # Load kernel module symbols
lx-dmesg                      # Print kernel log
lx-ps                         # List processes
lx-lsmod                      # List modules

# Analysis
p *(struct sk_buff *)$rdi     # Print kernel structures
info threads                   # Check CPU/thread state
bt                             # Backtrace
watch *(int *)0xaddr          # Hardware watchpoint on the vulnerable field
```

---

## Phase 5: Exploitability Assessment

After confirming the root cause, assess whether this bug is exploitable for privilege escalation,
information leak, or denial of service.

Read `references/exploitability-assessment.md` for the full assessment framework.

### 5.1 Key Questions

1. **What primitive does this bug give an attacker?**
   - UAF → potential arbitrary read/write via heap spray
   - OOB write → adjacent object corruption
   - Double-free → overlapping allocations
   - Info leak → KASLR bypass
   - Race condition → how wide is the window? Is it winnable?

2. **What is the attack surface?**
   - Reachable from unprivileged user? Needs `CAP_NET_ADMIN`? Needs user namespaces?
   - Reachable from network? From a container?

3. **What objects share the same slab cache?**
   - For UAF/OOB: what useful kernel objects (e.g., `struct cred`, `struct file`, `msg_msg`,
     `pipe_buffer`, `sk_buff`) live in the same `kmalloc-*` bucket?
   - Can the attacker control allocation/free timing?

4. **What mitigations apply?**
   - KASLR, SMEP, SMAP, CFI, RANDSTRUCT
   - `CONFIG_SLAB_FREELIST_RANDOM`, `CONFIG_SLAB_FREELIST_HARDENED`
   - `CONFIG_HARDENED_USERCOPY`, `CONFIG_USERFAULTFD` availability

5. **Is there precedent?**
   - Search the kernelctf knowledge base for exploits in the same subsystem or using similar primitives
   - Reference known techniques: `msg_msg` spray, `pipe_buffer` ROP, `io_uring` primitives, cross-cache attacks

### 5.2 Exploitability Rating

Rate as one of:
- **Highly Exploitable**: Reliable UAF/OOB-write with good heap spray target, reachable unprivileged
- **Likely Exploitable**: Bug gives useful primitive but exploitation has challenges (narrow race, limited control)
- **Potentially Exploitable**: Bug exists but exploitation path unclear or requires unusual conditions
- **Unlikely Exploitable**: DoS only, or requires already-privileged attacker
- **Not Exploitable**: Theoretical bug with no practical attack path

---

## Phase 6: Patch Development & Verification

### 6.1 Write the Patch

Read `references/patch-writing-guide.md` for Linux kernel patch conventions.

**Core principles**:
- Fix the root cause, not the symptom (don't just add a NULL check if the real bug is a missing lock)
- Minimal diff — change only what's necessary
- Follow the existing code style of the file you're modifying
- Add appropriate locking, reference counting, or lifetime management
- Consider all callers — your fix must not break other code paths

**Commit message format**:

The commit message MUST include the decoded backtrace from `scripts/decode_stacktrace.sh`.
This is standard Linux kernel convention — look at any KASAN/bug fix in mainline `git log`
and you'll see the decoded trace. It makes the bug searchable by function name, file, and line.

```
subsystem: brief description of the fix

Longer explanation of what the bug is, how it manifests, and why
this patch fixes it. Include the root cause analysis.

Decoded backtrace (from scripts/decode_stacktrace.sh):

 BUG: KASAN: null-ptr-deref in icmp_unreach (net/ipv4/icmp.c:1085)
 Call Trace:
  <IRQ>
  icmp_unreach (net/ipv4/icmp.c:1143)
  icmp_rcv (net/ipv4/icmp.c:1524)
  ip_protocol_deliver_rcu (net/ipv4/ip_input.c:205)
  ip_local_deliver_finish (net/ipv4/ip_input.c:234)
  ip_local_deliver (net/ipv4/ip_input.c:254)
  ip_rcv (net/ipv4/ip_input.c:569)
  </IRQ>

Fixes: <12-char-hash> ("original commit title that introduced the bug")
Reported-by: <who reported> <email>
Signed-off-by: <your name> <email>
```

**Backtrace guidelines for the commit message**:
- Use the DECODED trace (with file:line), not raw hex addresses
- Trim to the relevant frames — typically the crash point + 5-10 key frames in the call chain
- Remove noise: `? unreliable_frame`, timestamps, register dumps, module lists
- Include the bug title line (e.g., `BUG: KASAN: ...`)
- Include `<IRQ>` / `</IRQ>` / `<TASK>` context markers
- Indent with a single space

### 6.2 Validate the Patch

1. **checkpatch.pl**: `./scripts/checkpatch.pl --strict 0001-*.patch`
2. **Compilation**: `make -j$(nproc)` with at least `defconfig` and the relevant config options
3. **Sparse/smatch** (if available): Static analysis for locking errors
4. **Subsystem selftests**: `make -C tools/testing/selftests/<subsystem> run_tests`

### 6.3 Verify in QEMU

This is the critical verification step — the patch MUST be tested with the PoC:

1. Build the patched kernel
2. Boot in QEMU with the same configuration as the vulnerable kernel
3. Run the PoC — it must NOT crash
4. Check `dmesg` for any new warnings or errors
5. Run basic smoke tests to ensure the patched kernel is functional

```bash
# Boot patched kernel and run PoC
qemu-system-x86_64 -kernel bzImage-patched -initrd rootfs.cpio.gz \
  -append "console=ttyS0 nokaslr" -nographic -m 2G -smp 2

# Inside QEMU:
./poc_binary
dmesg | grep -iE "bug|error|warning|kasan|ubsan|panic"
```

### 6.4 Regression Check

- Ensure no new KASAN/UBSAN warnings appear
- If the subsystem has selftests, run them on the patched kernel
- Test edge cases: what happens at the boundaries of your fix?

### 6.5 Restore Source Tree (Required)

After verification is complete, the kernel source tree MUST be restored to its original
(unpatched) state. The analysis process must be non-destructive — the patch lives only
in the report's `patch/` directory as a standalone `.patch` file.

```bash
# Restore all modified source files
git checkout -- <modified-files>

# Verify clean state
git diff --stat   # should show no changes
```

The correct workflow for the entire build-and-test cycle:

```
1. Save the patch:  git diff > report/patch/0001-fix.patch
2. Stash changes:   git stash
3. Build VULNERABLE kernel from clean source
4. Copy vulnerable bzImage/vmlinux to report/kernel/test-*
5. Pop stash:       git stash pop
6. Build PATCHED kernel
7. Copy patched bzImage/vmlinux to report/kernel/patched-*
8. Test both in QEMU
9. RESTORE source:  git checkout -- <files>   ← DO NOT FORGET
```

If you skip step 9, the source tree is left in a modified state, which is messy and
may confuse subsequent analyses or the user's own work.

---

## Phase 7: Report Generation & Artifact Packaging

### 7.1 Output Directory Structure

Create a self-contained analysis folder:

```
<CVE-or-bug-id>-analysis/
├── report.md                    # Full analysis report
├── poc/
│   ├── poc.c                    # PoC source code
│   ├── Makefile                 # PoC build instructions
│   └── poc_binary               # Compiled PoC (optional)
├── patch/
│   ├── 0001-fix-description.patch  # The git format-patch output
│   └── patch_description.md     # Patch explanation
├── kernel/
│   ├── test-vmlinux             # Vulnerable kernel vmlinux (for GDB)
│   ├── test-bzImage             # Vulnerable kernel bzImage
│   ├── patched-vmlinux          # Patched kernel vmlinux
│   ├── patched-bzImage          # Patched kernel bzImage
│   └── .config                  # Kernel config used
├── env/
│   ├── rootfs.cpio.gz           # Root filesystem image
│   ├── run-vulnerable.sh        # Script to boot vulnerable kernel
│   └── run-patched.sh           # Script to boot patched kernel
└── logs/
    ├── crash.log                # Original crash log
    ├── gdb-session.log          # Key GDB session output
    └── patch-verification.log   # Log showing PoC no longer crashes
```

### 7.2 Report Template

Read `assets/report_template.md` for the full template. The report must include:

1. **Executive Summary**: One-paragraph overview — what the bug is, severity, exploitability, fix status
2. **Bug Classification**: Type, affected subsystem, affected versions, CVE (if assigned)
3. **Crash Log Analysis**: Annotated crash log with key signals highlighted
4. **Root Cause Analysis**: Detailed technical analysis with code references
5. **Vulnerability Timeline**: Object lifecycle, race window, or error path that leads to the bug
6. **Exploitability Assessment**: Rating and justification, with references to similar known exploits
7. **Patch**: The fix, with explanation of why it's correct
8. **Verification Results**: Evidence that the patch fixes the bug without regressions
9. **References**: Related CVEs, kernel commits, kernelctf entries

### 7.3 Run Scripts

Generate `run-vulnerable.sh` and `run-patched.sh` that boot QEMU with the correct parameters:

```bash
#!/bin/bash
# run-vulnerable.sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
qemu-system-x86_64 \
  -kernel "$SCRIPT_DIR/../kernel/test-bzImage" \
  -initrd "$SCRIPT_DIR/rootfs.cpio.gz" \
  -append "console=ttyS0 root=/dev/ram rdinit=/init nokaslr" \
  -nographic -m 2G -smp 2 \
  -net nic -net user,hostfwd=tcp::10022-:22
```

---

## Subagent Orchestration Patterns

### Pattern 1: Parallel Static Analysis

```
Main Agent (Coordinator):
├── Subagent A: Read and analyze functions in the crash call stack
├── Subagent B: Git log/blame the affected files, find introducing commit
├── Subagent C: Search knowledge base for similar vulnerability patterns
└── Main Agent: Synthesize results → determine root cause hypothesis
```

### Pattern 2: Build & Test Pipeline

```
Main Agent (Coordinator):
├── Subagent D [worktree]: Build vulnerable kernel with debug configs
├── Subagent E [worktree]: Build patched kernel
└── Main Agent: When both complete → verify with QEMU
```

### Pattern 3: Cross-Reference Research

```
Main Agent (Coordinator):
├── Subagent F: Search kernelctf for exploits in same subsystem
├── Subagent G: Search for related CVEs and patches upstream
├── Subagent H: Analyze slab cache sharing for exploitability
└── Main Agent: Synthesize exploitability assessment
```

### When to Use Subagents vs. Do It Yourself

- **Use subagents** when: tasks are independent, IO-bound (file reading, git operations, web fetch),
  or you need isolated worktrees (compilation)
- **Do it yourself** when: the task is a quick single-file read, or results of step N are needed
  for step N+1 with no parallelism opportunity

---

## Important Considerations

### Security & Ethics

This skill is for **authorized security research, defensive analysis, and educational purposes**.
The goal is to understand vulnerabilities to fix them and improve kernel security.
- Always focus on developing correct patches, not weaponizing bugs
- If a PoC is needed for verification, keep it minimal — just enough to trigger the bug
- Report findings responsibly

### Linux Coding Standards

When writing patches, strictly follow:
- `Documentation/process/coding-style.rst`
- `Documentation/process/submitting-patches.rst`
- Run `scripts/checkpatch.pl --strict` on all patches
- Tabs for indentation, 80-column lines (soft limit, 100 hard)
- No unnecessary whitespace changes
- Commit messages: imperative mood, 72-char subject, wrapped body

### Avoiding Patch Regressions

- Test with multiple kernel configs (defconfig, allyesconfig with relevant options)
- Consider all callers of modified functions
- If adding locking, verify no deadlock potential (lock ordering)
- If modifying reference counting, verify no leaks or double-frees introduced
- If changing error paths, verify all resources are properly cleaned up

### Tools Reference

| Tool | Purpose |
|---|---|
| `scripts/decode_stacktrace.sh` | Decode raw kernel stack traces |
| `scripts/get_maintainer.pl` | Find subsystem maintainers |
| `scripts/checkpatch.pl` | Validate patch coding style |
| `virtme-ng (vng)` | Quick kernel boot for testing |
| `addr2line` | Resolve addresses to source lines |
| `pahole` | Inspect struct layouts and padding |
| `crash` | Kernel crash dump analysis |

---

## Reference Files

These files contain detailed guidance for specific phases. Read them when you reach the
relevant phase — they contain information too detailed for the main skill but essential
for correct analysis.

- `references/crash-log-analysis.md` — How to parse KASAN, UBSAN, BUG, panic logs with examples
- `references/vuln-classification.md` — Taxonomy of kernel vulnerability classes and identification
- `references/exploitability-assessment.md` — Framework for assessing kernel bug exploitability
- `references/patch-writing-guide.md` — Linux kernel patch conventions and common patterns
- `references/qemu-setup.md` — Setting up QEMU+GDB kernel debugging environments
- `references/kernelctf-knowledge-base.md` — Exploit techniques and patterns from Google's kernelCTF
- `assets/report_template.md` — Template for the final analysis report
