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

### 1.2 Acquire the PoC

If the user provides a crash log but no PoC, you need to obtain or create one.

**From syzbot**: Read `references/syzbot-workflow.md` for details.
```bash
# Download C reproducer from syzbot
curl -sL '<syzbot-repro-url>' -o poc.c
gcc -o poc -static -lpthread poc.c   # always static-link for QEMU rootfs
```

**From CVE databases**: Search for public PoCs on GitHub, Exploit-DB, or the CVE references.

**Write from scratch**: If no PoC exists, write a minimal trigger based on the crash call trace:
1. Identify the syscall entry point from the bottom of the stack trace
2. Set up required preconditions (namespaces, sysctl, devices)
3. Issue the triggering syscall sequence
4. For race conditions: use pthreads to run concurrent paths

**PoC validation checklist**:
- [ ] Compiles with `gcc -static` (needed for minimal QEMU rootfs)
- [ ] Does it need root? Network? Specific sysctl?
- [ ] Does it need `unshare(CLONE_NEWUSER|CLONE_NEWNET)` for namespaces?
- [ ] Is the crash reliable or does it need loop/stress testing?

### 1.3 Identify the Kernel Subsystem and Source Tree

**Do NOT guess the tree from the top-level directory name alone.** Many subsystems have
independent maintainer trees even though their code lives under a shared parent directory.
The canonical source of truth is `scripts/get_maintainer.pl` and the `MAINTAINERS` file.

**Step 1: Run `get_maintainer.pl` on the affected file**

```bash
./scripts/get_maintainer.pl --scm --web <path/to/affected/file>
# The "SCM:" line tells you the correct git tree
# The "W:" line tells you the web page / mailing list
```

**Step 2: Cross-reference with the subsystem tree mapping**

Some paths are deceptive — always match **most-specific path first**:

| Source path | Subsystem | Git tree (fixes) | Prefix |
|---|---|---|---|
| `net/bluetooth/` | Bluetooth | `bluetooth/bluetooth.git` | `PATCH bluetooth` |
| `net/wireless/`, `drivers/net/wireless/` | WiFi | `wireless/wifi.git` | `PATCH wifi` |
| `net/mac80211/` | WiFi (mac80211) | `wireless/wifi.git` | `PATCH wifi` |
| `net/netfilter/`, `net/ipv4/netfilter/` | Netfilter | `netfilter/nf.git` | `PATCH nf` |
| `net/bridge/` | Bridge | `netdev/net.git` | `PATCH net` |
| `net/ipv4/`, `net/ipv6/`, `net/core/` | Networking core | `netdev/net.git` | `PATCH net` |
| `net/sctp/`, `net/dccp/`, `net/tipc/` | Networking | `netdev/net.git` | `PATCH net` |
| `net/can/` | CAN | `linux-can/linux.git` | `PATCH can` |
| `net/nfc/` | NFC | `sameo/nfc.git` | `PATCH nfc` |
| `kernel/bpf/`, `net/bpf/` | BPF | `bpf/bpf.git` | `PATCH bpf` |
| `drivers/net/ethernet/` | Network drivers | `netdev/net.git` | `PATCH net` |
| `drivers/bluetooth/` | Bluetooth drivers | `bluetooth/bluetooth.git` | `PATCH bluetooth` |
| `drivers/gpu/drm/` | DRM/GPU | `drm/drm.git` | `PATCH drm` |
| `drivers/usb/` | USB | `usb/usb.git` | `PATCH usb` |
| `sound/` | Sound/ALSA | `tiwai/sound.git` | `PATCH sound` |
| `fs/ext4/` | ext4 | `tytso/ext4.git` | `PATCH ext4` |
| `fs/btrfs/` | Btrfs | `kdave/btrfs.git` | `PATCH btrfs` |
| `fs/xfs/` | XFS | `djwong/xfs-linux.git` | `PATCH xfs` |
| `mm/` | Memory management | `akpm/mm.git` | `PATCH mm` |
| `io_uring/` | io_uring | `axboe/linux-block.git` | `PATCH io_uring` |
| `security/apparmor/` | AppArmor | `jj/linux-apparmor.git` | `PATCH apparmor` |
| Others | General | `torvalds/linux.git` | `PATCH` |

**The trap**: `net/bluetooth/` is under `net/` but does NOT go to `netdev/net.git`.
Bluetooth patches go to `bluetooth/bluetooth.git` and are picked by the Bluetooth
maintainer (Luiz Augusto von Dentz). Eventually they flow through `netdev/net.git`
into mainline, but patches must be submitted to the Bluetooth tree directly.

```
WRONG:  net/bluetooth/l2cap_core.c → "this is net/ → netdev/net.git → PATCH net"
RIGHT:  net/bluetooth/l2cap_core.c → get_maintainer.pl → bluetooth.git → PATCH bluetooth
```

**Step 3: When in doubt, always trust `get_maintainer.pl`**

```bash
# It handles all the edge cases in MAINTAINERS
./scripts/get_maintainer.pl --scm net/bluetooth/l2cap_core.c
# Output will show bluetooth.git, not net.git
```

**Step 4: Identify the relevant kernel version**
- Check if the bug exists in mainline, stable, or LTS
- Parse from crash log: `grep 'Not tainted' crash.log`

### 1.4 Create the Analysis Plan

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

### 1.5 Subagent Dispatch Strategy

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

### 2.1 Acquire and Update Source

In practice, the user usually already has a local kernel source tree. Do NOT blindly
clone a fresh repo every time — check what's available first.

**Case A: User already has a local kernel source tree (most common)**

```bash
cd /path/to/existing/kernel-src

# 1. Check current state
git status                           # any uncommitted changes?
git describe --tags --abbrev=0       # what version is this?
git remote -v                        # what remote does it track?

# 2. Fetch latest from upstream — ALWAYS do this
git fetch origin
git fetch --tags origin

# 3. Check how far behind we are
git log --oneline HEAD..origin/master | head -20
# If significantly behind (>100 commits), strongly recommend updating

# 4. Update to latest (if tree is clean)
git pull --rebase origin master
# Or if on a specific branch:
git pull --rebase origin <branch>
```

If the user has uncommitted changes (their own annotations, previous patches, etc.):
- `git stash` first, then fetch/pull, then `git stash pop` after analysis
- Or work on a detached HEAD at the latest tag: `git checkout <latest-tag>`

**Case B: No local source — clone fresh**

```bash
# For the appropriate subsystem tree:
git clone <tree-url> /path/to/analysis/kernel-src
cd /path/to/analysis/kernel-src
git checkout <version-tag>

# For full history (needed for git bisect / git blame):
git clone <tree-url> /path/to/analysis/kernel-src

# Shallow clone is faster but limits git bisect:
git clone --depth=1 --branch <version-tag> <tree-url> /path/to/analysis/kernel-src
```

**Case C: Local source exists but tracks a different tree**

Sometimes the user has `torvalds/linux.git` but the bug is in a subsystem tree
(e.g., `netdev/net.git`). Add it as a second remote:

```bash
git remote add net git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git
git fetch net
git log net/master --oneline | head -5
```

### 2.2 Verify Source Version (Required — Do This Before Any Analysis)

Writing a patch against stale source is a critical mistake: the patch may not apply to
mainline, may fix an already-fixed bug, or may be semantically wrong due to context changes.
Always verify the source is current before proceeding.

**Step 1: Check if the local tree is up-to-date with remote**

```bash
git fetch origin
git log HEAD..origin/master --oneline | head -10
# If output is non-empty → the local tree is behind. Update it:
git pull --rebase origin master
```

**Step 2: Check if the bug is already fixed upstream**

This is the most important check — someone may have already submitted a fix.

```bash
# Search for patches touching the vulnerable function
git log --all --oneline -S '<vulnerable_function_name>' -- <file>

# Search for Fixes: tags referencing the introducing commit
git log --all --oneline --grep='Fixes: <introducing-commit-short-hash>'

# Search commit messages for the bug description keywords
git log --all --oneline --grep='<key_keyword>' -- <file>

# Check the linux-stable tree for backported fixes
git log --all --oneline --grep='<CVE-number>'
```

If a fix already exists:
- **Report it** — tell the user the bug is already fixed, with the fixing commit hash
- **Verify the fix** — read the upstream fix to confirm it actually addresses the root cause
- **Skip to Phase 7** — no need to write a new patch; document the existing fix in the report

**Step 3: Two-Stage Workflow — Analyze on Crash Version, Patch on Latest**

This is a **critical distinction** that the skill MUST enforce:

Extract the crash kernel version from the log first:

```bash
# Parse the crash log for the kernel version
CRASH_VERSION=$(grep -oP 'Not tainted \K\S+' crash.log)
# e.g., CRASH_VERSION="6.12.77"

# Find the closest git tag
CRASH_TAG=$(git tag -l "v${CRASH_VERSION}*" | sort -V | tail -1)
# Or for stable kernels: git tag -l "v$(echo $CRASH_VERSION | cut -d. -f1-2)*" | sort -V | tail -1

# Get current latest upstream
git fetch origin --tags
LATEST=$(git describe --tags --abbrev=0 origin/master)
```

```
┌────────────────────────────────────────────────────────────────────┐
│  Crash log says kernel $CRASH_VERSION (e.g., a stable/old release) │
│  Latest upstream is $LATEST (e.g., mainline HEAD)                  │
│                                                                     │
│  WRONG: Write the patch against $CRASH_VERSION and call it done.    │
│  RIGHT: Analyze on $CRASH_VERSION, then rebase the fix onto         │
│         $LATEST mainline/subsystem-tree HEAD before finalizing.     │
└────────────────────────────────────────────────────────────────────┘
```

**Stage 1 — Analyze & Reproduce on the crash version**:
```bash
# Checkout the crash kernel version for analysis and QEMU reproduction
git checkout "$CRASH_TAG"
# Build, boot in QEMU, reproduce the crash, do root cause analysis
# This ensures you understand the bug in the exact context it was reported
```

**Stage 2 — Fetch latest code and check before writing the patch**:
```bash
# ALWAYS fetch the latest subsystem tree before writing ANY patch
git fetch origin
git fetch --tags origin

# Check: does the vulnerable code still exist in the latest version?
git show origin/master:<path/to/vulnerable/file> | grep '<vulnerable_function>'
# If the code has been refactored or removed → the bug may be moot in mainline

# Check: has someone already fixed this in the latest tree?
git log origin/master --oneline -S '<vulnerable_function>' | head -10
git log origin/master --oneline --grep='<key_keyword>' -- <file> | head -10

# If bug still exists in latest → write patch against latest HEAD:
git checkout origin/master
# Or for networking fixes:
git checkout net/main       # netdev/net.git main branch
```

**Stage 3 — Write the patch against the latest code**:
```bash
# The patch MUST be based on the latest subsystem tree HEAD
# NOT on the old crash kernel version
git diff > patch.diff      # your fix, based on latest code

# Verify the fix also applies to the crash version (for QEMU testing)
git stash
git checkout "$CRASH_TAG"
git stash pop              # if it applies cleanly
# Or: git cherry-pick / manual port if context differs
```

**Why this matters**:
- Upstream WILL NOT accept patches based on old stable kernels
- The code around the bug may have changed (variable renames, refactors, new callers)
- A patch against an old stable may not apply to the latest mainline at all
- Even if the patch applies, context lines may differ → `git am` fails

| Crash kernel version | Analyze on | Write patch against |
|---|---|---|
| Stable (e.g., X.Y.Z) | `v$CRASH_VERSION` tag | Latest `origin/master` or subsystem HEAD |
| Mainline (e.g., X.Y-rcN) | `v$CRASH_VERSION` tag | Latest `origin/master` |
| Distro (e.g., X.Y.Z-distro) | Distro source | Upstream mainline HEAD |
| net-next / subsystem tree | Subsystem HEAD | Subsystem HEAD (already latest) |

**If the local tree is old and behind upstream**:
```bash
# You MUST update before writing the patch
git fetch origin
git log --oneline HEAD..origin/master | wc -l
# If significantly behind → pull or checkout latest

# Check if the vulnerable file has changed significantly
git diff "$CRASH_TAG"..origin/master -- <path/to/file> | diffstat
# If large diff → the patch context has changed, must write against latest
```

**Step 4: Record the base commit in the report**

Always document the exact commit your patch is based on:

```bash
echo "Patch base: $(git log --oneline -1 HEAD)" >> report_metadata.txt
# e.g., "Patch base: abc123def456 Merge tag 'net-6.12-rc4'"
```

This goes in the report's metadata section so anyone applying the patch knows exactly
which tree state it was developed against.

**If the source tree was already present** (e.g., the user has a local clone):
- Still run Steps 1-3 — don't assume it's current
- `git fetch && git log HEAD..origin/master --oneline` is fast and catches stale trees
- If the tree is weeks/months behind, warn the user before proceeding

### 2.3 Static Analysis (Spawn as Subagents)

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

### 3.2 Build the Bug Narrative — Source-Level Deep Trace (Required)

A shallow narrative ("Thread A frees, Thread B uses" or "missing NULL check") is NOT sufficient.
After confirming the root cause, you must produce a **source-level deep trace** that combines
the kernel source code and the PoC's behavior to explain exactly how the bug manifests.

This trace must be generated **from the actual source code and PoC for each specific bug**.
The approach varies by vulnerability class — use the matching methodology below.

#### Common Steps (All Vulnerability Types)

**Step A: Map PoC actions to kernel code paths**

Read the PoC and trace what each part does in the kernel:
- `PoC line/action → syscall/packet → kernel entry function (file.c:line)`
- For multi-threaded PoCs: which thread does what, and what's the intended race

**Step B: Read the relevant kernel source with file:line citations**

For every function in the call chain from syscall entry to crash:
- What does it do? What data does it read/write?
- What validation/checks does it perform (or fail to perform)?
- What synchronization (locks, RCU, refcount, memory barriers) does it use?

**Step C: Build a timeline/flow diagram from source**

Produce a visual that shows the bug's progression. The format depends on the
vulnerability class (see below). Use actual function names and file:line references
from the source, not generic placeholders.

**Step D: Explain why the bug exists**

- What invariant is violated?
- What mechanism was supposed to prevent this? Why did it fail?
- Is this a design flaw or an implementation oversight?

#### Per-Vulnerability-Class Methodology

**Choose the methodology that matches your bug's root cause.** Not every bug involves
refcounts or races — trace what's actually relevant.

**UAF / Double-Free / Refcount bugs**:
- Trace the object's full refcount lifecycle: creation (init → get) → normal state →
  destruction (put → release → free), with refcount value at each step
- Identify who holds each reference and when they release it
- Show the race timeline (side-by-side CPUs) with refcount transitions as `before→after`
- Highlight: missing `kref_get_unless_zero`, premature `put`, or unprotected reader

**Race conditions (non-refcount)**:
- Identify the shared state being raced on (flag, pointer, list, counter)
- Show the TOCTOU window: what's checked, what changes, what's used
- Side-by-side CPU timeline showing interleaving that leads to the bug
- Highlight: missing lock, wrong lock scope, missing memory barrier

**NULL pointer dereference (non-race)**:
- Trace the data flow: where does the NULL pointer originate?
- Is it from a failed allocation? A missing initialization? An error path that
  skips setup? A sparse array lookup (like `inet_protos[]`)?
- Show the call chain from the point where NULL enters to the crash dereference
- Highlight: what validation is missing and where it should be

**Out-of-bounds (OOB) read/write**:
- Trace the buffer allocation: what size, from where, based on what input?
- Trace the access: what index/offset, from where, based on what input?
- Show the arithmetic: `allocated_size` vs `accessed_offset` — why does it overflow?
- If integer overflow: show the multiplication/addition that wraps
- Highlight: missing bounds check, wrong size calculation, signedness confusion

**Logic bugs / State machine errors**:
- Map out the state machine: what states exist, what transitions are valid?
- Show the sequence of operations that reaches an "impossible" state
- Trace the error path that skips a required state transition
- Highlight: missing state check, wrong transition order, error path that forgets cleanup

**Info leaks**:
- Trace the data flow from kernel memory to user space
- Identify the uninitialized field, padding bytes, or stale pointer
- Show the struct layout with `pahole` — which bytes are leaked?
- Highlight: missing memset/initialization, struct padding, wrong copy size

**Type confusion**:
- Show the two types involved and their different layouts
- Trace how the object gets cast/reinterpreted as the wrong type
- Highlight which fields overlap incorrectly (especially function pointers vs data)

#### Step E: Visualize Your Analysis with ASCII Diagrams

Diagrams are NOT a separate step — they are the **visual output of the source analysis above**.
After completing Steps A-D, produce diagrams that summarize what you found. The diagrams must
reference actual function names and file:line from YOUR analysis, not generic templates.

Generate whichever diagram types are relevant to the bug:

- **Call chain + data transformation**: Show how data flows through each function with
  `skb->data` / pointer / buffer state at each layer. Each box = actual function (file:line).
- **Race timeline (for concurrency bugs)**: Side-by-side CPUs with actual function names,
  refcount/state transitions, and the race window marked.
- **Struct layout (for OOB/type confusion/info leak)**: pahole-style field offsets showing
  which field is corrupted/leaked/confused. Use actual struct name from the source.
- **Packet/data format (for protocol bugs)**: Byte-level layout of attacker input showing
  which fields are controlled and where validation is missing.
- **Object lifecycle (for UAF)**: Allocation → use → free → use-after-free with refcount
  values at each step, referencing actual functions.
- **State machine (for logic bugs)**: Valid vs actual state transitions.
- **Memory/slab layout (for heap bugs)**: Slab page showing adjacent objects.

**The diagram must reflect your source code analysis — not be a generic template.**
For example, a call chain diagram should use the real function names you found in Step B,
not placeholder names like `function_a()`.

#### Quality Criteria (All Types)

- Every source reference has a **file:line** citation
- The PoC's behavior is mapped to kernel code paths
- State changes (refcount, lock, flag, pointer) show **before→after** values
- The crash is traced to a specific struct field and offset
- Diagrams use actual function/struct names from the source analysis, not placeholders
- There's a clear explanation of **what's broken and why**

#### What to Avoid

- Generic descriptions without source references ("the object is freed then used")
- Drawing diagrams without doing the source analysis first (diagrams are OUTPUT, not INPUT)
- Using only one methodology for all bug types (not everything is a refcount race)
- Skipping the PoC→kernel mapping (the reader needs to understand HOW the bug triggers)
- Copying template diagrams instead of generating them from your analysis

### 3.3 Determine Affected Version Range

After identifying the introducing commit, determine the exact affected version range:

```bash
# Find the earliest release tag containing the introducing commit
git tag --contains <introducing-commit> | sort -V | head -5
# e.g., v3.13-rc1 → bug exists since v3.13

# If a fix already exists upstream, find when it landed
git tag --contains <fixing-commit> | sort -V | head -5
# e.g., v6.14-rc2 → fixed in v6.14

# Check which stable branches are affected
git branch -r --contains <introducing-commit> | grep 'stable'
# Check which stable branches have the fix backported
git branch -r --contains <fixing-commit> | grep 'stable'
```

Record in the report: `Affected: v3.13 — v6.13 (fixed in v6.14-rc2)`

For stable/LTS impact, check if the fix needs `Cc: stable@vger.kernel.org`.

### 3.4 Diagram Reference (Format Examples)

When producing diagrams in Step E above, use these format conventions. These are
**formatting templates only** — your actual diagrams must use real function names
and data from your source analysis.

See `references/crash-log-analysis.md` for address interpretation patterns and
`references/vuln-classification.md` for the bug classification decision tree.

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

### 4.4 Handling Non-Deterministic Reproduction

Race conditions and timing-sensitive bugs may not crash on every run.

**Increase reproduction rate**:
```bash
# Loop the PoC — run 100 times and count crashes
for i in $(seq 1 100); do
    timeout 5 ./poc 2>/dev/null
    echo "Run $i: exit=$?"
done

# Increase CPU count to widen race windows
qemu-system-x86_64 ... -smp 4    # or -smp 8

# Add system stress to increase scheduling pressure
stress-ng --cpu 4 --io 2 --vm 2 --timeout 60 &
./poc

# Use taskset to pin PoC threads to specific CPUs
taskset -c 0,1 ./poc
```

**Record reproduction rate** in the report: e.g., "Triggers 30/100 runs with -smp 4"

**If the PoC never crashes**:
- Verify kernel config matches the crash environment (especially KASAN, PREEMPT, SMP)
- Check if the compiler version matters (see `references/syzbot-workflow.md`)
- Try the exact syzbot kernel config if available
- Add `usleep()` delays in the PoC to manipulate race timing
- Use `ftrace` to confirm the race window exists even if it doesn't crash

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

### 5.2 Permission Gate Analysis (`capable` vs `ns_capable`) — Required

Before rating exploitability, you MUST trace the full permission check chain from
syscall entry to the vulnerable function. This determines the true attack surface.

**Why this matters**: A bug gated by `capable(CAP_NET_ADMIN)` needs real root.
But the SAME capability checked via `ns_capable()` is obtainable by any unprivileged
user through `unshare(CLONE_NEWUSER|CLONE_NEWNET)`. Many analysts miss this distinction,
leading to wrong severity assessments.

**Step 1: Find all capability checks in the call path**

```bash
# Trace from syscall entry to the vulnerable function
# and grep for every permission check along the way
grep -n 'capable\|ns_capable\|netlink_capable\|nfnl.*capable\|sk_net_capable' \
    net/netfilter/nfnetlink.c net/netfilter/nfnetlink_osf.c
```

**Step 2: Draw the permission gate diagram**

For each layer, document: what check, namespace-aware or not, what happens on failure.

```
User-space syscall (sendmsg on netlink socket)
         │
         ▼
Framework layer (e.g., nfnetlink_rcv)
│  netlink_net_capable(skb, CAP_NET_ADMIN)  ← namespace-aware (ns_capable)
│  userns root CAN pass this gate
│  failure → -EPERM, never reaches callback
         │
         ▼
Subsystem callback (e.g., nfnl_osf_add_callback)
│  capable(CAP_NET_ADMIN)  ← init_user_ns ONLY
│  userns root CANNOT pass this gate
│  failure → -EPERM
         │
         ▼
Vulnerable code path
```

**Step 3: Determine effective privilege requirement**

The effective requirement is the **most restrictive** check in the entire chain:

- If ANY layer uses `capable()` → needs real root (init_user_ns)
- If ALL layers use `ns_capable()` / `netlink_capable()` → reachable via userns
- Watch for framework vs callback mismatch (common pattern: framework is ns-aware
  but specific callback adds a stricter `capable()` check)

**Step 4: Document in the report**

Include the ASCII gate diagram in the report's exploitability section. State clearly:
- "Effective privilege: unprivileged (all checks are namespace-aware)" OR
- "Effective privilege: real root (callback uses `capable()` at line X)"
- Note if a future `capable()` → `ns_capable()` change would expand the attack surface

Read `references/exploitability-assessment.md` § "Critical: capable() vs ns_capable()"
for the full reference on which subsystems use which check.

### 5.3 Challenge Your Initial Assessment (Required)

**Do NOT stop at the first conclusion.** The most common mistake in kernel vulnerability
analysis is accepting the surface-level classification ("it's just a NULL deref / DoS")
without probing deeper. Many high-severity CVEs were initially dismissed as DoS.

After forming your initial assessment, systematically challenge it by asking these questions:

#### "Is the crash symptom hiding a stronger primitive?"

| Initial symptom | Ask yourself | Deeper reality? |
|---|---|---|
| NULL ptr deref | Is KASAN enabled? Without KASAN, a UAF to zeroed memory looks like NULL deref | Possibly UAF |
| NULL ptr deref at offset N | Is N controllable by the attacker? If so, this may be an arbitrary-address read | Possible info leak |
| GPF / non-canonical addr | Is the address derived from attacker data + corruption? Could the attacker make it canonical? | Possible controlled dereference |
| Single-byte OOB write | What's adjacent in the slab? Even 1 byte can flip a boolean flag or corrupt a refcount | Possible privilege escalation |
| Refcount WARNING | Does this eventually lead to a UAF if triggered enough times? | Likely UAF with patience |
| DoS-only race | With different timing, does the race give a wider window? Can userfaultfd freeze the race? | Possible reliable UAF |

#### "Is the NULL deref masking a UAF?" — The RCU Lifetime Pattern

This is the most commonly missed upgrade path. When you see a NULL deref in
RCU-protected code, ask: **where did the NULL come from?**

```
Pattern: RCU object has field cleared before grace period expires

Teardown path (writer):                Read path (RCU reader):
──────────────────────                 ────────────────────────
hlist_del_rcu(&obj->node)             rcu_read_lock()
                                       obj = rcu_dereference(hash[idx])
obj->ops->destroy(obj)                 │
  │                                    │  ← obj is valid (RCU protects it)
  ├─ resource_put(obj->ptr)            │     but obj->ptr is being destroyed
  ├─ obj->ptr = NULL     ◄── HERE      │
  │                                    │
  └─ call_rcu(&obj->rcu, free_fn)      obj->ptr->field  ← NULL DEREF
                                       rcu_read_unlock()
```

**The critical question**: What happens in the window BETWEEN `resource_put(obj->ptr)`
and `obj->ptr = NULL`?

```
Timeline:
  T1: resource_put(obj->ptr)  → obj->ptr's refcount drops to 0 → memory freed
  T2: ───────────────────────── WINDOW: obj->ptr points to FREED MEMORY
  T3: obj->ptr = NULL         → now it's "safely" NULL
  T4: call_rcu(free_fn)       → obj itself deferred

  If reader accesses obj->ptr between T1 and T3 → UAF (not NULL deref!)
  If reader accesses obj->ptr after T3 → NULL deref (the "safe" crash)
```

**The PoC that crashes with NULL deref is hitting the T3→T4 window.**
But the T1→T3 window is more dangerous — it's a real UAF where the reader
follows a dangling pointer to freed memory.

**How to evaluate this**:
1. Read the teardown code — is there a `put`/`release`/`free` BEFORE the `= NULL`?
2. If yes: the freed memory could be reallocated with attacker-controlled content
3. What object is being freed? What slab cache? What size?
4. Can the attacker spray that cache between T1 and T3?
5. What fields does the reader dereference? Function pointers? Data?

**Hypothetical example — generic subsystem teardown**:
```
some_subsystem_destroy(obj):
  dev_put(obj->netdev, ...)        ← T1: netdev refcount → 0, memory freed
  ──────────────────────────────── ← WINDOW: obj->netdev is dangling pointer
  obj->netdev = NULL               ← T2: "safe" NULL
  call_rcu(&obj->rcu, obj_free)    ← T3: obj itself deferred

Reader hitting T1-T2 window: obj->netdev → freed memory
→ if reader dereferences function pointers through it → code execution
→ MUCH more dangerous than the NULL deref at T2+
```

Look for this pattern whenever you see a NULL deref in RCU-protected code where
the NULL comes from an explicit assignment in a teardown/destroy path.

**If you find this pattern, the bug upgrades from "DoS" to "Likely/Highly Exploitable".**

#### "Can I get a different/stronger primitive from the same root cause?"

Think about what happens if you **change the PoC strategy**:

- **Different timing**: The current PoC crashes immediately, but what if you delay
  the second operation? Could you get a UAF instead of a NULL deref?
- **Different object size**: Can you control the allocation size to land in a more
  useful slab cache?
- **Different protocol/path**: The bug might be reachable through multiple code paths —
  does another path give a write instead of a read?
- **Partial trigger**: Instead of fully triggering the crash, can you stop halfway
  and get an info leak or partial corruption?
- **Win the earlier race window**: If the NULL assignment masks a UAF (see above),
  can the PoC hit the pre-NULL window instead?

#### "Can this be chained with other bugs?"

Even a "DoS-only" bug can be valuable in a chain:
- **Info leak + this bug**: If you have a separate KASLR bypass, does this bug
  become exploitable?
- **This bug + another write**: A read primitive from this bug + a write primitive
  from another bug = full exploit
- **This bug enables another**: Does crashing this specific code path leave the
  system in a state that makes another bug reachable?

#### "What happens on different kernel configurations?"

- Without `CONFIG_INIT_ON_FREE_DEFAULT_ON`: freed memory retains old data →
  a NULL deref might become a valid-pointer dereference (UAF)
- Without KASAN: UAF doesn't get caught immediately → attacker has more time
  to spray
- With `CONFIG_USERFAULTFD=y`: race windows can be frozen → narrow races become
  reliable
- With older kernels: NULL page may be mappable (`mmap_min_addr=0`) → NULL deref
  becomes code execution

#### Document your reasoning

In the report, include a section like:

```markdown
### Alternative Exploitation Analysis

Initial assessment: NULL pointer dereference → DoS only

Challenges considered:
1. Could this be a UAF? — No: inet_protos[] is a static global array, not a heap object.
   No allocation/free lifecycle exists.
2. Is the offset controllable? — No: always dereferences NULL + 0x10 regardless of
   attacker-chosen protocol number. All unregistered protocols produce the same NULL.
3. Different timing? — No: this is a single-packet, single-path crash. No race involved.
4. Chain potential? — Low: the crash is in softirq context and is immediately fatal.
   No opportunity for continued execution after the fault.

Conclusion: DoS assessment stands. No viable path to stronger primitive.
```

**If you find a stronger primitive**, update the rating and exploitation path accordingly.
This step often upgrades "DoS" bugs to "Likely Exploitable" or higher.

### 5.4 Exploitability Rating

Rate as one of:
- **Highly Exploitable**: Reliable UAF/OOB-write with good heap spray target, reachable unprivileged
- **Likely Exploitable**: Bug gives useful primitive but exploitation has challenges (narrow race, limited control)
- **Potentially Exploitable**: Bug exists but exploitation path unclear or requires unusual conditions
- **Unlikely Exploitable**: DoS only, confirmed no stronger primitive after challenge analysis
- **Not Exploitable**: Theoretical bug with no practical trigger path

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

The commit message MUST include the decoded backtrace and follow upstream tag conventions.
Look at any KASAN/bug fix in mainline `git log --grep='KASAN'` for real examples.

```
subsystem: brief description of the fix

Longer explanation of what the bug is, how it manifests, and why
this patch fixes it. Use present tense. Include the root cause.

Trigger conditions (required — helps reviewers assess severity):
- Required CONFIG: CONFIG_NET=y, CONFIG_INET=y
- Required sysctl: net.ipv4.ip_no_pmtu_disc=3 (non-default)
- Required privilege: CAP_NET_RAW (raw socket) or root
- Attack vector: remote (crafted ICMP packet)

Introduce the backtrace naturally (upstream convention):

syzbot reported a null-ptr-deref in icmp_unreach [1]:

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

The root cause is that icmp_tag_validation() dereferences
inet_protos[proto] without checking for NULL...

<explanation of the fix>

[1] https://syzkaller.appspot.com/bug?extid=<hash>

Fixes: <12-char-hash> ("original commit title that introduced the bug")
Reported-by: <who reported> <email>
Closes: <bug report URL>
Link: <lore.kernel.org mail thread URL>
Reviewed-by: <reviewer> <email>
Cc: stable@vger.kernel.org
Signed-off-by: <your name> <email>
```

**Commit message tag rules** (order matters):

| Tag | Required? | Purpose |
|---|---|---|
| `Fixes:` | Yes | 12-char hash of the introducing commit |
| `Reported-by:` | Yes | Who found the bug |
| `Closes:` | Yes (if URL exists) | URL of the bug report — **required after `Reported-by:` per upstream convention** |
| `Link:` | Recommended | lore.kernel.org link to the mailing list discussion |
| `Tested-by:` | Recommended | Who tested the patch (can be `syzbot+<hash>@...` if syzbot tested it) |
| `Reviewed-by:` | If reviewed | Code reviewer's signoff |
| `Acked-by:` | If acked | Subsystem maintainer acknowledgment |
| `Cc: stable@vger.kernel.org` | If applicable | Request backport to stable trees |
| `Signed-off-by:` | Yes (last) | Developer Certificate of Origin |

**Trigger conditions in the commit body** (required):

Every commit message should state what's needed to trigger the bug. This helps
reviewers and stable-tree maintainers assess severity and backport priority.

Include:
- **Required CONFIG options**: `CONFIG_*` that must be enabled (e.g., `CONFIG_NETFILTER=y`)
- **Required sysctl / runtime settings**: Non-default settings (e.g., `ip_no_pmtu_disc=3`)
- **Required privilege**: `capable()` vs `ns_capable()`, specific `CAP_*`, or unprivileged
- **Attack vector**: local / remote / requires userns / requires specific hardware
- **Default exposure**: Is this reachable with default kernel config and settings?

Example:
```
The bug requires CONFIG_INET=y (default) and the non-default sysctl
net.ipv4.ip_no_pmtu_disc=3. Triggering requires CAP_NET_RAW for the
raw socket, or the packet can arrive from the network (remote).
```

**Backtrace guidelines**:
- Introduce naturally: `"syzbot reported a <bug-type> in <function> [1]:"` or just paste the
  first crash line, NOT `"Decoded backtrace:"` (not used upstream)
- Use the DECODED trace (file:line), not raw hex addresses
- Trim to key frames: crash point + 5-10 relevant frames
- Remove noise: timestamps, registers, `?` frames, `Code:` lines, module lists
- Indent with single space
- If from syzbot, add footnote `[1]` linking to the syzbot bug page

### 6.2 Validate the Patch

1. **checkpatch.pl**: `./scripts/checkpatch.pl --strict 0001-*.patch`
2. **Compilation**: `make -j$(nproc)` with at least `defconfig` and the relevant config options
3. **Sparse/smatch** (if available): Static analysis for locking errors
4. **Subsystem selftests**: `make -C tools/testing/selftests/<subsystem> run_tests`
5. **No MIME headers**: Verify the generated patch has NO `MIME-Version`, `Content-Type`,
   or `Content-Transfer-Encoding` headers. These appear when the commit message contains
   non-ASCII (UTF-8) characters and will cause rejection on the mailing list.
   ```bash
   # Check — should produce no output:
   grep -E 'MIME-Version|Content-Type|Content-Transfer-Encoding' 0001-*.patch
   # If it does: fix the commit message to use pure ASCII, then re-generate
   ```
6. **Generate submission command**: Run `get_maintainer.pl` and produce the ready-to-use
   `git send-email` command. Include this in the report so the user can copy-paste to submit.

```bash
# Generate patch file
git format-patch -1 --subject-prefix="PATCH net"

# Get maintainers and mailing lists, then build the send command
./scripts/get_maintainer.pl 0001-*.patch

# Auto-generate git send-email with correct recipients
git send-email \
    $(./scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats \
        0001-*.patch | awk '{printf "--cc=\047%s\047 ", $0}') \
    0001-*.patch
```

Read `references/patch-writing-guide.md` § "Find Maintainers and Generate git send-email Command"
for the full workflow including `tocmd`/`cccmd` auto-configuration.

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

## GATE CHECK: Before Entering Phase 7

**DO NOT proceed to Phase 7 (Report Generation) until ALL of the following are confirmed.**
This is a hard gate — not a suggestion. Skipping QEMU verification invalidates the entire
analysis because an untested patch may be wrong, incomplete, or introduce regressions.

```
┌─────────────────────────────────────────────────────────────────────┐
│  VERIFICATION CHECKLIST — all must be YES to proceed to Phase 7    │
│                                                                     │
│  [ ] Vulnerable kernel built and booted in QEMU?                    │
│  [ ] PoC confirmed to crash the vulnerable kernel?                  │
│  [ ] Patched kernel built from latest upstream code?                │
│  [ ] Patched kernel booted in QEMU?                                 │
│  [ ] PoC confirmed to NOT crash the patched kernel?                 │
│  [ ] dmesg checked for new KASAN/UBSAN/WARNING on patched kernel?   │
│  [ ] Source tree restored to original state?                        │
│                                                                     │
│  If ANY item is NO → DO NOT generate the report.                    │
│  Instead: fix the missing step, then re-check.                      │
│                                                                     │
│  If QEMU environment is unavailable (no qemu-system, no rootfs):    │
│  → Ask the user for their test environment path                     │
│  → Or build one using scripts/setup_qemu_env.sh                    │
│  → NEVER skip verification silently                                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Common excuses for skipping verification (all invalid)**:

| Excuse | Why it's wrong |
|---|---|
| "The patch is obviously correct" | Obvious patches have hidden bugs. The ICMP fix looked trivial but could have had a `// BUG` comment left in. |
| "The prove log already showed it crashes" | The prove log tested the VULNERABLE kernel. You need to test the PATCHED kernel. |
| "I'll test later" | The report will be delivered to the user without verification. They'll trust it. |
| "QEMU isn't available" | Ask the user. Build one. Don't skip. |
| "It's just a NULL check" | Even a NULL check can be wrong — wrong variable, wrong scope, wrong return value. |

**If you catch yourself about to write `report.md` without having run QEMU**: STOP.
Go back to Phase 6.3. Build the kernel. Boot it. Run the PoC. Check dmesg.
Only then proceed.

---

## Phase 7: Report Generation & Artifact Packaging

### 7.1 Output Directory Structure

Create a self-contained analysis folder. **Generate two separate reports** — one in English
(`report_en.md`) and one in Chinese (`report_cn.md`). Each report is a complete standalone
document (not a translation stub that references the other). Technical content (code snippets,
diffs, struct layouts, ASCII diagrams, shell commands) should be identical in both; only the
prose (explanations, analysis narrative, table headers) differs by language.

```
<CVE-or-bug-id>-analysis/
├── report_en.md                 # Full analysis report (English)
├── report_cn.md                 # Full analysis report (Chinese / 中文)
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

### 7.2 Report Templates

Two templates are provided:
- `assets/report_template.md` — English template
- `assets/report_template_cn.md` — Chinese (中文) template

Generate **both** `report_en.md` and `report_cn.md` using their respective templates.
Do NOT create a single bilingual report with interleaved EN/CN sections — each report must
be a complete, self-contained document in one language. Both reports must include:

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
| `ftrace` | In-kernel function tracer (no recompile needed) |
| `perf` | Hardware performance counters, timing analysis |
| `objdump` | Disassembly when source-level debugging isn't enough |
| `strace` | Trace PoC syscall sequences |
| `slabinfo` | Runtime slab cache analysis |

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
- `references/syzbot-workflow.md` — Syzbot interaction: reproducers, `#syz test`, `#syz fix`
- `references/regression-testing.md` — Kselftest, KUnit, LTP, multi-config testing
- `assets/report_template.md` — Template for the final analysis report

### Quick Reference Index

| When you encounter... | Read this |
|---|---|
| KASAN crash log | `references/crash-log-analysis.md` § KASAN Reports |
| syzbot report URL | `references/syzbot-workflow.md` § Reading a Syzbot Report |
| UAF / double-free / OOB | `references/vuln-classification.md` |
| "Is this exploitable?" | `references/exploitability-assessment.md` § Assessment Methodology |
| Writing a patch | `references/patch-writing-guide.md` § Common Fix Patterns |
| Setting up QEMU+GDB | `references/qemu-setup.md` § Full QEMU Setup |
| Similar known exploits | `references/kernelctf-knowledge-base.md` § Exploit Technique Catalog |
| Writing regression test | `references/regression-testing.md` § Writing a New Selftest |
| Submitting patch upstream | `references/patch-writing-guide.md` § Submitting Patches Upstream |
| Defensive blocking | `references/exploitability-assessment.md` § Syscalls to Block |
