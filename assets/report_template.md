# Kernel Vulnerability Analysis Report: {{BUG_ID}}

**Date**: {{DATE}}
**Analyst**: Claude (AI-assisted analysis)
**Status**: {{STATUS}}

---

## 1. Executive Summary

{{One paragraph: what the bug is, where it lives, severity, exploitability rating, and fix status.}}

| Field | Value |
|---|---|
| **Bug ID / CVE** | {{CVE or tracking ID}} |
| **Bug Type** | {{e.g., Use-After-Free, Out-of-Bounds Write}} |
| **Subsystem** | {{e.g., net/netfilter, fs/ext4}} |
| **Affected Versions** | {{e.g., 5.15 - 6.7}} |
| **Exploitability** | {{Highly Exploitable / Likely / Potentially / Unlikely / Not Exploitable}} |
| **CVSS Estimate** | {{if applicable}} |
| **Attack Surface** | {{e.g., Unprivileged local, requires CAP_NET_ADMIN}} |
| **Fix Status** | {{Patch developed and verified / Patch proposed / Under analysis}} |

---

## 2. Crash Log Analysis

### 2.1 Original Crash Report

```
{{Paste the original crash log here, annotated}}
```

### 2.2 Key Signals

- **Bug detector**: {{KASAN / UBSAN / BUG / panic / GPF}}
- **Bug subtype**: {{e.g., slab-use-after-free}}
- **Access**: {{Read/Write}} of size {{N}} at address {{addr}}
- **Faulting function**: {{function+offset}}
- **Slab cache**: {{cache name}} (size {{N}})
- **Task**: {{task name}} (PID {{pid}})
- **Kernel version**: {{version}}

### 2.3 Call Trace Analysis

```
{{Annotated call trace with comments on key frames}}
```

**Subsystem identification**: {{How the subsystem was determined from the call trace}}

---

## 2.5 Subsystem Background

{{Explain how the affected subsystem works NORMALLY before describing the bug.
This section helps readers who aren't familiar with the subsystem understand the context.}}

- **Architecture**: {{Key data structures, their relationships, lifecycle}}
- **Normal call path**: {{What the code is supposed to do in the non-buggy case}}
- **Why this area is bug-prone**: {{e.g., complex state machine, performance-critical path
  with minimal validation, historical pattern of similar bugs}}

---

## 3. Root Cause Analysis

### 3.1 Vulnerable Code Path

{{Describe the code path that leads to the bug. Reference specific source files and line numbers.}}

```c
// {{file}}:{{line}}
{{Relevant code snippet with annotations}}
```

### 3.2 Bug Mechanism

{{Detailed chronological description of how the bug manifests:}}

1. **Step 1**: {{Thread/context A does X...}}
2. **Step 2**: {{Thread/context B does Y...}}
3. **Step 3**: {{The invariant violation occurs because...}}
4. **Step 4**: {{The crash happens when...}}

### 3.3 True Bug Classification

| Symptom | Root Cause |
|---|---|
| {{What the crash log shows}} | {{What the actual bug is}} |

{{Explain why the symptom differs from the root cause, if applicable.
e.g., "The crash presents as a NULL pointer dereference at offset 0x40, but this is
actually a UAF — the object was freed and the memory zeroed by INIT_ON_FREE, causing
the pointer field at offset 0x40 to read as NULL."}}

### 3.4 Introducing Commit

```
{{hash}} ("{{commit title}}")
```

{{How this commit introduced the bug.}}

---

## 4. Dynamic Analysis

### 4.1 Reproduction

- **QEMU configuration**: {{CPU, memory, kernel config highlights}}
- **PoC**: {{Brief description of the PoC and how it triggers the bug}}
- **Reproduction rate**: {{e.g., 100% with 2 CPUs, ~30% with 1 CPU}}

### 4.2 GDB Session Highlights

{{Key findings from GDB debugging:}}

```gdb
{{Key GDB commands and output that confirm the root cause}}
```

### 4.3 Object Lifecycle

{{If UAF: describe the allocation → use → free → use-after-free lifecycle with timestamps/breakpoints}}

---

## 5. Exploitability Assessment

### 5.1 Rating: {{RATING}}

### 5.2 Permission Gate Analysis (`capable` vs `ns_capable`)

Trace every capability check from syscall entry to the vulnerable code:

```
{{Syscall entry / packet reception}}
         │
         ▼
{{Framework layer}} ({{file.c:line}})
│  {{check function}}({{capability}})  ← {{namespace-aware / init_user_ns only}}
│  {{userns root CAN / CANNOT pass}}
│  failure → {{-EPERM / drop}}
         │
         ▼
{{Subsystem callback}} ({{file.c:line}})
│  {{check function}}({{capability}})  ← {{namespace-aware / init_user_ns only}}
│  failure → {{-EPERM / drop}}
         │
         ▼
{{Vulnerable code path}}
```

**Effective privilege requirement**: {{The most restrictive check in the chain}}
- {{e.g., "Real root required — callback uses capable() at line X"}}
- {{OR "Unprivileged via userns — all checks use ns_capable()"}}

**Note**: {{Any comments about potential future changes that could expand attack surface}}

### 5.3 Primitive Analysis

- **What the bug provides**: {{e.g., UAF on a 256-byte slab object}}
- **Controllability**: {{How much control does the attacker have?}}
- **Timing**: {{Is the race window wide enough?}}

### 5.3 Exploitation Path

{{If exploitable, describe the theoretical exploitation path:}}

1. {{Step 1: e.g., Trigger UAF by...}}
2. {{Step 2: e.g., Reclaim with msg_msg spray in kmalloc-256...}}
3. {{Step 3: e.g., Leak kernel pointer via...}}
4. {{Step 4: e.g., Overwrite function pointer to achieve code execution...}}

### 5.4 Mitigations

| Mitigation | Applicable? | Bypassable? |
|---|---|---|
| KASLR | {{Yes/No}} | {{Yes — via info leak / No}} |
| SMEP | {{Yes/No}} | {{Yes — via ROP / No}} |
| SMAP | {{Yes/No}} | {{Yes/No}} |
| CFI | {{Yes/No}} | {{Yes/No}} |
| Slab hardening | {{Yes/No}} | {{Yes/No}} |

### 5.5 Precedent

{{Similar vulnerabilities from kernelCTF or public exploits:}}
- {{CVE-XXXX-XXXX}}: Similar {{bug type}} in {{subsystem}}, exploited via {{technique}}

---

## 6. Patch

### 6.1 Fix Description

{{What the patch does and why it correctly fixes the root cause.}}

### 6.2 Patch Diff

```diff
{{The actual patch diff}}
```

### 6.3 Commit Message

The commit message MUST include the decoded backtrace (from `scripts/decode_stacktrace.sh`).

```
{{subsystem: brief description}}

{{Root cause explanation.}}

{{Why this patch fixes it.}}

Decoded backtrace:

 {{BUG: KASAN: ... in function_name (file.c:line)}}
 {{Call Trace:}}
  {{<IRQ>}}
  {{crash_function (file.c:line)}}
  {{caller_function (file.c:line)}}
  {{...trimmed to key frames...}}
  {{</IRQ>}}

Fixes: {{hash}} ("{{commit title}}")
Reported-by: {{name}} <{{email}}>
Cc: stable@vger.kernel.org
Signed-off-by: {{name}} <{{email}}>
```

### 6.4 Validation

- [ ] `checkpatch.pl --strict` passes
- [ ] Compiles with defconfig
- [ ] Compiles with relevant debug configs (KASAN, etc.)
- [ ] Boot test passes
- [ ] PoC no longer crashes
- [ ] No new KASAN/UBSAN warnings
- [ ] Subsystem selftests pass (if applicable)
- [ ] No regression in basic functionality

---

## 7. Verification Results

### 7.1 Vulnerable Kernel Test

```
{{dmesg output showing the crash when running PoC on vulnerable kernel}}
```

### 7.2 Patched Kernel Test

```
{{dmesg output showing clean run when running PoC on patched kernel}}
```

### 7.3 Stress Test

{{Results of running the PoC in a loop on the patched kernel}}

---

## 8. Artifacts

| Artifact | Path | Description |
|---|---|---|
| PoC source | `poc/poc.c` | Proof of concept |
| PoC binary | `poc/poc_binary` | Compiled PoC |
| Patch | `patch/0001-*.patch` | git format-patch |
| Vulnerable kernel | `kernel/test-bzImage` | Bootable vulnerable kernel |
| Vulnerable vmlinux | `kernel/test-vmlinux` | Debug symbols |
| Patched kernel | `kernel/patched-bzImage` | Bootable patched kernel |
| Patched vmlinux | `kernel/patched-vmlinux` | Debug symbols |
| Kernel config | `kernel/.config` | Build configuration |
| Root filesystem | `env/rootfs.cpio.gz` | QEMU rootfs |
| Boot script (vuln) | `env/run-vulnerable.sh` | Boot vulnerable kernel |
| Boot script (patch) | `env/run-patched.sh` | Boot patched kernel |
| Boot script (debug) | `env/run-debug.sh` | Boot with GDB |
| Crash log | `logs/crash.log` | Original crash |
| Verification log | `logs/patch-verification.log` | Patch test output |

---

## 9. References

- {{Link to original bug report / syzbot / mailing list}}
- {{Link to relevant kernel source}}
- {{Related CVEs}}
- {{kernelCTF references for similar bugs}}
- {{Relevant kernel documentation}}

---

## 10. Environment & Reproducibility

Record exact environment for reproducibility:

| Item | Value |
|---|---|
| Kernel source | `{{git repo URL}}` @ `{{commit hash}}` |
| Kernel version | `{{make kernelversion output}}` |
| Compiler | `{{gcc --version / clang --version}}` |
| QEMU | `{{qemu-system-x86_64 --version}}` |
| Busybox | `{{busybox --help | head -1}}` |
| Host OS | `{{uname -a}}` |

---

## 11. Timeline

| Date | Event |
|---|---|
| {{date}} | Bug reported / crash observed |
| {{date}} | Root cause identified |
| {{date}} | Patch developed |
| {{date}} | Patch verified |
| {{date}} | {{Submitted upstream / etc.}} |
