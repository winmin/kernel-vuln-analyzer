# Linux Kernel Patch Writing Guide

## Table of Contents
1. [Patch Principles](#patch-principles)
2. [Common Fix Patterns](#common-fix-patterns)
3. [Commit Message Format](#commit-message-format)
4. [Coding Style Checklist](#coding-style-checklist)
5. [Testing Requirements](#testing-requirements)
6. [Common Mistakes to Avoid](#common-mistakes-to-avoid)

---

## Patch Principles

### Fix the Root Cause

The most important rule: **fix the root cause, not the symptom**.

Bad: Adding a NULL check where the pointer "shouldn't" be NULL
→ This hides the real bug (why is it NULL? probably a UAF or missing init)

Good: Fix the lifetime management, locking, or initialization that causes
the invalid state in the first place.

### Minimal Diff

Change only what's necessary to fix the bug:
- Don't refactor surrounding code
- Don't fix style issues in untouched lines
- Don't add unrelated improvements
- Each patch should do exactly one thing

### Consider All Callers

Before changing a function's behavior:
1. `git grep` for all call sites
2. Check if your change breaks any caller's assumptions
3. If the function is exported (EXPORT_SYMBOL), out-of-tree modules may use it

### Match Existing Style

Every file in the kernel has its own micro-conventions:
- Some use `goto err_*` labels, some use `goto out`
- Some initialize variables at declaration, some don't
- Match what's already there, even if you prefer differently

---

## Common Fix Patterns

### UAF Fix: Add Proper Locking

```c
/* Before (buggy): */
void release_handler(struct my_obj *obj)
{
    kfree(obj);
}

void use_handler(struct my_obj *obj)
{
    // No lock! obj might be freed between check and use
    if (obj->state == ACTIVE)
        do_something(obj->data);
}

/* After (fixed): */
void release_handler(struct my_obj *obj)
{
    spin_lock(&obj->lock);
    obj->state = DEAD;
    spin_unlock(&obj->lock);
    kfree(obj);
}

void use_handler(struct my_obj *obj)
{
    spin_lock(&obj->lock);
    if (obj->state == ACTIVE)
        do_something(obj->data);
    spin_unlock(&obj->lock);
}
```

### UAF Fix: Add Reference Counting

```c
/* Before (buggy): */
void work_fn(struct work_struct *work)
{
    struct my_obj *obj = container_of(work, struct my_obj, work);
    // obj might be freed before work runs
    process(obj);
}

/* After (fixed): */
void work_fn(struct work_struct *work)
{
    struct my_obj *obj = container_of(work, struct my_obj, work);
    process(obj);
    my_obj_put(obj);  // Release the reference taken when scheduling work
}

void schedule_work_for(struct my_obj *obj)
{
    my_obj_get(obj);  // Take reference before scheduling
    schedule_work(&obj->work);
}
```

### UAF Fix: RCU Protection

```c
/* Before (buggy): */
struct my_obj *lookup(int id)
{
    return idr_find(&my_idr, id);  // No protection, obj can be freed
}

/* After (fixed): */
struct my_obj *lookup(int id)
{
    struct my_obj *obj;
    rcu_read_lock();
    obj = idr_find(&my_idr, id);
    if (obj && !refcount_inc_not_zero(&obj->refcnt))
        obj = NULL;
    rcu_read_unlock();
    return obj;
}

void release(struct my_obj *obj)
{
    idr_remove(&my_idr, obj->id);
    call_rcu(&obj->rcu_head, my_obj_free_rcu);  // Defer free
}
```

### OOB Fix: Bounds Check

```c
/* Before (buggy): */
int handle_cmd(struct cmd *cmd)
{
    return handlers[cmd->type](cmd);  // No bounds check
}

/* After (fixed): */
int handle_cmd(struct cmd *cmd)
{
    if (cmd->type >= ARRAY_SIZE(handlers))
        return -EINVAL;
    return handlers[cmd->type](cmd);
}
```

### Integer Overflow Fix

```c
/* Before (buggy): */
buf = kmalloc(count * size, GFP_KERNEL);

/* After (fixed): use overflow-safe helpers */
buf = kmalloc_array(count, size, GFP_KERNEL);
// or:
if (check_mul_overflow(count, size, &total))
    return -EOVERFLOW;
buf = kmalloc(total, GFP_KERNEL);
```

### Missing Initialization Fix

```c
/* Before (buggy): */
struct result res;
res.status = compute_status();
// res.padding bytes not initialized
copy_to_user(user_buf, &res, sizeof(res));

/* After (fixed): */
struct result res = {};  // Zero-initialize everything
res.status = compute_status();
copy_to_user(user_buf, &res, sizeof(res));
```

### Error Path Resource Leak Fix

```c
/* Before (buggy): */
int init_thing(void)
{
    a = alloc_a();
    if (!a) return -ENOMEM;
    b = alloc_b();
    if (!b) return -ENOMEM;  // LEAK: a not freed!
    return 0;
}

/* After (fixed): */
int init_thing(void)
{
    a = alloc_a();
    if (!a) return -ENOMEM;
    b = alloc_b();
    if (!b) {
        free_a(a);
        return -ENOMEM;
    }
    return 0;
}
// Or use the goto-based cleanup pattern (preferred in kernel):
int init_thing(void)
{
    a = alloc_a();
    if (!a)
        return -ENOMEM;
    b = alloc_b();
    if (!b)
        goto err_free_a;
    return 0;

err_free_a:
    free_a(a);
    return -ENOMEM;
}
```

---

## Commit Message Format

The commit message MUST include the decoded backtrace. This is standard upstream
practice — check any KASAN/bug fix in the kernel git log (e.g., `git log --grep='KASAN'`).
The decoded trace makes the bug searchable by function, file, and line number.

```
subsystem: brief imperative description

Detailed explanation of the bug and the fix. Explain:
- What the bug is (root cause, not just symptom)
- How it manifests (crash type, conditions to trigger)
- Why this patch fixes it correctly

Keep lines under 75 characters. Use present tense for the description
of the bug and the fix ("This causes..." not "This caused...").

The decoded backtrace goes here, indented with one space:

 BUG: KASAN: slab-use-after-free in some_function (path/to/file.c:123)
 Read of size 8 at addr ffff888012345678 by task exploit/1234
 Call Trace:
  <IRQ>
  some_function (path/to/file.c:123)
  caller_function (path/to/other.c:456)
  entry_point (path/to/entry.c:789)
  </IRQ>

Fixes: abc123def456 ("the commit that introduced the bug")
Reported-by: Name <email>
Tested-by: Name <email>
Cc: stable@vger.kernel.org   # If it should be backported
Signed-off-by: Your Name <your@email.com>
```

### Producing the Decoded Backtrace

```bash
# Decode the full crash log
./scripts/decode_stacktrace.sh vmlinux < crash.log > decoded_crash.log

# Or decode individual addresses
addr2line -e vmlinux -fip 0xffffffff81234567
```

### Trimming the Backtrace for the Commit Message

Include in the commit message:
- The bug title line (`BUG: KASAN: ...` or `Oops: ...`)
- Access type and address (`Read/Write of size N at addr ...`)
- The key call trace frames (crash point + 5-10 relevant frames)
- Context markers (`<IRQ>`, `</IRQ>`, `<TASK>`)

Remove from the commit message:
- Timestamps (`[ 23.456789]`)
- Register dumps (`RAX: ... RBX: ...`)
- `?` unreliable frames
- Module lists (`Modules linked in:`)
- Raw hex `Code:` lines
- Duplicate/noise frames (scheduling, generic entry)

### Rules

- **Subject line**: `subsystem: imperative description` — max 72 chars
  - Use the subsystem prefix from recent commits to the same file
  - `git log --oneline <file>` to see the convention
- **Body**: Wrapped at 75 characters
- **Backtrace**: Decoded (file:line), trimmed, indented with one space
- **Fixes tag**: 12-character abbreviated commit hash + original subject
  - Find with: `git log --oneline --all -- <file>`
  - Or `git bisect` for the introducing commit
- **Reported-by**: Who found the bug (name + email)
- **Closes**: URL of the bug report — **required after Reported-by per upstream convention**
  - syzbot: `Closes: https://syzkaller.appspot.com/bug?extid=<hash>`
  - Bugzilla: `Closes: https://bugzilla.kernel.org/show_bug.cgi?id=<id>`
- **Link**: lore.kernel.org URL to the mailing list discussion thread
- **Tested-by**: Who tested the patch (can be `syzbot+<hash>@syzkaller.appspotmail.com`)
- **Reviewed-by / Acked-by**: Code reviewer / subsystem maintainer signoff
- **Cc: stable**: Include if the bug affects stable/LTS kernels
- **Signed-off-by**: Required, always last (Developer Certificate of Origin)

**Tag ordering** (per `Documentation/process/submitting-patches.rst`):
```
Fixes: → Reported-by: → Closes: → Link: → Tested-by: →
Reviewed-by: → Acked-by: → Cc: → Signed-off-by:
```

---

## Coding Style Checklist

Run `scripts/checkpatch.pl --strict your.patch` and fix all errors.
Common issues:

- [ ] Tabs for indentation (not spaces)
- [ ] Opening brace on same line as statement (except functions)
- [ ] No space after function name: `func(arg)` not `func (arg)`
- [ ] Space after keywords: `if (`, `for (`, `while (`
- [ ] No trailing whitespace
- [ ] Line length: prefer under 80, hard limit ~100
- [ ] Use kernel types: `u32` not `uint32_t` (in kernel code)
- [ ] Use kernel helpers: `ARRAY_SIZE()`, `min()`, `max()`, `container_of()`
- [ ] Error handling: return negative errno values
- [ ] Comments: `/* C style */` not `// C++ style` (older kernel convention,
      though `//` is increasingly accepted)

---

## Testing Requirements

### Minimum Testing

1. **Compile test**: `make -j$(nproc)` with the relevant config
2. **checkpatch**: `./scripts/checkpatch.pl --strict 0001-*.patch`
3. **Boot test**: Boot the patched kernel (QEMU is fine)
4. **PoC test**: Run the PoC — it must not crash the patched kernel

### Recommended Additional Testing

5. **Selftests**: `make -C tools/testing/selftests/<subsystem> run_tests`
6. **Stress test**: Run the PoC in a loop (100+ iterations) to check for races
7. **KASAN build**: Build with KASAN enabled and run the PoC — no KASAN warnings
8. **Multiple configs**: Test with defconfig and any configs enabling the affected feature
9. **lockdep**: Build with `CONFIG_LOCKDEP=y` and check for warnings (if patch adds locking)
10. **Sparse**: `make C=1` to check for annotation issues

### For Network Subsystem Patches

- `make -C tools/testing/selftests/net run_tests`
- Run iperf/netperf for basic throughput regression
- Test with network namespaces if applicable

### For Filesystem Patches

- `xfstests` with the affected filesystem
- Test with different mount options

---

## Common Mistakes to Avoid

### Don't Just Add a NULL Check

```c
// BAD: This hides the real bug
if (!ptr)
    return -EINVAL;  // Why is ptr NULL? Fix THAT.
```

Unless the NULL is a legitimate condition (e.g., optional feature not configured),
a NULL check is a band-aid. Find and fix the root cause.

### Don't Introduce Deadlocks

If adding locking to fix a race:
- Check the existing lock ordering (read `Documentation/locking/`)
- Use `lockdep` annotations if needed
- Don't hold a lock across sleeping operations (use mutex instead of spinlock if needed)
- Check for lock nesting: A→B in one path, B→A in another = deadlock

### Don't Break ABI

- Changing struct sizes in UAPI headers breaks user-space programs
- Changing ioctl semantics breaks user-space programs
- If you must change behavior, maintain backwards compatibility

### Don't Forget Error Paths

When adding cleanup code, make sure ALL error paths clean up correctly.
The `goto err_*` pattern makes this easier to audit:

```c
int init(void)
{
    ret = step_a();
    if (ret)
        return ret;
    ret = step_b();
    if (ret)
        goto err_a;
    ret = step_c();
    if (ret)
        goto err_b;
    return 0;

err_b:
    undo_b();
err_a:
    undo_a();
    return ret;
}
```

### Don't Copy Security Fixes Incorrectly

If referencing a fix for a similar bug:
- Understand WHY the other fix works
- Don't blindly apply the same pattern — your bug may have different constraints
- Verify the fix is complete for YOUR code path

---

## Submitting Patches Upstream

### Find Maintainers and Generate `git send-email` Command

Use `get_maintainer.pl` to automatically determine who should receive the patch
and which mailing lists to CC. Then generate a ready-to-run `git send-email` command.

**Step 1: Run `get_maintainer.pl` on the patch**

```bash
./scripts/get_maintainer.pl 0001-your-patch.patch
```

Example output:
```
David S. Miller <davem@davemloft.net> (maintainer:NETWORKING CORE)
Eric Dumazet <edumazet@google.com> (reviewer:NETWORKING CORE)
Jakub Kicinski <kuba@kernel.org> (maintainer:NETWORKING CORE)
Paolo Abeni <pabeni@redhat.com> (maintainer:NETWORKING CORE)
netdev@vger.kernel.org (open list:NETWORKING CORE)
linux-kernel@vger.kernel.org (open list)
```

**Step 2: Auto-generate the `git send-email` command**

`get_maintainer.pl` can directly produce `--to` and `--cc` flags:

```bash
# Generate --to/--cc flags from get_maintainer.pl output
./scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats \
    0001-your-patch.patch \
    | sed 's/^/--cc=/' \
    | tr '\n' ' '
```

Or more precisely, use the built-in `--separator` option and pipe to `git send-email`:

```bash
# One-liner: generate patch + send with correct recipients
git send-email \
    $(./scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats \
        --separator=',' 0001-your-patch.patch \
        | awk -F, '{for(i=1;i<=NF;i++) print "--cc=\""$i"\""}') \
    --to='netdev@vger.kernel.org' \
    0001-your-patch.patch
```

**Step 3: The recommended approach — let `git send-email` invoke it automatically**

The cleanest method is to configure `git send-email` to call `get_maintainer.pl` itself:

```bash
# In the kernel source tree, set this config:
git config sendemail.tocmd 'scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats --nol'
git config sendemail.cccmd 'scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats --nom'

# Now git send-email automatically populates To: and Cc: from the patch content
git send-email 0001-your-patch.patch
# It will show you the recipients and ask for confirmation before sending
```

Explanation of flags:
- `--nogit` / `--nogit-fallback`: don't use git blame (faster, avoids noise)
- `--norolestats`: don't show role annotations in email addresses
- `--nol`: exclude mailing lists (for `tocmd` — puts maintainers in To:)
- `--nom`: exclude maintainers (for `cccmd` — puts lists in Cc:)

**Step 4: Full example with a real patch**

```bash
# 1. Generate the patch
git format-patch -1 --subject-prefix="PATCH net"
# → 0001-icmp-fix-null-deref-in-icmp_tag_validation.patch

# 2. Check who gets it
./scripts/get_maintainer.pl 0001-icmp-fix-null-deref-in-icmp_tag_validation.patch
# David S. Miller <davem@davemloft.net> (maintainer:NETWORKING CORE)
# Eric Dumazet <edumazet@google.com> (reviewer:NETWORKING CORE)
# Jakub Kicinski <kuba@kernel.org> (maintainer:NETWORKING CORE)
# Paolo Abeni <pabeni@redhat.com> (maintainer:NETWORKING CORE)
# netdev@vger.kernel.org (open list:NETWORKING CORE)
# linux-kernel@vger.kernel.org (open list)

# 3. Send (with tocmd/cccmd configured, or manually)
git send-email \
    --to='davem@davemloft.net' \
    --to='edumazet@google.com' \
    --to='kuba@kernel.org' \
    --to='pabeni@redhat.com' \
    --cc='netdev@vger.kernel.org' \
    --cc='linux-kernel@vger.kernel.org' \
    0001-icmp-fix-null-deref-in-icmp_tag_validation.patch

# 4. Save the command and recipients in the report
```

**Step 5: Record in the report**

Include the `get_maintainer.pl` output and the exact `git send-email` command
in the report's patch section, so the user can copy-paste to submit.

### `git send-email` Setup (One-Time)

```bash
# SMTP configuration
git config --global sendemail.smtpserver smtp.gmail.com
git config --global sendemail.smtpserverport 587
git config --global sendemail.smtpencryption tls
git config --global sendemail.smtpuser your@gmail.com

# Auto-recipient configuration (run in kernel source tree)
git config sendemail.tocmd 'scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats --nol'
git config sendemail.cccmd 'scripts/get_maintainer.pl --nogit --nogit-fallback --norolestats --nom'
```

### Choosing the Right Subject Prefix Tag

The `[PATCH <tag>]` prefix tells maintainers **which tree** to apply your patch to.
Getting this wrong means your patch goes to the wrong tree and gets ignored.

```bash
git format-patch -1 --subject-prefix="PATCH <tag>"
```

**How to determine the tag**:

| Your patch is... | Tag | Tree |
|---|---|---|
| **Networking bug fix** (for current release) | `PATCH net` | `netdev/net.git` |
| **Networking new feature** (for next release) | `PATCH net-next` | `netdev/net-next.git` |
| **BPF bug fix** | `PATCH bpf` | `bpf/bpf.git` |
| **BPF new feature** | `PATCH bpf-next` | `bpf/bpf-next.git` |
| **Wireless fix** | `PATCH wifi` | `wireless/wifi.git` |
| **Bluetooth fix** | `PATCH bluetooth` | `bluetooth/bluetooth.git` |
| **General kernel fix** (no subsystem tree) | `PATCH` | `torvalds/linux.git` |
| **Stable backport request** | `PATCH stable` | stable tree |
| **Any subsystem with its own tree** | `PATCH <subsystem>` | check MAINTAINERS |

**Decision rule**: Bug fixes go to the **base tree** (`net`, `bpf`), new features go
to the **-next tree** (`net-next`, `bpf-next`). When in doubt, check where recent
commits to the same file went:

```bash
# Look at recent patches to this file on lore.kernel.org
# or check the git log of the subsystem tree
git log --oneline net/ipv4/icmp.c | head -10
# If they say "net:" or were merged via net.git → use "PATCH net"
```

**For non-networking subsystems**, check `MAINTAINERS` for the tree URL:

```bash
./scripts/get_maintainer.pl --scm 0001-your-patch.patch
# Look for the "SCM" line — it shows the git tree
# e.g., "git git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git"
#        → tag is "net"
```

**Version tags combine**: `[PATCH net v2]`, `[PATCH bpf-next v3 1/2]`

```bash
# Version 2 of a networking fix:
git format-patch -1 --subject-prefix="PATCH net v2"

# A 2-patch series for bpf-next, version 3:
git format-patch -2 --subject-prefix="PATCH bpf-next v3"
```

**Important**:
- Never include `security@kernel.org` if the issue is already public
- For version 2+: `git format-patch -v2` and explain changes below `---`
- Do NOT use Gmail web interface — it mangles whitespace and encoding
- Prefer `mutt` or `thunderbird` (with plain-text mode) for reading replies

### After Submission

- Monitor the mailing list for reviewer feedback (lore.kernel.org)
- Respond to review comments; issue new versions (`-v2`, `-v3`) as needed
- Document changes between versions in the patch changelog (below `---`)
- If syzbot reported the bug, reply with `#syz fix: <commit subject>` after merge

### Regression Test Submission

Consider including a kselftest alongside your fix patch. See `references/regression-testing.md`
for how to write and validate selftests. Submit the test as a separate patch in the same series:

```bash
git format-patch -2 --subject-prefix="PATCH net"
# Generates:
# 0001-icmp-fix-null-deref-in-icmp_tag_validation.patch
# 0002-selftests-net-add-icmp-pmtu-unregistered-proto-test.patch
```
