# Kernel Vulnerability Classification

## Table of Contents
1. [Memory Safety Bugs](#memory-safety-bugs)
2. [Concurrency Bugs](#concurrency-bugs)
3. [Logic Bugs](#logic-bugs)
4. [Integer Bugs](#integer-bugs)
5. [Information Leaks](#information-leaks)
6. [Type Confusion](#type-confusion)
7. [Classification Decision Tree](#classification-decision-tree)

---

## Memory Safety Bugs

### Use-After-Free (UAF)

**Pattern**: Object is freed while still referenced. Subsequent access through stale pointer.

**Common causes in kernel**:
- Missing RCU grace period between free and access
- Reference count underflow (extra `put` without matching `get`)
- Race between a close/release path and a concurrent user
- Error path frees an object but caller still has pointer
- Timer/workqueue callback fires after object freed

**Key indicators**:
- KASAN: `slab-use-after-free`
- GPF with `0x6b6b6b6b` address (SLUB poison)
- NULL deref at struct member offset (freed + zeroed memory)
- Crash in a callback function (the callback's object was freed)

**Exploitation potential**: HIGH. UAF is the most exploitable kernel bug class.
Attacker frees the object, reallocates the memory with controlled data (heap spray),
then the kernel uses attacker-controlled data as a struct with function pointers.

### Double-Free

**Pattern**: Same memory freed twice.

**Common causes**:
- Two error paths both free the same resource
- Missing flag to track whether free already happened
- Reference counting bug leading to two free calls

**Key indicators**:
- KASAN: `double-free` or `invalid-free`
- SLUB: "Object already free" messages

**Exploitation potential**: HIGH. Similar to UAF — first free makes allocator
return the same memory for a new allocation, second free corrupts allocator metadata
or frees the replaced object.

### Out-of-Bounds (OOB) Read/Write

**Pattern**: Access beyond allocated buffer boundaries.

**Common causes**:
- Off-by-one in loop bounds or size calculation
- Integer overflow in allocation size → undersized buffer
- Missing bounds check on user-supplied index/offset
- Variable-length struct with wrong size calculation
- `copy_from_user`/`copy_to_user` with wrong length

**Key indicators**:
- KASAN: `slab-out-of-bounds` or `global-out-of-bounds`
- The offset from the object start exceeds the allocation size
- Crash in `memcpy` or similar copy functions

**Exploitation potential**: OOB write is HIGH (corrupt adjacent object).
OOB read is MEDIUM (info leak, KASLR bypass).

### Stack Buffer Overflow

**Pattern**: Writing past a stack-allocated buffer.

**Rare in modern kernels due to:**
- Stack protector (`CONFIG_STACKPROTECTOR`)
- FORTIFY_SOURCE compile-time checks
- Most buffer operations use heap, not stack

**Exploitation potential**: MEDIUM-HIGH if achievable. Stack contains return addresses.

### Heap Overflow

**Pattern**: Writing past a heap-allocated buffer into adjacent objects.

**This is a specific case of OOB-write** where the overflow crosses object boundaries
in the slab allocator.

**Exploitation potential**: HIGH if the adjacent object contains function pointers
or security-critical data. Cross-cache attacks can make this reliable.

---

## Concurrency Bugs

### Data Race

**Pattern**: Two threads access shared data without proper synchronization,
with at least one write.

**Common causes**:
- Missing lock acquisition
- Wrong lock used (lock A protects field X, but field Y accessed without lock)
- Lock-free code with incorrect memory ordering
- TOCTOU (time-of-check-to-time-of-use)

**Key indicators**:
- KCSAN (Kernel Concurrency Sanitizer) reports
- Bug only reproduces under stress (multiple CPUs, high load)
- Corrupted data structures that look "partially updated"
- Non-deterministic crashes

**Exploitation potential**: Variable. Data races can lead to UAF, OOB, or state corruption
depending on what's being raced.

### Race Condition (TOCTOU)

**Pattern**: Check a condition, then act on it — but the condition changes between check and action.

**Classic kernel TOCTOU examples**:
- Check if user pointer is valid → user remaps the page → kernel accesses now-different data
- Check if object exists → concurrent thread frees it → access freed object
- Check permission → concurrent setuid → bypass check

**Exploitation potential**: HIGH when it leads to UAF or permission bypass.

### Deadlock / Lock Inversion

**Pattern**: Two or more threads each hold a lock the other needs.

**Not directly exploitable** but can cause DoS. However, a "fix" that introduces
a deadlock is worse than the original bug.

---

## Logic Bugs

### Missing Permission Check

**Pattern**: Privileged operation accessible without proper authorization.

**Exploitation potential**: HIGH for privilege escalation.

### Incorrect State Machine Transition

**Pattern**: Object reaches a state that should be impossible, leading to
invariant violations.

**Common causes**:
- Missing state check before transition
- Concurrent state changes without synchronization
- Error path leaves object in partially-initialized state

### Missing Error Handling

**Pattern**: Error return value ignored, leading to use of invalid data.

```c
ptr = kmalloc(size, GFP_KERNEL);
// Missing: if (!ptr) return -ENOMEM;
ptr->field = value;  // NULL deref if allocation failed
```

But also more subtle: a function returns an error, the caller ignores it and
continues with stale/invalid data.

---

## Integer Bugs

### Integer Overflow/Underflow

**Pattern**: Arithmetic exceeds the range of the integer type.

```c
// Classic: user controls both `count` and `size`
size_t total = count * size;  // overflow if count * size > SIZE_MAX
buf = kmalloc(total, GFP_KERNEL);  // undersized allocation
copy_from_user(buf, user_buf, count * size);  // heap overflow
```

**Exploitation potential**: HIGH when it leads to undersized allocation → heap overflow.

### Signedness Error

**Pattern**: Signed/unsigned confusion.

```c
int len = user_value;  // user provides negative value
if (len > MAX_SIZE) return -EINVAL;  // check passes (negative < MAX_SIZE)
memcpy(dst, src, len);  // len cast to size_t → huge copy → overflow
```

---

## Information Leaks

### Uninitialized Memory Disclosure

**Pattern**: Kernel stack or heap memory copied to user space without full initialization.

```c
struct result res;
res.field1 = compute();
// res.field2 never set — contains old stack/heap data
copy_to_user(user_buf, &res, sizeof(res));  // leaks kernel memory
```

**Including padding bytes**: Struct padding between fields may contain old data.

**Exploitation potential**: MEDIUM. Useful for KASLR bypass or leaking sensitive data
(crypto keys, pointers). Often a prerequisite for a full exploit chain.

### Kernel Pointer Leak

**Pattern**: Kernel address exposed to user space via `/proc`, sysfs, logs, or copy_to_user.

**Exploitation potential**: MEDIUM. Direct KASLR bypass.

---

## Type Confusion

**Pattern**: An object of type A is treated as type B.

**Common causes in kernel**:
- Incorrect container_of() usage
- Wrong cast in void* callback data
- Union field accessed as wrong member
- Netlink/ioctl with wrong attribute type parsing

**Exploitation potential**: HIGH if the confused types have different layouts,
especially if one has function pointers where the other has user-controlled data.

---

## Classification Decision Tree

Use this to systematically classify a bug:

```
Start: What does the bug detector report?
│
├── KASAN report
│   ├── slab-use-after-free → UAF
│   │   └── Check: is there a race? → Concurrency + UAF
│   ├── slab-out-of-bounds → OOB
│   │   └── Check: is size from user input? → Integer bug + OOB
│   ├── double-free → Double-Free
│   └── global-out-of-bounds → Stack/Global OOB
│
├── NULL pointer dereference
│   ├── Offset = 0 → Missing NULL check or init failure
│   ├── Small offset → Struct field via NULL pointer
│   │   ├── Check: should pointer be non-NULL here? → Possible UAF (freed + zeroed)
│   │   └── Check: is the NULL from an explicit `ptr = NULL` assignment?
│   │       └── YES → RCU LIFETIME BUG: read the teardown path
│   │           ├── Is there a put/free BEFORE the `= NULL`?
│   │           │   └── YES → **UAF window exists between free and NULL assignment**
│   │           │       The NULL deref PoC is hitting the SAFE window (after NULL).
│   │           │       The DANGEROUS window (after free, before NULL) gives UAF.
│   │           │       → UPGRADE to UAF. Check what object is freed, what cache,
│   │           │         what the reader dereferences (func ptrs? data?)
│   │           └── NO (NULL is the initial state) → genuine missing-init bug
│   └── Check: is KASAN enabled? If no → could be masked UAF
│
├── General Protection Fault
│   ├── Address = 0x6b6b6b6b... → UAF (SLUB poison)
│   ├── Address = 0xdead... → UAF (KASAN freed marker)
│   └── Non-canonical address → Corrupted pointer (UAF, OOB-write, or type confusion)
│
├── UBSAN report
│   ├── shift-out-of-bounds → Integer bug
│   ├── signed-integer-overflow → Integer bug
│   └── array-index-out-of-bounds → OOB (possibly integer-driven)
│
├── WARNING / BUG
│   ├── refcount_t underflow → Reference count bug → likely UAF
│   ├── list_add corruption → List corruption → likely UAF or double-add
│   └── Explicit BUG_ON → Logic error → investigate the invariant
│
└── KCSAN report → Data Race → investigate what it leads to
```
