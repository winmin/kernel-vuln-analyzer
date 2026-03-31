# kernelCTF Knowledge Base

This reference consolidates exploit techniques, vulnerability patterns, and lessons learned
from Google's kernelCTF program and publicly documented kernel exploits. Use this as a
cross-reference when assessing exploitability of new vulnerabilities.

## Table of Contents
1. [Exploit Technique Catalog](#exploit-technique-catalog)
2. [Vulnerability Patterns by Subsystem](#vulnerability-patterns-by-subsystem)
3. [Common Exploit Chains](#common-exploit-chains)
4. [Object Spray Catalog](#object-spray-catalog)
5. [Mitigation Bypass Techniques](#mitigation-bypass-techniques)
6. [How to Build This Knowledge Base](#how-to-build-this-knowledge-base)

---

## Exploit Technique Catalog

### Heap Spray Techniques

| Technique | Object | Size Range | Controllability | Cleanup |
|---|---|---|---|---|
| msg_msg spray | `struct msg_msg` | 48 - ~8K | Full content control | `msgrcv()` to free |
| pipe_buffer spray | `struct pipe_buffer` | 1024 (x86_64) | Ops pointer target | `close(pipe_fd)` |
| sk_buff spray | `struct sk_buff` | Variable | Data content control | Socket close |
| setxattr spray | temp buffer | Arbitrary | Full content, brief lifetime | Auto-freed |
| add_key spray | key payload | Arbitrary | Full content control | `keyctl(KEYCTL_REVOKE)` |
| sendmsg spray | ancillary data | Variable | Full content control | After sendmsg returns |
| tty_struct spray | `struct tty_struct` | ~1024 | Limited (ops pointer) | Close PTY fd |
| seq_operations spray | `struct seq_operations` | 32 | Function pointers | Close /proc fd |
| subprocess_info | `struct subprocess_info` | ~128 | work.func pointer | Auto-freed |

### Privilege Escalation Primitives

| Primitive | Mechanism | Requirements |
|---|---|---|
| cred overwrite | Direct modification of `current->cred->uid` etc. | Arbitrary write to known address |
| modprobe_path overwrite | Change `/sbin/modprobe` to attacker script | Arbitrary write to `modprobe_path` symbol |
| core_pattern overwrite | Change core dump handler | Arbitrary write to `core_pattern` symbol |
| setuid binary trick | Write to process memory during execve | Timing-sensitive, mostly mitigated |
| namespace escape | Abuse user/net namespaces | Depends on namespace setup |
| commit_creds(prepare_kernel_cred(NULL)) | Classic ROP payload | Code execution in kernel |

### Information Leak Techniques

| Technique | What it Leaks | How |
|---|---|---|
| msg_msg OOB read | Adjacent slab data | Craft msg_msg with wrong size field → msgrcv reads OOB |
| seq_operations read | Kernel text pointers | Spray seq_ops, read via /proc, check for function pointers |
| Uninitialized stack read | Previous stack frame data | Trigger code path with uninitialized local, read it back |
| /proc/kallsyms (root) | All kernel symbols | Direct read (disabled for unprivileged) |
| dmesg pointer leak | Various kernel addresses | `printk` with `%p` instead of `%pK` |
| Timing side channel | KASLR base | Cache timing on kernel addresses |

---

## Vulnerability Patterns by Subsystem

### Networking (net/)

The most common source of kernel exploits. Key areas:

**Socket operations (net/socket.c, net/core/)**:
- Reference counting bugs in socket lifecycle
- Race between close() and concurrent operations
- Netfilter/nftables: complex rule evaluation, frequent UAF targets

**Netfilter/nftables (net/netfilter/)**:
- Extremely frequent target — complex state machines, many objects
- Common: UAF in rule/set/chain objects during concurrent modification
- nf_tables transaction handling races
- Example patterns: concurrent table flush + rule evaluation

**TCP/UDP (net/ipv4/, net/ipv6/)**:
- sk_buff handling bugs
- Race conditions in connection setup/teardown
- Timer-related UAF (retransmission timers, keepalive)

**Packet sockets (net/packet/)**:
- `AF_PACKET` — historically rich exploit target
- Ring buffer management bugs
- TOCTOU in packet fanout

### Filesystem (fs/)

**VFS layer (fs/)**:
- Inode reference counting across mount points
- Race between unlink and open
- Dentry cache inconsistencies

**Specific filesystems**:
- OverlayFS: layer interaction bugs
- FUSE: userspace-kernel interaction races
- Ext4/Btrfs/XFS: complex on-disk format parsing (fuzzing targets)

### Memory Management (mm/)

- Page fault handler races
- mmap/munmap race conditions
- Copy-on-write (COW) bugs (Dirty COW lineage)
- Userfaultfd interaction with other MM operations

### io_uring (io_uring/)

- Complex async I/O subsystem, relatively new code
- Reference counting bugs in request lifecycle
- Interaction between io_uring and file/socket operations
- Fixed buffer registration bugs

### BPF (kernel/bpf/)

- Verifier bypass → arbitrary kernel R/W
- Map operations race conditions
- JIT compilation bugs

### Drivers

- USB gadget/host drivers: untrusted input from devices
- GPU drivers (DRM): complex buffer management
- TTY subsystem: race conditions in terminal handling

---

## Common Exploit Chains

### Chain 1: UAF → msg_msg Spray → Arbitrary Read → KASLR Bypass → ROP

1. Trigger UAF to free object in kmalloc-N cache
2. Spray `msg_msg` to reclaim the freed slot
3. Use the dangling pointer to read the `msg_msg` (or adjacent data) → leak kernel pointer
4. Calculate kernel base from leaked pointer (KASLR bypass)
5. Free the msg_msg, spray with pipe_buffer or other function-pointer-bearing object
6. Trigger function pointer call through dangling pointer → ROP chain
7. ROP: `commit_creds(prepare_kernel_cred(NULL))` → return to userspace as root

### Chain 2: OOB Write → Adjacent Object Corruption → Privilege Escalation

1. Trigger out-of-bounds write
2. Corrupt adjacent object's function pointer or security field
3. If function pointer: hijack control flow
4. If cred-like data: directly modify permissions

### Chain 3: Double-Free → Overlapping Objects → Type Confusion

1. Trigger double-free on object A
2. Allocate object B in the same slot
3. Second free of A effectively frees B's memory
4. Allocate object C in B's (freed) memory
5. B and C now overlap → writes to C appear in B and vice versa
6. If B has function pointers and C has user-controlled data → code execution

### Chain 4: Race Condition → UAF → (proceed as Chain 1)

1. Win the race to free an object while it's still in use
2. Object is now use-after-free
3. Continue with UAF exploitation techniques

### Chain 5: Info Leak Only → KASLR Bypass → Combined with Separate Write Primitive

Sometimes you need two bugs:
1. Bug A: info leak → bypass KASLR
2. Bug B: write primitive → overwrite `modprobe_path` or build ROP chain

---

## Object Spray Catalog

### kmalloc-32
- `struct seq_operations` (4 function pointers) — via `open("/proc/self/stat")`
- `struct shm_file_data` — via `shmget` + `shmat`

### kmalloc-64
- Small `msg_msg` — via `msgsnd` with small payload

### kmalloc-96 / kmalloc-128
- `struct subprocess_info` — via triggering `call_usermodehelper`
- Various inode-related structures

### kmalloc-192 / kmalloc-256
- `struct msg_msg` (with appropriate payload size)
- `struct timerfd_ctx` — via `timerfd_create`

### kmalloc-512
- `struct msg_msg` (with ~464 byte payload)
- Various netlink-related structures

### kmalloc-1024 (kmalloc-1k)
- `struct pipe_buffer` (array of 16 pipe_buf per pipe) — via `pipe()`
- `struct tty_struct` — via opening `/dev/ptmx`
- `struct msg_msg` (with ~976 byte payload)

### kmalloc-2048 and above
- Large `msg_msg` objects
- `struct sk_buff` data area (controllable via socket options)
- BPF map values (if BPF accessible)

---

## Mitigation Bypass Techniques

### KASLR Bypass Methods

1. **Direct info leak**: Read kernel pointer from accessible interface
2. **Side-channel**: Cache timing to determine if address is mapped
3. **Partial overwrite**: Only overwrite lower bytes of a pointer (upper bytes stay correct due to KASLR granularity)
4. **Heap pointer leak**: Leak slab pointer → infer kernel base from fixed offset

### SMEP/SMAP Bypass

- **ROP/JOP**: Chain gadgets within kernel text
- **Stack pivot**: Move stack to controlled kernel memory, then ROP
- Historically `ret2usr` was possible without SMEP — now need kernel-space gadgets

### CFI Bypass

- **Data-only attack**: Don't hijack function pointers — corrupt data to change control flow indirectly
- **Valid target abuse**: Find a legitimate CFI-valid function that does something useful when called with wrong arguments
- **modprobe_path overwrite**: No code pointer hijack needed — just corrupt a string

---

## How to Build This Knowledge Base

This is a living document. To keep it current:

### Adding New Entries

When analyzing a new vulnerability, if the exploit uses a novel technique or confirms
an existing pattern in a new context, add it here:

1. **New exploit technique**: Add to the technique catalog with object, size, controllability
2. **New subsystem pattern**: Add to the subsystem section with specific functions/files
3. **New exploit chain**: Document the full chain if it differs from existing patterns
4. **New mitigation bypass**: Document the technique and what it bypasses

### Sourcing Information

Primary sources for kernel exploit knowledge:
- **kernelCTF submissions**: `https://github.com/google/security-research/tree/master/kernelctf`
- **Project Zero blog**: Public kernel exploit writeups
- **syzbot dashboard**: `https://syzkaller.appspot.com/upstream`
- **oss-security mailing list**: Public vulnerability disclosures
- **Kernel commit log**: Fixes often describe the vulnerability in the commit message
- **Academic papers**: USENIX Security, CCS, S&P papers on kernel exploitation

### Searching for Precedent

When assessing a new bug, search for precedent:
1. Same subsystem + same bug class → very likely similar exploit applies
2. Same slab cache + UAF → similar spray technique likely works
3. Same mitigation environment → check if bypass technique exists
4. Search by CVE if known: `https://www.cvedetails.com/`, NVD
