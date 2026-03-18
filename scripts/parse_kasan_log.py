#!/usr/bin/env python3
"""
Parse KASAN/kernel crash logs and extract structured information.

Usage:
    python parse_kasan_log.py <crash_log_file>
    cat crash.log | python parse_kasan_log.py

Output: JSON with extracted bug information.
"""

import sys
import re
import json
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class CrashInfo:
    bug_type: str = ""
    bug_subtype: str = ""  # e.g., slab-use-after-free, slab-out-of-bounds
    access_type: str = ""  # Read or Write
    access_size: int = 0
    faulting_address: str = ""
    faulting_function: str = ""
    faulting_offset: str = ""
    faulting_module: str = ""
    slab_cache: str = ""
    object_size: int = 0
    task_name: str = ""
    task_pid: int = 0
    kernel_version: str = ""
    cpu: int = -1
    call_trace: list = None
    alloc_trace: list = None
    free_trace: list = None
    subsystem_guess: str = ""
    raw_title: str = ""

    def __post_init__(self):
        if self.call_trace is None:
            self.call_trace = []
        if self.alloc_trace is None:
            self.alloc_trace = []
        if self.free_trace is None:
            self.free_trace = []


def parse_crash_log(text: str) -> CrashInfo:
    info = CrashInfo()
    lines = text.strip().split('\n')

    # Extract KASAN bug type
    kasan_match = re.search(
        r'BUG: KASAN: (\S+) in (\S+?)(\+0x[\da-f]+/0x[\da-f]+)?(\s+\[(\S+)\])?',
        text
    )
    if kasan_match:
        info.bug_type = "KASAN"
        info.bug_subtype = kasan_match.group(1)
        info.faulting_function = kasan_match.group(2)
        if kasan_match.group(3):
            info.faulting_offset = kasan_match.group(3)
        if kasan_match.group(5):
            info.faulting_module = kasan_match.group(5)
        info.raw_title = f"KASAN: {info.bug_subtype} in {info.faulting_function}"

    # Extract NULL pointer dereference
    null_match = re.search(
        r'BUG: kernel NULL pointer dereference.*?address:\s*(0x[\da-f]+|[\da-f]+)',
        text
    )
    if null_match:
        info.bug_type = "NULL_PTR_DEREF"
        info.faulting_address = null_match.group(1)
        info.raw_title = f"NULL pointer dereference at {info.faulting_address}"

    # Extract GPF
    gpf_match = re.search(
        r'general protection fault.*?(?:address\s+|for non-canonical address\s+)(0x[\da-f]+|[\da-f]+)',
        text
    )
    if gpf_match:
        info.bug_type = "GPF"
        info.faulting_address = gpf_match.group(1)
        addr = info.faulting_address.replace('0x', '')
        if '6b6b6b6b' in addr:
            info.bug_subtype = "likely-uaf-slub-poison"
        elif 'dead' in addr[:4]:
            info.bug_subtype = "likely-uaf-kasan-freed"
        info.raw_title = f"GPF at {info.faulting_address}"

    # Extract kernel BUG
    bug_match = re.search(r'kernel BUG at (\S+):(\d+)', text)
    if bug_match:
        info.bug_type = "BUG"
        info.faulting_function = f"{bug_match.group(1)}:{bug_match.group(2)}"
        info.raw_title = f"kernel BUG at {info.faulting_function}"

    # Extract UBSAN
    ubsan_match = re.search(r'UBSAN: (\S+) in (\S+):(\d+):(\d+)', text)
    if ubsan_match:
        info.bug_type = "UBSAN"
        info.bug_subtype = ubsan_match.group(1)
        info.faulting_function = f"{ubsan_match.group(2)}:{ubsan_match.group(3)}"
        info.raw_title = f"UBSAN: {info.bug_subtype} in {info.faulting_function}"

    # Extract WARNING
    warn_match = re.search(r'WARNING:.*?at (\S+):(\d+)\s+(\S+)', text)
    if warn_match:
        if not info.bug_type:
            info.bug_type = "WARNING"
            info.faulting_function = f"{warn_match.group(1)}:{warn_match.group(2)} {warn_match.group(3)}"
            info.raw_title = f"WARNING at {info.faulting_function}"

    # Extract access type and size
    access_match = re.search(r'(Read|Write) of size (\d+) at addr ([\da-fx]+)', text)
    if access_match:
        info.access_type = access_match.group(1)
        info.access_size = int(access_match.group(2))
        info.faulting_address = access_match.group(3)

    # Extract task info
    task_match = re.search(r'CPU:\s*(\d+)\s+PID:\s*(\d+)\s+Comm:\s*(\S+)', text)
    if task_match:
        info.cpu = int(task_match.group(1))
        info.task_pid = int(task_match.group(2))
        info.task_name = task_match.group(3)

    # Extract kernel version
    ver_match = re.search(r'Not tainted\s+(\S+)', text)
    if not ver_match:
        ver_match = re.search(r'Tainted:.*?(\d+\.\d+\.\d+\S*)', text)
    if ver_match:
        info.kernel_version = ver_match.group(1)

    # Extract slab cache info
    cache_match = re.search(r'belongs to the cache (\S+) of size (\d+)', text)
    if cache_match:
        info.slab_cache = cache_match.group(1)
        info.object_size = int(cache_match.group(2))

    # Extract call traces
    info.call_trace = extract_trace(text, r'Call Trace:', r'(?:Allocated by task|Freed by task|Code:|---\[)')
    info.alloc_trace = extract_trace(text, r'Allocated by task', r'(?:Freed by task|The buggy address)')
    info.free_trace = extract_trace(text, r'Freed by task', r'(?:The buggy address|Last potentially)')

    # Guess subsystem from call trace
    info.subsystem_guess = guess_subsystem(info.call_trace)

    return info


def extract_trace(text: str, start_pattern: str, end_pattern: str) -> list:
    """Extract a stack trace section."""
    trace = []
    match = re.search(start_pattern, text)
    if not match:
        return trace

    start_idx = match.end()
    end_match = re.search(end_pattern, text[start_idx:])
    end_idx = start_idx + end_match.start() if end_match else len(text)

    section = text[start_idx:end_idx]
    for line in section.split('\n'):
        # Match reliable frames (no ? prefix)
        frame_match = re.match(r'\s+(\S+)\+0x[\da-f]+/0x[\da-f]+', line.strip())
        if frame_match:
            func = frame_match.group(1)
            # Skip unreliable frames
            if not line.strip().startswith('?'):
                trace.append(func)
    return trace


def guess_subsystem(call_trace: list) -> str:
    """Guess the kernel subsystem from the call trace."""
    subsystem_hints = {
        'net': ['tcp_', 'udp_', 'ip_', 'sock_', 'sk_', 'net_', 'nf_', 'nft_',
                'packet_', 'inet_', 'netlink_', 'xfrm_', '__sys_sendmsg', '__sys_recvmsg',
                'sctp_', 'dccp_', 'raw_', 'icmp_'],
        'fs': ['vfs_', 'ext4_', 'btrfs_', 'xfs_', 'f2fs_', 'nfs_', 'fuse_',
               'do_sys_open', 'inode_', 'dentry_', 'file_', 'path_', 'ovl_'],
        'mm': ['do_page_fault', 'handle_mm_fault', 'mmap_', 'munmap', 'brk',
               'page_', 'slab_', 'kmalloc', 'vmalloc', 'swap_', 'oom_'],
        'io_uring': ['io_uring_', 'io_submit_', 'io_ring_', '__io_'],
        'bpf': ['bpf_', '__bpf_', 'btf_', 'map_'],
        'drivers/usb': ['usb_', 'hub_', 'hcd_'],
        'drivers/gpu': ['drm_', 'amdgpu_', 'i915_', 'nouveau_'],
        'sound': ['snd_', 'hda_', 'pcm_', 'alsa_'],
        'block': ['blk_', 'bio_', 'submit_bio', 'nvme_', 'scsi_'],
        'ipc': ['do_msg', 'msg_', 'sem_', 'shm_'],
        'security': ['selinux_', 'apparmor_', 'smack_', 'security_'],
        'scheduler': ['schedule', '__schedule', 'wake_up', 'try_to_wake_up'],
        'tty': ['tty_', 'pty_', 'n_tty_'],
    }

    trace_str = ' '.join(call_trace).lower()
    scores = {}
    for subsys, keywords in subsystem_hints.items():
        score = sum(1 for kw in keywords if kw.lower() in trace_str)
        if score > 0:
            scores[subsys] = score

    if scores:
        return max(scores, key=scores.get)
    return "unknown"


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    info = parse_crash_log(text)
    result = asdict(info)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
