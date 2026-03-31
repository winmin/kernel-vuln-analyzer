# Regression Testing Guide

Reference: https://docs.kernel.org/dev-tools/kselftest.html

## Table of Contents
1. [Running Existing Selftests](#running-existing-selftests)
2. [Writing a New Selftest for Your Fix](#writing-a-new-selftest-for-your-fix)
3. [Subsystem-Specific Test Suites](#subsystem-specific-test-suites)
4. [KUnit (Kernel Unit Tests)](#kunit)
5. [LTP (Linux Test Project)](#ltp)
6. [Multi-Config Test Matrix](#multi-config-test-matrix)

---

## Running Existing Selftests

Selftests live in `tools/testing/selftests/`. Each subsystem has its own directory.

### Quick Start

```bash
# Build and run all selftests for a subsystem
make headers
make -C tools/testing/selftests TARGETS=net run_tests

# Run specific subsystems
make TARGETS="net timers" kselftest

# Summary mode (cleaner output)
make summary=1 TARGETS=net kselftest

# Skip certain targets
make SKIP_TARGETS="size timers" kselftest
```

### Common Subsystem Selftests

| Subsystem | Target | Example |
|---|---|---|
| Networking | `net` | `make TARGETS=net kselftest` |
| Netfilter | `net/netfilter` | `make TARGETS=net/netfilter kselftest` |
| Memory management | `mm` | `make TARGETS=mm kselftest` |
| BPF | `bpf` | `make TARGETS=bpf kselftest` |
| Filesystems | `filesystems` | `make TARGETS=filesystems kselftest` |
| Seccomp | `seccomp` | `make TARGETS=seccomp kselftest` |
| Timers | `timers` | `make TARGETS=timers kselftest` |
| io_uring | `io_uring` | `make TARGETS=io_uring kselftest` |

### Running in QEMU

Install selftests, pack them into the rootfs:

```bash
# Install to a directory
make -C tools/testing/selftests install INSTALL_PATH=/tmp/kselftest_install

# Pack into rootfs
cp -r /tmp/kselftest_install $ROOTFS_DIR/root/kselftest/

# Inside QEMU:
cd /root/kselftest
./run_kselftest.sh -c net    # run networking tests
./run_kselftest.sh -l        # list available tests
```

---

## Writing a New Selftest for Your Fix

When you fix a kernel bug, consider adding a selftest that validates the fix
and prevents regressions. This is increasingly expected by upstream maintainers.

### Step 1: Choose the Right Directory

Place the test in the appropriate subsystem directory:

```
tools/testing/selftests/
├── net/           ← networking bugs (TCP, UDP, ICMP, routing)
├── net/netfilter/ ← netfilter/nftables bugs
├── mm/            ← memory management bugs
├── bpf/           ← BPF bugs
├── filesystems/   ← filesystem bugs
└── <subsystem>/   ← other subsystems
```

### Step 2: Write the Test (Userspace — C)

Use the kselftest harness for structured test output (TAP format):

```c
// tools/testing/selftests/net/icmp_pmtu_test.c
// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "../kselftest_harness.h"

/*
 * Test: ICMP FRAG_NEEDED with unregistered protocol should not crash
 *
 * Regression test for: icmp: fix NULL ptr deref in icmp_tag_validation()
 * When ip_no_pmtu_disc=3 and an ICMP Frag Needed arrives with an inner
 * IP header containing an unregistered protocol, the kernel should
 * drop the packet gracefully instead of NULL-dereferencing inet_protos[].
 */

FIXTURE(icmp_pmtu) {
    int raw_sock;
};

FIXTURE_SETUP(icmp_pmtu) {
    /* Set hardened PMTU mode */
    system("sysctl -qw net.ipv4.ip_no_pmtu_disc=3");
    system("ip link set lo up");

    self->raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    ASSERT_GE(self->raw_sock, 0);

    int on = 1;
    setsockopt(self->raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
}

FIXTURE_TEARDOWN(icmp_pmtu) {
    close(self->raw_sock);
    system("sysctl -qw net.ipv4.ip_no_pmtu_disc=0");
}

TEST_F(icmp_pmtu, unregistered_protocol_no_crash) {
    /* Build ICMP Frag Needed with inner protocol=253 (unregistered) */
    char packet[56] = {};
    /* ... build packet ... */

    struct sockaddr_in dst = { .sin_family = AF_INET };
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");

    int ret = sendto(self->raw_sock, packet, sizeof(packet), 0,
                     (struct sockaddr *)&dst, sizeof(dst));
    ASSERT_GT(ret, 0);

    /* If we reach here without crashing, the bug is fixed */
    usleep(100000);  /* give kernel time to process */
}

TEST_HARNESS_MAIN
```

### Step 3: Write the Test (Shell Script Alternative)

For simpler tests or tests that need network namespace setup:

```bash
#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test: ICMP FRAG_NEEDED with unregistered inner protocol
# Regression test for NULL deref in icmp_tag_validation()

source lib.sh  # kselftest shell helpers

# Setup
setup_ns NS_TEST
ip -netns $NS_TEST link set lo up
ip netns exec $NS_TEST sysctl -qw net.ipv4.ip_no_pmtu_disc=3

# Run the test PoC
ip netns exec $NS_TEST ./icmp_pmtu_poc
ret=$?

# Check result
if [ $ret -eq 0 ]; then
    echo "ok 1 - ICMP frag_needed with unregistered proto handled gracefully"
else
    echo "not ok 1 - kernel crashed or PoC failed"
fi

# Cleanup
cleanup_ns $NS_TEST

exit $ret
```

### Step 4: Update the Makefile

```makefile
# tools/testing/selftests/net/Makefile (add your test)
TEST_GEN_PROGS += icmp_pmtu_test
# Or for shell scripts:
TEST_PROGS += icmp_pmtu_test.sh
```

### Step 5: Add Kernel Config Requirements

Create/update `tools/testing/selftests/net/config`:

```
CONFIG_NET=y
CONFIG_INET=y
CONFIG_IP_ADVANCED_ROUTER=y
```

### Step 6: Validate

```bash
# Build and run just your test
make -C tools/testing/selftests TARGETS=net run_tests

# Verify all build targets work
make -C tools/testing/selftests TARGETS=net all
make -C tools/testing/selftests TARGETS=net install
make -C tools/testing/selftests TARGETS=net clean
```

### Kselftest Harness API Quick Reference

| Macro | Purpose |
|---|---|
| `TEST(name) { ... }` | Define a standalone test |
| `TEST_F(fixture, name) { ... }` | Define a test with fixture |
| `FIXTURE(name) { ... }` | Define fixture data struct |
| `FIXTURE_SETUP(name) { ... }` | Setup before each test |
| `FIXTURE_TEARDOWN(name) { ... }` | Cleanup after each test |
| `ASSERT_EQ(expected, actual)` | Assert equal (fatal) |
| `ASSERT_NE(a, b)` | Assert not equal (fatal) |
| `ASSERT_GT(a, b)` | Assert greater than (fatal) |
| `ASSERT_GE(a, b)` | Assert greater or equal (fatal) |
| `ASSERT_NULL(ptr)` | Assert NULL (fatal) |
| `ASSERT_TRUE(cond)` | Assert true (fatal) |
| `EXPECT_EQ(expected, actual)` | Expect equal (non-fatal) |
| `TH_LOG(fmt, ...)` | Debug logging |
| `TEST_HARNESS_MAIN` | Main entry point |

---

## Subsystem-Specific Test Suites

Different subsystems have their own test tools beyond kselftest:

### Networking

```bash
# Kselftest networking tests
make TARGETS=net kselftest
make TARGETS=net/netfilter kselftest

# Performance regression with iperf3
iperf3 -s &                    # server
iperf3 -c 127.0.0.1 -t 10     # client — compare before/after patch

# Network namespace isolation tests
# Many net selftests use lib.sh helpers for namespace setup
```

### Filesystems

```bash
# xfstests — the standard filesystem test suite
# https://github.com/kdave/xfstests
./check -g quick               # quick test group
./check generic/001             # specific test
```

### Memory Management

```bash
make TARGETS=mm kselftest
# Also: stress-ng for memory pressure testing
stress-ng --vm 4 --vm-bytes 256M --timeout 60
```

---

## KUnit

KUnit is the kernel's unit testing framework for testing kernel internals in isolation.

```bash
# Run all KUnit tests
./tools/testing/kunit/kunit.py run

# Run tests for a specific module
./tools/testing/kunit/kunit.py run --kunitconfig=net/core/.kunitconfig

# Run in QEMU architecture
./tools/testing/kunit/kunit.py run --arch=x86_64
```

KUnit tests are written as kernel modules — useful for testing internal functions
that aren't reachable from userspace.

---

## LTP (Linux Test Project)

LTP provides 3000+ test cases. Useful for broad regression testing.

```bash
# Install LTP
git clone https://github.com/linux-test-project/ltp.git
cd ltp && make autotools && ./configure && make && make install

# Run networking tests
/opt/ltp/runltp -f net.ipv4

# Run syscall tests
/opt/ltp/runltp -f syscalls

# Run memory tests
/opt/ltp/runltp -f mm
```

---

## Multi-Config Test Matrix

When verifying a patch, test with multiple kernel configurations:

| Config | Purpose | Command |
|---|---|---|
| defconfig | Baseline sanity | `make defconfig && make -j$(nproc)` |
| defconfig + KASAN | Memory safety check | Add `CONFIG_KASAN=y` |
| defconfig + LOCKDEP | Lock ordering check (if patch adds locking) | Add `CONFIG_LOCKDEP=y CONFIG_PROVE_LOCKING=y` |
| defconfig + KCSAN | Data race check (if fixing concurrency bug) | Add `CONFIG_KCSAN=y` |
| Syzbot config | Match the exact crash environment | Download from syzbot dashboard |

For each config: build → boot → run PoC → run selftests → check dmesg.
