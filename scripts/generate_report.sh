#!/bin/bash
# generate_report.sh - Generate the analysis report directory structure
#
# Usage:
#   ./generate_report.sh <bug_id> <output_dir>
#
# Creates the standard report directory structure.
# The markdown report itself should be written by the analyzer.

set -euo pipefail

BUG_ID="${1:?Usage: $0 <bug_id> <output_dir>}"
OUTPUT_DIR="${2:?Usage: $0 <bug_id> <output_dir>}"

REPORT_DIR="$OUTPUT_DIR/${BUG_ID}-analysis"

echo "[*] Creating report directory structure: $REPORT_DIR"

mkdir -p "$REPORT_DIR"/{poc,patch,kernel,env,logs}

# Create placeholder files with instructions
cat > "$REPORT_DIR/README.txt" << EOF
Kernel Vulnerability Analysis Report
Bug ID: $BUG_ID
Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

Directory Structure:
  report.md          - Full analysis report
  poc/               - Proof of concept
    poc.c            - PoC source code
    Makefile         - Build instructions
  patch/             - The fix
    0001-*.patch     - git format-patch output
  kernel/            - Kernel binaries
    test-bzImage     - Vulnerable kernel (bootable)
    test-vmlinux     - Vulnerable kernel (GDB symbols)
    patched-bzImage  - Patched kernel (bootable)
    patched-vmlinux  - Patched kernel (GDB symbols)
    .config          - Kernel configuration
  env/               - QEMU environment
    rootfs.cpio.gz   - Root filesystem
    run-vulnerable.sh - Boot vulnerable kernel
    run-patched.sh   - Boot patched kernel
    run-debug.sh     - Boot with GDB stub
  logs/              - Analysis logs
    crash.log        - Original crash log
    gdb-session.log  - GDB debugging session
    patch-verification.log - Patch test results
EOF

echo "[+] Report directory created: $REPORT_DIR"
echo ""
echo "    Next steps:"
echo "    1. Copy kernel artifacts to kernel/"
echo "    2. Copy PoC to poc/"
echo "    3. Copy patch to patch/"
echo "    4. Copy QEMU files to env/"
echo "    5. Write the analysis report as report.md"
