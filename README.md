# kernel-vuln-analyzer

A Claude Code plugin for Linux kernel vulnerability analysis — from crash log triage through root cause analysis, exploitability assessment, patch development, and verified fix delivery.

## What It Does

Given a KASAN crash log, syzbot report, CVE, or kernel panic trace, this skill orchestrates a full 7-phase analysis:

1. **Triage & Planning** — Parse crash logs, identify subsystem and correct maintainer tree
2. **Source Acquisition** — Fetch latest code, two-stage workflow (analyze on crash version, patch on latest)
3. **Root Cause Analysis** — Complete data flow tracing with ASCII diagrams, distinguish symptoms from true bug class
4. **Dynamic Analysis** — QEMU + GDB reproduction, race condition handling
5. **Exploitability Assessment** — `capable()` vs `ns_capable()` gate analysis, RCU lifetime UAF detection, challenge initial assessment
6. **Patch Development & Verification** — Write fix, verify in QEMU, generate `git send-email` command, restore source tree
7. **Report & Artifacts** — Bilingual (EN/ZH) reports with all artifacts

## Installation

### Method 1: Plugin marketplace install (recommended)

```bash
# Step 1: Add the marketplace
/plugin marketplace add winmin/kernel-vuln-analyzer

# Step 2: Install the plugin
/plugin install kernel-vuln-analyzer@kernel-vuln-analyzer
```

Or via CLI:
```bash
claude plugin install kernel-vuln-analyzer@kernel-vuln-analyzer
```

### Method 2: Manual skill copy

```bash
git clone https://github.com/winmin/kernel-vuln-analyzer.git
cp -r kernel-vuln-analyzer/skills/kernel-vuln-analyzer ~/.claude/skills/
```

## Usage

The skill triggers automatically when you:
- Paste a KASAN/UBSAN/kernel panic crash log
- Ask about a kernel CVE
- Request kernel bug analysis or patch development

Or invoke directly:

```
/kernel-vuln-analyzer <paste crash log or describe the bug>
```

## Plugin Structure

```
kernel-vuln-analyzer/
├── .claude-plugin/
│   ├── plugin.json                       # Plugin manifest
│   └── marketplace.json                  # Marketplace metadata
├── skills/
│   └── kernel-vuln-analyzer/
│       ├── SKILL.md                      # Main skill (7-phase workflow)
│       ├── references/
│       │   ├── crash-log-analysis.md     # KASAN/UBSAN/GPF/NULL deref parsing
│       │   ├── vuln-classification.md    # Bug taxonomy + decision tree
│       │   ├── exploitability-assessment.md  # Exploit primitives, mitigations, capable vs ns_capable
│       │   ├── patch-writing-guide.md    # Kernel patch conventions, git send-email, MIME rules
│       │   ├── qemu-setup.md            # QEMU+GDB environment setup
│       │   ├── regression-testing.md    # Kselftest, KUnit, LTP
│       │   ├── syzbot-workflow.md       # Syzbot interaction (#syz test, #syz fix)
│       │   └── kernelctf-knowledge-base.md  # Exploit techniques from Google kernelCTF
│       ├── scripts/
│       │   ├── parse_kasan_log.py       # Structured crash log parser (JSON output)
│       │   ├── setup_qemu_env.sh        # Automated QEMU env builder
│       │   ├── run_patch_test.sh        # Automated patch verification
│       │   └── generate_report.sh       # Report directory scaffolding
│       └── assets/
│           ├── report_template.md        # Analysis report template (EN)
│           └── report_template_cn.md     # Analysis report template (ZH)
├── README.md
└── LICENSE
```

## Key Features

- **Subagent/hive-mode architecture** — Parallel analysis workstreams for speed
- **Symptom vs. root cause distinction** — e.g., NULL deref masking RCU lifetime UAF
- **Permission gate analysis** — `capable()` vs `ns_capable()` to determine true attack surface
- **Challenge initial assessment** — Mandatory step to probe for stronger exploitation primitives
- **ASCII art diagrams** — Protocol structures, struct layouts, call chains with data transformation
- **Precise subsystem mapping** — `net/bluetooth/` → `bluetooth.git`, not `net.git`
- **Two-stage workflow** — Analyze on crash version, patch against latest mainline
- **Decoded backtrace in commit messages** — With `Closes:`, `Link:` tags per upstream conventions
- **No MIME headers** — Pure ASCII patches ready for kernel mailing list
- **Auto-generated `git send-email`** — From `get_maintainer.pl` with correct `--subject-prefix`
- **QEMU verification** — Automated build → boot → PoC → verify cycle
- **Syzbot integration** — `#syz test`, `#syz fix`, reproducer extraction
- **Regression testing** — Kselftest writing guide, KUnit, LTP
- **Source tree restoration** — Non-destructive analysis, source reverted after testing
- **Bilingual reports** — English and Chinese

## License

MIT
