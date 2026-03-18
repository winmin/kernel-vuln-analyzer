# kernel-vuln-analyzer

A Claude Code skill for Linux kernel vulnerability analysis — from crash log triage through root cause analysis, exploitability assessment, patch development, and verified fix delivery.

## What It Does

Given a KASAN crash log, syzbot report, CVE, or kernel panic trace, this skill orchestrates a full 7-phase analysis:

1. **Triage & Planning** — Parse crash logs, identify subsystem, plan analysis with subagents
2. **Source Acquisition & Static Analysis** — Clone kernel tree, parallel code path analysis via subagents
3. **Root Cause Analysis** — Complete data flow tracing with ASCII diagrams, distinguish symptoms from true bug class
4. **Dynamic Analysis** — QEMU + GDB reproduction and confirmation
5. **Exploitability Assessment** — Rating with kernelCTF cross-reference
6. **Patch Development & Verification** — Write fix, verify in QEMU, restore source tree
7. **Report & Artifacts** — Bilingual (EN/ZH) reports with all artifacts

## Installation

Copy the skill directory to your Claude Code skills folder:

```bash
cp -r . ~/.claude/skills/kernel-vuln-analyzer/
```

Or clone directly:

```bash
git clone https://github.com/winmin/kernel-vuln-analyzer.git ~/.claude/skills/kernel-vuln-analyzer/
```

## Usage

In Claude Code, the skill triggers automatically when you:
- Paste a KASAN/UBSAN/kernel panic crash log
- Ask about a kernel CVE
- Request kernel bug analysis or patch development

Or invoke directly:

```
/kernel-vuln-analyzer <paste crash log or describe the bug>
```

## Structure

```
├── SKILL.md                          # Main skill (7-phase workflow)
├── references/
│   ├── crash-log-analysis.md         # KASAN/UBSAN/GPF/NULL deref parsing
│   ├── vuln-classification.md        # Bug taxonomy + decision tree
│   ├── exploitability-assessment.md  # Exploit primitives, heap techniques, mitigations
│   ├── patch-writing-guide.md        # Linux kernel patch conventions
│   ├── qemu-setup.md                # QEMU+GDB environment setup
│   └── kernelctf-knowledge-base.md  # Exploit techniques from Google kernelCTF
├── scripts/
│   ├── parse_kasan_log.py           # Structured crash log parser (JSON output)
│   ├── setup_qemu_env.sh            # Automated QEMU env builder
│   ├── run_patch_test.sh            # Automated patch verification
│   └── generate_report.sh           # Report directory scaffolding
└── assets/
    └── report_template.md            # Analysis report template
```

## Key Features

- **Subagent/hive-mode architecture** — Parallel analysis workstreams for speed
- **Symptom vs. root cause distinction** — e.g., NULL deref that's actually UAF
- **ASCII art diagrams** — Protocol structures, struct layouts, call chains with data transformation
- **Decoded backtrace in commit messages** — Following upstream Linux kernel conventions
- **QEMU verification** — Automated build → boot → PoC → verify cycle
- **Source tree restoration** — Non-destructive analysis, source reverted after testing
- **Bilingual reports** — English and Chinese

## License

MIT
