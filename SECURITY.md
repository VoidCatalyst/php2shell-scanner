# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

PHP2Shell Scanner is a **security tool** — we take reports about its own security seriously.

### What to report

- Bugs that could allow PHP2Shell Scanner to be used for **unintended destructive actions**  
  (e.g. if a code path could send exploit payloads despite the tool's passive-only design)
- Dependency vulnerabilities in `requirements.txt` packages
- Logic flaws in severity classification that would produce false negatives on CRITICAL targets
- Any issue that could cause the scanner to disclose data it collected to unintended parties

### How to report

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Open a [GitHub Security Advisory](../../security/advisories/new)
(private disclosure channel built into GitHub).

Include:
- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- Affected versions
- Suggested remediation (if any)

We will acknowledge within **48 hours** and aim to release a fix within **14 days** of confirmation.

---

## Responsible Use Reminder

This tool is designed for **authorized security assessments only**.

Scanning systems you do not own or do not have explicit written permission to test may violate:
- The Computer Fraud and Abuse Act (CFAA) — United States
- The Computer Misuse Act — United Kingdom
- The Information Technology Act, 2000 — India
- Equivalent laws in your jurisdiction

The maintainers are not responsible for misuse of this tool.
