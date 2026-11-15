# Contributing to PHP2Shell Scanner

Thank you for helping improve PHP2Shell Scanner! This is a community security-research tool — contributions that improve detection accuracy, add test coverage, or fix bugs are welcome.

---

## Ground Rules

1. **Authorized use only.** All development and testing must be done against systems you own or have explicit written permission to test (localhost, Podman/Docker containers, lab environments).

2. **Passive-only principle.** This tool never sends exploit payloads. PRs that add active exploitation, file upload, shell execution, or any destructive capability will be rejected.

3. **No personal data in commits.** Do not commit `targets.txt` or any file containing real scan targets, client URLs, or personal information. Use `targets.example.txt` as a template.

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR-ORG/php2shell-scanner.git
cd php2shell-scanner

# 2. Create a virtual environment
python3 -m venv venv && source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
pip install pytest

# 4. Run the test suite (should all pass)
pytest tests/ -v
```

---

## Test Lab (Podman / Docker)

```bash
# PHP 8.3.35 — should return CRITICAL
podman run -d --name php8335 -p 8083:80 php:8.3.35-apache
podman exec php8335 bash -c 'echo "<?php phpinfo(); ?>" > /var/www/html/phpinfo.php'
python3 php2shell.py -u http://localhost:8083 --check-phpinfo -v

# PHP 8.3.36 — should return NOT_VULNERABLE
podman run -d --name php8336 -p 8084:80 php:8.3.36-apache
podman exec php8336 bash -c 'echo "<?php phpinfo(); ?>" > /var/www/html/phpinfo.php'
python3 php2shell.py -u http://localhost:8084 --check-phpinfo -v
```

---

## What to Contribute

| Type | Welcome? | Notes |
|------|----------|-------|
| Bug fixes | ✅ | Include a regression test |
| New PHP version coverage | ✅ | Update `config/vulnerability_db.json` and `tests/` |
| New detector method | ✅ | Follow `detectors/` interface: return `{"found": bool, ...}` |
| Improved HTML report | ✅ | Must be self-contained (no CDN dependencies) |
| Active exploit / payload | ❌ | Out of scope — passive-only tool |

---

## Pull Request Checklist

- [ ] `pytest tests/ -v` passes with no failures
- [ ] No personal information, real client URLs, or local paths in code or tests
- [ ] `targets.txt` is **not** included (it is in `.gitignore`)
- [ ] New detection logic has at least one new test in `tests/`
- [ ] Updated `config/vulnerability_db.json` if PHP version data changed
- [ ] PR description explains **what** changed and **why**

---

## Code Style

- Python 3.10+, type annotations throughout
- `packaging.version.Version` for all version comparisons — never string comparison
- Detectors return a plain `dict`; confidence merging happens in `core/confidence.py`
- Keep HTTP client usage in `core/http_client.py` — no raw `requests.get()` elsewhere
