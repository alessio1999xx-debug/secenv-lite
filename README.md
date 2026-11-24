# secenv-lite: check if your .env files are committed to git or leaking secrets

secenv-lite helps you find `.env` files that are tracked by git or not covered by `.gitignore`, and flags obvious API keys and tokens inside them. It is a read-only check (it never edits, deletes or uploads anything), uses only the Python standard library, and prints a list of fixes you can apply in a minute.

- One file, Python 3.9+. Nothing to `pip install`.
- Default target: the current working directory (pass a repo path as the first argument).
- Masked previews only; exit code `1` when at least one risk is reported.

Need an encrypted vault you can commit, drift checks, or a hook that blocks plaintext keys? That is the full [SecEnv CLI](https://py-forge.com/products/secenv-cli?utm_source=github&utm_medium=readme&utm_campaign=secenv-lite) (one-time payment, yours to keep, no subscription). A table later in this README lists what lite does and what the paid tool adds. Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=secenv-lite) ($99, one payment).

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/secenv-lite/main/secenv_lite.py
chmod +x secenv_lite.py
python secenv_lite.py --help
```

## Find .env files committed to git or missing from .gitignore

```bash
# scan the current repo
python secenv_lite.py

# scan another path
python secenv_lite.py /path/to/repo

# machine-readable report
python secenv_lite.py --json
```

secenv-lite walks the tree for `.env`, `.env.*` and `*.env` files (it skips the `.git` directory). For each one it reports:

| Check | How |
|---|---|
| Tracked by git? | `git ls-files` when git is available |
| Covered by `.gitignore`? | `git check-ignore`, or a simple fallback parser if git is missing |
| Obvious keys inside? | Provider regexes + generic `KEY` / `SECRET` / `TOKEN` / `PASSWORD` assignments |

Template files (`.env.example`, `.env.sample`, `.env.template`) are not flagged as tracked/unignored on their own — but real-looking secrets inside them still are.

Example (tracked `.env`):

```text
1. Kind      : tracked
   Provider  : ENV_TRACKED_BY_GIT
   Path      : /repo/.env
   Details   : .env is tracked by git ...

Suggested fixes:
  1. Add .env (and .env.* if you use variants) to .gitignore ...
  2. Stop tracking the file without deleting it locally: `git rm --cached -- <file>` ...
  3. Caveat: removing the file from the index does NOT remove it from git history.
     If this repo was ever pushed, treat every value in that .env as exposed and
     rotate the keys at each provider.
```

If a `.env` was already pushed, deleting it (or `git rm --cached`) is not enough: the values stay in git history, so rotate every key at the provider.

## Spot obvious API keys and tokens in .env files

This is **not** a full secret scanner. It only matches common, high-confidence shapes and generic assignments. Patterns currently checked:

| Provider / kind | Example shape (not a real key) |
|---|---|
| Anthropic API key | `sk-ant-api03-…` |
| Anthropic legacy key | `sk-ant-…` |
| OpenAI API key | `sk-…` / `sk-proj-…` |
| Google Gemini / Cloud | `AIzaSy…` |
| GitHub PAT / OAuth | `ghp_` / `gho_` / … |
| GitHub fine-grained | `github_pat_…` |
| AWS access key id | `AKIA…` / `ASIA…` |
| AWS secret access key | `aws_secret_access_key=…` |
| Stripe secret / restricted | `sk_live_` / `sk_test_` / `rk_…` |
| Slack token | `xoxb-` / `xoxp-` / … |
| Private key header | `-----BEGIN … PRIVATE KEY-----` |
| Generic assignment | `API_KEY=` / `SECRET=` / `TOKEN=` / `PASSWORD=` (non-empty, non-placeholder) |

Previews look like `abcd...xyz`. Full values are never printed.

Example output, recorded 25 Nov 2026 (Europe/Rome) on a throwaway git repo that committed a `.env` with a fake OpenAI key. Exit code `1`. Paths are from that sample directory.

```text
================================================================================
                        SECENV-LITE SCAN REPORT                                
================================================================================
Target                 : /tmp/demo-sec/my-app
Git available          : True
Git root               : /tmp/demo-sec/my-app
.env-style files found : 1
Findings               : 3
Risks reported         : 3
--------------------------------------------------------------------------------
Findings (3 total):

1. Kind      : tracked
   Provider  : ENV_TRACKED_BY_GIT
   Path      : /tmp/demo-sec/my-app/.env
   Details   : .env is tracked by git (relative: .env). Plain secrets in history stay even after you delete the file.

2. Kind      : secret
   Provider  : OpenAI API Key
   Path      : /tmp/demo-sec/my-app/.env
   Line      : 1
   Preview   : sk-p...bbb
   Details   : OpenAI API Key match (masked preview)

3. Kind      : secret
   Provider  : Generic KEY/SECRET/TOKEN/PASSWORD assignment
   Path      : /tmp/demo-sec/my-app/.env
   Line      : 1
   Key       : OPENAI_API_KEY
   Preview   : sk-p...bbb
   Details   : Generic KEY/SECRET/TOKEN/PASSWORD assignment match (masked preview)

--------------------------------------------------------------------------------
Suggested fixes:
  1. Add .env (and .env.* if you use variants) to .gitignore, then commit the .gitignore change.
  2. Stop tracking the file without deleting it locally: `git rm --cached -- <file>` (repeat for each tracked .env).
  3. Caveat: removing the file from the index does NOT remove it from git history. If this repo was ever pushed, treat every value in that .env as exposed and rotate the keys at each provider.
================================================================================
Read-only scan. No files were modified. This checks common patterns only — it does not claim to find every possible secret.
```

## Run it as a pre-commit hook or in CI

```bash
python secenv_lite.py
echo $?   # 0 = clean; 1 = at least one risk (tracked / unignored / obvious key)
```

Use the exit code in a local pre-commit hook or a CI step so a tracked or unignored `.env` fails the check. The lite tool itself does not install hooks for you.

## secenv-lite vs SecEnv CLI

secenv-lite is a **read-only** check: find risky `.env` files and obvious keys, print a fix list. It never encrypts, decrypts or rewrites anything.

| Capability | Lite (free) | Paid SecEnv CLI |
| --- | --- | --- |
| Find `.env` files tracked by git or missing from `.gitignore` | Yes | Yes (`audit`) |
| Flag obvious API keys and tokens (masked previews) | Yes | Yes (`audit`) |
| Encrypt `.env` files into a vault you can commit | No | Yes (AES-256-CTR + HMAC-SHA256, in the Vault package) |
| Inject secrets only while the app runs | No | Yes (`run`) |
| Compare environments for drift | No | Yes (`drift`) |
| Pre-commit hook that blocks plaintext keys | No (you can call lite yourself) | Yes (`install-hook`) |
| Sync a profile to AWS or GCP secret managers | No | Yes (`sync`; uses the `aws` / `gcloud` CLIs) |
| Output | Plain text or `--json` | CLI commands plus `audit` |

One-time payment, yours to keep. No subscription. Full tool: [SecEnv CLI](https://py-forge.com/products/secenv-cli?utm_source=github&utm_medium=readme&utm_campaign=secenv-lite). Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=secenv-lite) ($99, one payment).

## Need more?

Need the full version? **SecEnv CLI** on PyForge: https://py-forge.com/products/secenv-cli?utm_source=github&utm_medium=readme&utm_campaign=secenv-lite

Or get every PyForge tool, current and future, with the All-Access Pass: https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=secenv-lite

## Tests

```bash
python3 test_secenv_lite.py
```

## More free tools from the same author

- [agentconfig-audit-lite](https://github.com/alessio1999xx-debug/agentconfig-audit-lite) — Audit MCP config for secrets: plaintext tokens and unpinned npx/uvx servers in `.mcp.json` and `CLAUDE.md`.
- [agenttrail-scrub-lite](https://github.com/alessio1999xx-debug/agenttrail-scrub-lite) — Claude Code secret scanner: find API keys and tokens leaked in AI agent transcripts.
- [cronpulse-lite](https://github.com/alessio1999xx-debug/cronpulse-lite) — Cron job monitoring in one Python file: alerts to Slack/Discord/webhook on failure or hang.
- [depcooldown-lite](https://github.com/alessio1999xx-debug/depcooldown-lite) — Dependency cooldown check: fail CI when a pinned PyPI or npm package is newer than N days.
- [homelab-doctor-lite](https://github.com/alessio1999xx-debug/homelab-doctor-lite) — Read-only homelab health check: stale images, exposed ports, expiring certs, silent cron, disk.
- [imagenudge-lite](https://github.com/alessio1999xx-debug/imagenudge-lite) — Docker image update checker: find running containers with a newer image (digest or tag).
- [pthguard-lite](https://github.com/alessio1999xx-debug/pthguard-lite) — Scan Python site-packages for malicious `.pth` files and startup backdoors.
- [pulseping-lite](https://github.com/alessio1999xx-debug/pulseping-lite) — Check SSL certificate expiry and URL/port uptime from cron.

## License

MIT (this lite version). The full SecEnv CLI tool is sold separately under its own license.
