# secenv-lite: check if your .env files are committed to git or leaking secrets

secenv-lite helps you find `.env` files that are tracked by git or not covered by `.gitignore`, and flags obvious API keys and tokens inside them. It is a read-only check (it never edits, deletes or uploads anything), uses only the Python standard library, and prints a list of fixes you can apply in a minute.

- One file, Python 3.9+. Nothing to `pip install`.
- Default target: the current working directory (pass a repo path as the first argument).
- Masked previews only; exit code `1` when at least one risk is reported.

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/secenv-lite/main/secenv_lite.py
chmod +x secenv_lite.py
python secenv_lite.py --help
```

(Until the repo is public, copy `secenv_lite.py` from this tree instead of curling.)

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

## Run it as a pre-commit hook or in CI

```bash
python secenv_lite.py
echo $?   # 0 = clean; 1 = at least one risk (tracked / unignored / obvious key)
```

Use the exit code in a local pre-commit hook or a CI step so a tracked or unignored `.env` fails the check. The lite tool itself does not install hooks for you.

## secenv-lite vs SecEnv CLI

secenv-lite is a **read-only** check: find risky `.env` files and obvious keys, print a fix list. It never encrypts, decrypts or rewrites anything.

The full **[SecEnv CLI](https://py-forge.com/products/secenv-cli?utm_source=github&utm_medium=lite_repo&utm_content=secenv-lite)** helps with:

- encrypting `.env` files into a vault you can commit (AES-256-CTR + HMAC-SHA256)
- injecting secrets only while your app runs — no plaintext left on disk (`run`)
- comparing environments for drift
- an audit pre-commit hook that stops commits containing plaintext keys
- syncing a profile to AWS or GCP secret managers

One-time payment, yours to keep. No subscription.

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=lite_repo&utm_content=secenv-lite).

## Need more?

Need the full version? **SecEnv CLI** on PyForge: https://py-forge.com/products/secenv-cli?utm_source=github&utm_medium=lite_repo&utm_content=secenv-lite

Or get every PyForge tool, current and future, with the All-Access Pass: https://py-forge.com/pass?utm_source=github&utm_medium=lite_repo&utm_content=secenv-lite

## Tests

```bash
python3 test_secenv_lite.py
```

## License

MIT (this lite version). The full SecEnv CLI tool is sold separately under its own license.
