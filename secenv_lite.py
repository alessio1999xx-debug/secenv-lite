#!/usr/bin/env python3
"""secenv-lite: read-only check for .env files at risk in a git repo.

Single file, Python 3.9+ standard library only. Finds .env-style files that are
tracked by git or missing from .gitignore, and flags obvious API keys / tokens
inside them. Masked previews only; never writes to disk.

    python secenv_lite.py
    python secenv_lite.py /path/to/repo
    python secenv_lite.py --json
    python secenv_lite.py --help

Full version (encrypt/decrypt vault, run-with-injected secrets, drift, audit
hook, sync to cloud secret managers):
https://py-forge.com/products/secenv-cli?utm_source=github&utm_medium=code&utm_content=secenv-lite
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

__version__ = "0.1.0"

# Exact template filenames: still scanned for secrets, but not flagged as
# "tracked / unignored .env file" risk on their own.
TEMPLATE_NAMES: Set[str] = {".env.example", ".env.sample", ".env.template"}

# High-confidence provider signatures + generic KEY/SECRET/TOKEN/PASSWORD=.
SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "Anthropic API Key",
        re.compile(r"\b(sk-ant-api03-[A-Za-z0-9_-]{80,120})\b"),
    ),
    (
        "Anthropic Legacy Key",
        re.compile(r"\b(sk-ant-(?!api03)[A-Za-z0-9_-]{32,80})\b"),
    ),
    (
        "OpenAI API Key",
        re.compile(r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,120})\b"),
    ),
    (
        "Google Gemini / Cloud API Key",
        re.compile(r"\b(AIzaSy[A-Za-z0-9_-]{33})\b"),
    ),
    (
        "GitHub Personal Access / OAuth Token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
    ),
    (
        "GitHub Fine-Grained Token",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    ),
    (
        "AWS Access Key ID",
        re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"),
    ),
    (
        "Slack Token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    ),
    (
        "Private Key Header",
        re.compile(r"(-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----)"),
    ),
    (
        "Generic KEY/SECRET/TOKEN/PASSWORD assignment",
        re.compile(
            r"(?i)^(?:export\s+)?"
            r"([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE)[A-Z0-9_]*)"
            r"\s*=\s*['\"]?([^\s'\"]+)['\"]?\s*$"
        ),
    ),
]

# Common placeholder values that are not real secrets.
_PLACEHOLDER_VALUES: Set[str] = {
    "",
    "changeme",
    "change_me",
    "changeme!",
    "your_key_here",
    "your_secret_here",
    "your_token_here",
    "your_password_here",
    "replace_me",
    "replace-me",
    "todo",
    "tbd",
    "xxx",
    "xxxx",
    "xxxxx",
    "xxxxxx",
    "...",
    "<secret>",
    "<password>",
    "<token>",
    "none",
    "null",
    "nil",
    "false",
    "true",
    "0",
    "1",
}


def is_env_filename(name: str) -> bool:
    """Return True for .env, .env.*, and *.env filenames."""
    if name == ".env":
        return True
    if name.startswith(".env."):
        return True
    if name.endswith(".env"):
        return True
    return False


def is_template_filename(name: str) -> bool:
    return name in TEMPLATE_NAMES


def mask_secret(value: str) -> str:
    """Produce a safe masked preview of a secret string."""
    clean = value.strip().replace("\n", "").replace("\r", "")
    if len(clean) <= 8:
        return "[REDACTED]"
    return f"{clean[:4]}...{clean[-3:]}"


def collect_env_files(root: pathlib.Path) -> List[pathlib.Path]:
    """Collect .env-style files under root (skip .git)."""
    if not root.exists():
        return []
    if root.is_file():
        return [root] if is_env_filename(root.name) else []
    found: List[pathlib.Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Do not descend into .git
        dirnames[:] = [d for d in dirnames if d != ".git"]
        current = pathlib.Path(dirpath)
        for fname in filenames:
            if is_env_filename(fname):
                found.append(current / fname)
    return sorted(found)


def _run_git(
    args: List[str], cwd: pathlib.Path, timeout: float = 10.0
) -> Optional[subprocess.CompletedProcess[str]]:
    """Run a git command; return None if git is missing or the call fails hard."""
    git = shutil.which("git")
    if not git:
        return None
    try:
        return subprocess.run(
            [git, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def detect_git_root(path: pathlib.Path) -> Optional[pathlib.Path]:
    """Return the git toplevel for path, or None if not a repo / no git."""
    start = path if path.is_dir() else path.parent
    proc = _run_git(["rev-parse", "--show-toplevel"], cwd=start)
    if proc is None or proc.returncode != 0:
        return None
    top = proc.stdout.strip()
    if not top:
        return None
    return pathlib.Path(top)


def git_tracked_files(git_root: pathlib.Path) -> Optional[Set[str]]:
    """Relative posix paths of tracked files, or None if git unavailable."""
    proc = _run_git(["ls-files", "-z"], cwd=git_root)
    if proc is None or proc.returncode != 0:
        return None
    out = proc.stdout
    if not out:
        return set()
    parts = out.split("\0")
    return {p for p in parts if p}


def git_check_ignored(git_root: pathlib.Path, rel_posix: str) -> Optional[bool]:
    """True if ignored, False if not, None if git check-ignore unavailable."""
    proc = _run_git(["check-ignore", "-q", "--", rel_posix], cwd=git_root)
    if proc is None:
        return None
    # exit 0 = ignored, 1 = not ignored, other = error
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None


def _gitignore_patterns(gitignore_path: pathlib.Path) -> List[Tuple[bool, str]]:
    """Parse a .gitignore into (negated, pattern) pairs. Simple subset only."""
    patterns: List[Tuple[bool, str]] = []
    try:
        text = gitignore_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return patterns
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:]
        # Drop directory-only trailing slash for matching simplicity.
        if line.endswith("/") and len(line) > 1:
            line = line.rstrip("/")
        patterns.append((negated, line))
    return patterns


def _path_matches_gitignore_pattern(rel_posix: str, pattern: str) -> bool:
    """Very small fnmatch-based matcher for common .gitignore patterns."""
    import fnmatch

    name = rel_posix.rsplit("/", 1)[-1]
    # Patterns with a slash match against the full relative path.
    if "/" in pattern.strip("/"):
        return fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(
            rel_posix, pattern.lstrip("/")
        )
    # Patterns without a slash match any path segment / basename.
    if fnmatch.fnmatch(name, pattern):
        return True
    # Also allow matching against any directory prefix + basename.
    return fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(
        rel_posix, "*/" + pattern
    )


def fallback_is_ignored(root: pathlib.Path, file_path: pathlib.Path) -> bool:
    """Best-effort .gitignore check when git is not available."""
    try:
        rel = file_path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    rel_posix = rel.as_posix()
    # Walk from root down to the file's directory, applying each .gitignore.
    ignored = False
    parts = pathlib.Path(rel_posix).parts
    # Check root .gitignore and nested ones along the path.
    dirs_to_check = [root]
    accum: List[str] = []
    for part in parts[:-1]:
        accum.append(part)
        dirs_to_check.append(root.joinpath(*accum))
    for base in dirs_to_check:
        gi = base / ".gitignore"
        if not gi.is_file():
            continue
        try:
            local_rel = file_path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            local_rel = rel_posix
        for negated, pattern in _gitignore_patterns(gi):
            if _path_matches_gitignore_pattern(local_rel, pattern) or (
                local_rel != rel_posix
                and _path_matches_gitignore_pattern(rel_posix, pattern)
            ):
                ignored = not negated
    # Also match against basename-only patterns from root for the full path.
    return ignored


def scan_env_content(file_path: pathlib.Path) -> List[Dict[str, Any]]:
    """Scan one .env-style file for obvious secret patterns."""
    hits: List[Dict[str, Any]] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        return [
            {
                "kind": "unreadable",
                "provider": "UNREADABLE_FILE",
                "path": str(file_path),
                "line": 0,
                "key": "",
                "masked": "",
                "description": f"Cannot read file: {exc}",
            }
        ]

    seen: Set[Tuple[int, str, str]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for provider, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                if provider.startswith("Generic"):
                    # groups: key name, value
                    key_name = match.group(1)
                    raw = match.group(2)
                    if raw.strip().lower() in _PLACEHOLDER_VALUES:
                        continue
                    if len(raw.strip()) < 4:
                        continue
                    display_key = key_name
                else:
                    raw = match.group(1) if match.lastindex else match.group(0)
                    display_key = ""
                dedupe = (line_no, provider, raw)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                hits.append(
                    {
                        "kind": "secret",
                        "provider": provider,
                        "path": str(file_path),
                        "line": line_no,
                        "key": display_key,
                        "masked": mask_secret(raw),
                        "description": f"{provider} match (masked preview)",
                    }
                )
    return hits


class LiteScanner:
    """Read-only .env risk scanner (lite)."""

    def __init__(self, target: pathlib.Path) -> None:
        self.target = target.expanduser().resolve()
        self.env_files_found = 0
        self.findings: List[Dict[str, Any]] = []
        self.git_available = False
        self.git_root: Optional[pathlib.Path] = None

    def run(self) -> Dict[str, Any]:
        if not self.target.exists():
            self.findings.append(
                {
                    "kind": "error",
                    "provider": "PATH_NOT_FOUND",
                    "path": str(self.target),
                    "line": 0,
                    "key": "",
                    "masked": "",
                    "description": "Scan target path does not exist",
                }
            )
            return self._result()

        self.git_root = detect_git_root(self.target)
        tracked: Optional[Set[str]] = None
        if self.git_root is not None:
            self.git_available = True
            tracked = git_tracked_files(self.git_root)

        files = collect_env_files(self.target)
        self.env_files_found = len(files)

        for fpath in files:
            rel_posix = self._rel_posix(fpath)
            is_template = is_template_filename(fpath.name)

            tracked_flag: Optional[bool] = None
            ignored_flag: Optional[bool] = None

            if self.git_available and self.git_root is not None and tracked is not None:
                tracked_flag = rel_posix in tracked
                ignored_flag = git_check_ignored(self.git_root, rel_posix)
                if ignored_flag is None:
                    ignored_flag = fallback_is_ignored(self.git_root, fpath)
            else:
                # No git: degrade gracefully — only .gitignore fallback from target.
                base = self.target if self.target.is_dir() else self.target.parent
                ignored_flag = fallback_is_ignored(base, fpath)
                tracked_flag = None

            if not is_template:
                if tracked_flag is True:
                    self.findings.append(
                        {
                            "kind": "tracked",
                            "provider": "ENV_TRACKED_BY_GIT",
                            "path": str(fpath),
                            "line": 0,
                            "key": "",
                            "masked": "",
                            "description": (
                                f"{fpath.name} is tracked by git "
                                f"(relative: {rel_posix}). Plain secrets in "
                                "history stay even after you delete the file."
                            ),
                            "tracked": True,
                            "ignored": ignored_flag,
                            "template": False,
                        }
                    )
                elif tracked_flag is False and ignored_flag is False:
                    self.findings.append(
                        {
                            "kind": "unignored",
                            "provider": "ENV_NOT_GITIGNORED",
                            "path": str(fpath),
                            "line": 0,
                            "key": "",
                            "masked": "",
                            "description": (
                                f"{fpath.name} is not covered by .gitignore "
                                f"(relative: {rel_posix}). An accidental "
                                "`git add` could commit it."
                            ),
                            "tracked": False,
                            "ignored": False,
                            "template": False,
                        }
                    )
                elif tracked_flag is None and ignored_flag is False:
                    # No git binary / not a repo: still warn when .gitignore
                    # does not cover the file.
                    self.findings.append(
                        {
                            "kind": "unignored",
                            "provider": "ENV_NOT_GITIGNORED",
                            "path": str(fpath),
                            "line": 0,
                            "key": "",
                            "masked": "",
                            "description": (
                                f"{fpath.name} does not appear covered by "
                                f".gitignore (relative: {rel_posix}; git "
                                "unavailable, used a simple fallback parser)."
                            ),
                            "tracked": None,
                            "ignored": False,
                            "template": False,
                        }
                    )

            # Always scan content (including templates) for obvious keys.
            for hit in scan_env_content(fpath):
                hit["template"] = is_template
                hit["tracked"] = tracked_flag
                hit["ignored"] = ignored_flag
                self.findings.append(hit)

        return self._result()

    def _rel_posix(self, fpath: pathlib.Path) -> str:
        base = self.git_root if self.git_root is not None else (
            self.target if self.target.is_dir() else self.target.parent
        )
        try:
            return fpath.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            return fpath.name

    def _result(self) -> Dict[str, Any]:
        risk_kinds = {"tracked", "unignored", "secret"}
        risks = [f for f in self.findings if f.get("kind") in risk_kinds]
        return {
            "summary": {
                "target": str(self.target),
                "git_available": self.git_available,
                "git_root": str(self.git_root) if self.git_root else None,
                "env_files_found": self.env_files_found,
                "findings": len(self.findings),
                "risks_found": len(risks),
            },
            "findings": self.findings,
            "fixes": build_fix_list(self.findings),
        }


def build_fix_list(findings: List[Dict[str, Any]]) -> List[str]:
    """Human fix steps derived from what was found."""
    fixes: List[str] = []
    has_tracked = any(f.get("kind") == "tracked" for f in findings)
    has_unignored = any(f.get("kind") == "unignored" for f in findings)
    has_secret = any(f.get("kind") == "secret" for f in findings)

    if has_unignored or has_tracked:
        fixes.append(
            "Add .env (and .env.* if you use variants) to .gitignore, then "
            "commit the .gitignore change."
        )
    if has_tracked:
        fixes.append(
            "Stop tracking the file without deleting it locally: "
            "`git rm --cached -- <file>` (repeat for each tracked .env)."
        )
        fixes.append(
            "Caveat: removing the file from the index does NOT remove it from "
            "git history. If this repo was ever pushed, treat every value in "
            "that .env as exposed and rotate the keys at each provider."
        )
    if has_secret and not has_tracked:
        fixes.append(
            "Rotate any real credentials that matched at the provider. Even a "
            "local-only .env can leak via chat paste, backups or a future commit."
        )
    if has_secret and has_tracked:
        # already added history caveat; reinforce rotation
        if not any("rotate" in f.lower() for f in fixes):
            fixes.append(
                "Rotate every exposed key at the provider. History rewrite "
                "(filter-repo / BFG) is a separate step and does not replace "
                "rotation if the repo was ever pushed or shared."
            )
    if not fixes and findings:
        # errors only
        fixes.append("Fix the path / permission errors above and re-run.")
    return fixes


def format_text_report(results: Dict[str, Any]) -> str:
    summary = results["summary"]
    findings = results["findings"]
    fixes = results["fixes"]
    lines = [
        "================================================================================",
        "                        SECENV-LITE SCAN REPORT                                ",
        "================================================================================",
        f"Target                 : {summary['target']}",
        f"Git available          : {summary['git_available']}",
        f"Git root               : {summary['git_root'] or '(none)'}",
        f".env-style files found : {summary['env_files_found']}",
        f"Findings               : {summary['findings']}",
        f"Risks reported         : {summary['risks_found']}",
        "--------------------------------------------------------------------------------",
    ]
    if summary["risks_found"] == 0 and not any(
        f.get("kind") in ("error", "unreadable") for f in findings
    ):
        lines.append(
            "[+] Status: CLEAN. No tracked/unignored .env files and no "
            "obvious key patterns in scanned .env-style files."
        )
    else:
        lines.append(f"Findings ({len(findings)} total):")
        for i, f in enumerate(findings, start=1):
            lines.append(f"\n{i}. Kind      : {f.get('kind')}")
            lines.append(f"   Provider  : {f.get('provider')}")
            lines.append(f"   Path      : {f.get('path')}")
            if f.get("line"):
                lines.append(f"   Line      : {f['line']}")
            if f.get("key"):
                lines.append(f"   Key       : {f['key']}")
            if f.get("masked"):
                lines.append(f"   Preview   : {f['masked']}")
            lines.append(f"   Details   : {f.get('description')}")

    if fixes:
        lines.append("\n--------------------------------------------------------------------------------")
        lines.append("Suggested fixes:")
        for i, fix in enumerate(fixes, start=1):
            lines.append(f"  {i}. {fix}")

    lines.append("================================================================================")
    lines.append(
        "Read-only scan. No files were modified. This checks common patterns "
        "only — it does not claim to find every possible secret."
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secenv-lite",
        description=(
            "Read-only check for .env files that are tracked by git or missing "
            "from .gitignore, plus obvious API keys/tokens inside them. "
            "Stdlib only; never modifies files."
        ),
        epilog=(
            "Full version: https://py-forge.com/products/secenv-cli"
            "?utm_source=github&utm_medium=cli&utm_content=secenv-lite"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repo or directory to scan (default: current working directory).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print the report as JSON instead of text.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    target = pathlib.Path(args.path).expanduser()
    results = LiteScanner(target).run()
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=False))
    else:
        print(format_text_report(results))
    return 1 if results["summary"]["risks_found"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
