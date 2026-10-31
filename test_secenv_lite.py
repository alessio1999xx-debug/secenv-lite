"""Tests for secenv-lite. Fixture secrets are built by concatenation so the
source never contains a full real-looking live key (GitHub push protection).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import secenv_lite as se


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        return se.main(argv), buf.getvalue()


def fake_openai() -> str:
    return "sk-" + ("B" * 48)


def fake_github() -> str:
    return "ghp_" + ("C" * 36)


def fake_aws_akia() -> str:
    return "AKIA" + ("D" * 16)


def fake_stripe() -> str:
    return "sk_test_" + ("E" * 24)


def fake_anthropic() -> str:
    return "sk-ant-api03-" + ("A" * 90)


def fake_slack() -> str:
    return "xoxb-" + ("F" * 12) + "-" + ("G" * 12)


def fake_google() -> str:
    return "AIzaSy" + ("H" * 33)


def _git_available() -> bool:
    return shutil.which("git") is not None


def init_git_repo(root: Path) -> None:
    subprocess.run(
        ["git", "init"], cwd=str(root), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )


@unittest.skipUnless(_git_available(), "git not available")
class GitRepoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        init_git_repo(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _commit_all(self, msg: str = "init") -> None:
        subprocess.run(
            ["git", "add", "-A"], cwd=str(self.root), check=True, capture_output=True
        )
        subprocess.run(
            ["git", "commit", "-m", msg, "--allow-empty"],
            cwd=str(self.root),
            check=True,
            capture_output=True,
        )

    def test_tracked_env_is_finding(self):
        env = self.root / ".env"
        env.write_text("HELLO=world\n", encoding="utf-8")
        # Commit WITHOUT gitignore — .env becomes tracked.
        self._commit_all("add env")
        results = se.LiteScanner(self.root).run()
        kinds = {f["kind"] for f in results["findings"]}
        self.assertIn("tracked", kinds)
        self.assertGreaterEqual(results["summary"]["risks_found"], 1)
        rc, out = run_main([str(self.root)])
        self.assertEqual(rc, 1)
        self.assertIn("ENV_TRACKED_BY_GIT", out)
        self.assertIn("git rm --cached", out)
        self.assertIn("history", out.lower())

    def test_untracked_ignored_is_clean(self):
        (self.root / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.root / ".env").write_text("HELLO=world\n", encoding="utf-8")
        self._commit_all("gitignore only")
        # .env exists but is ignored and untracked
        results = se.LiteScanner(self.root).run()
        self.assertEqual(results["summary"]["env_files_found"], 1)
        self.assertEqual(results["summary"]["risks_found"], 0)
        rc, out = run_main([str(self.root)])
        self.assertEqual(rc, 0)
        self.assertIn("CLEAN", out)

    def test_untracked_not_ignored_is_finding(self):
        (self.root / "README").write_text("x\n", encoding="utf-8")
        self._commit_all("readme")
        (self.root / ".env").write_text("HELLO=world\n", encoding="utf-8")
        # no .gitignore entry
        results = se.LiteScanner(self.root).run()
        kinds = {f["kind"] for f in results["findings"]}
        self.assertIn("unignored", kinds)
        self.assertEqual(run_main([str(self.root)])[0], 1)

    def test_template_skipped_for_tracked_but_secrets_flagged(self):
        example = self.root / ".env.example"
        secret = fake_github()
        example.write_text("GITHUB_TOKEN=" + secret + "\n", encoding="utf-8")
        self._commit_all("example tracked")
        results = se.LiteScanner(self.root).run()
        kinds = {f["kind"] for f in results["findings"]}
        # Template itself should NOT produce tracked/unignored findings.
        self.assertNotIn("tracked", kinds)
        self.assertNotIn("unignored", kinds)
        # But the real-looking secret inside must be flagged.
        self.assertIn("secret", kinds)
        providers = {f["provider"] for f in results["findings"] if f["kind"] == "secret"}
        self.assertTrue(
            any("GitHub" in p for p in providers)
            or any("Generic" in p for p in providers)
        )
        self.assertEqual(run_main([str(self.root)])[0], 1)

    def test_nested_env_local(self):
        (self.root / ".gitignore").write_text(".env\n", encoding="utf-8")
        nested = self.root / "apps" / "api"
        nested.mkdir(parents=True)
        self._commit_all("gi")
        # Create AFTER commit so it stays untracked. .env.local is an .env.*
        # file — not ignored by a bare ".env" gitignore pattern.
        env_local = nested / ".env.local"
        env_local.write_text("X=1\n", encoding="utf-8")
        results = se.LiteScanner(self.root).run()
        self.assertEqual(results["summary"]["env_files_found"], 1)
        kinds = {f["kind"] for f in results["findings"]}
        self.assertIn("unignored", kinds)


class NoGitFallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_fallback_gitignore_parser_ignores(self):
        (self.root / ".gitignore").write_text(".env\n*.local\n", encoding="utf-8")
        (self.root / ".env").write_text("A=1\n", encoding="utf-8")
        # Patch detect_git_root / git to simulate no git
        original_which = se.shutil.which

        def fake_which(cmd):
            if cmd == "git":
                return None
            return original_which(cmd)

        se.shutil.which = fake_which  # type: ignore
        try:
            results = se.LiteScanner(self.root).run()
            self.assertFalse(results["summary"]["git_available"])
            self.assertEqual(results["summary"]["risks_found"], 0)
        finally:
            se.shutil.which = original_which  # type: ignore

    def test_fallback_unignored_without_git(self):
        (self.root / ".env").write_text("A=1\n", encoding="utf-8")
        original_which = se.shutil.which

        def fake_which(cmd):
            if cmd == "git":
                return None
            return original_which(cmd)

        se.shutil.which = fake_which  # type: ignore
        try:
            results = se.LiteScanner(self.root).run()
            self.assertFalse(results["summary"]["git_available"])
            kinds = {f["kind"] for f in results["findings"]}
            self.assertIn("unignored", kinds)
            self.assertEqual(run_main([str(self.root)])[0], 1)
        finally:
            se.shutil.which = original_which  # type: ignore


class SecretAndMaskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detects_provider_keys_masked(self):
        content = "\n".join(
            [
                "OPENAI_API_KEY=" + fake_openai(),
                "GH=" + fake_github(),
                "AWS_ACCESS_KEY_ID=" + fake_aws_akia(),
                "STRIPE_KEY=" + fake_stripe(),
                "ANTHROPIC_API_KEY=" + fake_anthropic(),
                "SLACK_BOT_TOKEN=" + fake_slack(),
                "GOOGLE_API_KEY=" + fake_google(),
                "-----BEGIN RSA PRIVATE KEY-----",
            ]
        )
        (self.root / ".env").write_text(content + "\n", encoding="utf-8")
        (self.root / ".gitignore").write_text(".env\n", encoding="utf-8")
        hits = se.scan_env_content(self.root / ".env")
        providers = {h["provider"] for h in hits}
        self.assertIn("OpenAI API Key", providers)
        self.assertIn("GitHub Personal Access / OAuth Token", providers)
        self.assertIn("AWS Access Key ID", providers)
        self.assertIn("Stripe Secret Key", providers)
        self.assertIn("Anthropic API Key", providers)
        self.assertIn("Slack Token", providers)
        self.assertIn("Google Gemini / Cloud API Key", providers)
        self.assertIn("Private Key Header", providers)
        for h in hits:
            self.assertTrue(h["masked"])
            self.assertNotIn(fake_openai(), h["masked"])
            self.assertNotIn(fake_github(), h["masked"])

    def test_generic_password_assignment(self):
        (self.root / ".env").write_text(
            "DB_PASSWORD=" + ("Z" * 16) + "\n", encoding="utf-8"
        )
        hits = se.scan_env_content(self.root / ".env")
        self.assertTrue(
            any(
                h["provider"] == "Generic KEY/SECRET/TOKEN/PASSWORD assignment"
                for h in hits
            )
        )
        self.assertIn("...", hits[0]["masked"])

    def test_placeholder_not_flagged(self):
        (self.root / ".env").write_text(
            "API_KEY=changeme\nSECRET_TOKEN=your_key_here\n", encoding="utf-8"
        )
        hits = se.scan_env_content(self.root / ".env")
        generics = [
            h
            for h in hits
            if h["provider"] == "Generic KEY/SECRET/TOKEN/PASSWORD assignment"
        ]
        self.assertEqual(generics, [])

    def test_mask_short_and_long(self):
        self.assertEqual(se.mask_secret("abcd"), "[REDACTED]")
        masked = se.mask_secret("abcdefghijklmnop")
        self.assertTrue(masked.startswith("abcd"))
        self.assertTrue(masked.endswith("nop"))
        self.assertIn("...", masked)

    def test_env_production_filename(self):
        p = self.root / ".env.production"
        p.write_text("X=1\n", encoding="utf-8")
        files = se.collect_env_files(self.root)
        self.assertEqual(files, [p])

    def test_dotenv_suffix(self):
        p = self.root / "config.env"
        p.write_text("X=1\n", encoding="utf-8")
        self.assertTrue(se.is_env_filename("config.env"))
        files = se.collect_env_files(self.root)
        self.assertEqual(files, [p])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_exit_zero(self):
        (self.root / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.root / ".env").write_text("# empty-ish\nNAME=app\n", encoding="utf-8")
        rc, out = run_main([str(self.root)])
        # Without git, fallback should see .gitignore covering .env
        original_which = se.shutil.which

        def fake_which(cmd):
            if cmd == "git":
                return None
            return original_which(cmd)

        se.shutil.which = fake_which  # type: ignore
        try:
            rc, out = run_main([str(self.root)])
            self.assertEqual(rc, 0)
            self.assertIn("CLEAN", out)
        finally:
            se.shutil.which = original_which  # type: ignore

    def test_json_flag(self):
        (self.root / ".env").write_text("API_KEY=" + ("Q" * 20) + "\n", encoding="utf-8")
        rc, out = run_main(["--json", str(self.root)])
        self.assertEqual(rc, 1)
        data = json.loads(out)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertIn("fixes", data)
        self.assertGreaterEqual(data["summary"]["risks_found"], 1)

    def test_no_file_modification(self):
        env = self.root / ".env"
        body = "OPENAI_API_KEY=" + fake_openai() + "\n"
        env.write_text(body, encoding="utf-8")
        before = env.read_bytes()
        se.LiteScanner(self.root).run()
        run_main([str(self.root)])
        self.assertEqual(env.read_bytes(), before)

    def test_missing_path(self):
        missing = self.root / "nope"
        results = se.LiteScanner(missing).run()
        self.assertEqual(results["findings"][0]["provider"], "PATH_NOT_FOUND")
        self.assertEqual(run_main([str(missing)])[0], 0)

    def test_report_header(self):
        report = se.format_text_report(
            {
                "summary": {
                    "target": "/tmp/x",
                    "git_available": False,
                    "git_root": None,
                    "env_files_found": 0,
                    "findings": 0,
                    "risks_found": 0,
                },
                "findings": [],
                "fixes": [],
            }
        )
        self.assertIn("SECENV-LITE SCAN REPORT", report)
        self.assertIn("CLEAN", report)
        self.assertIn("Read-only", report)

    def test_is_template(self):
        self.assertTrue(se.is_template_filename(".env.example"))
        self.assertTrue(se.is_template_filename(".env.sample"))
        self.assertTrue(se.is_template_filename(".env.template"))
        self.assertFalse(se.is_template_filename(".env"))
        self.assertFalse(se.is_template_filename(".env.local"))


if __name__ == "__main__":
    unittest.main()
