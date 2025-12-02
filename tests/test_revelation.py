import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from RevelationScan.core.base import ScanContext
from RevelationScan.core.feed import compute_target_feed, resolve_update_sources, update_feed
from RevelationScan.trumpets.accounts import AccountsTrumpet
from RevelationScan.trumpets.listening_ports import ListeningPortsTrumpet
from RevelationScan.trumpets.service_versions import ServiceVersionTrumpet
from RevelationScan.trumpets.world_writable import WorldWritableTrumpet
from RevelationScan.trumpets.sudoers import SudoersTrumpet


def make_context(**overrides):
    defaults = dict(config={}, cve_feed=None, output_format="text", suggest_exploits=False, plugins=())
    defaults.update(overrides)
    return ScanContext(**defaults)


class TestWorldWritableTrumpet(unittest.TestCase):
    def test_detects_world_writable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            insecure_dir = root / "etc"
            insecure_dir.mkdir()
            target = insecure_dir / "shadow"
            target.write_text("data", encoding="utf-8")
            target.chmod(0o666)

            trumpet = WorldWritableTrumpet()
            with mock.patch.object(WorldWritableTrumpet, "TARGETS", [(insecure_dir, "fixture directory")]):
                findings = trumpet.blow(make_context())

        self.assertTrue(findings, "expected finding for world-writable file")
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("shadow", findings[0].details[0])


class TestServiceVersionTrumpet(unittest.TestCase):
    def test_reports_vulnerable_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            feed_path = Path(tmpdir) / "feed.json"
            feed_path.write_text(
                json.dumps(
                    {
                        "services": [
                            {
                                "name": "dummy",
                                "command": ["dummy", "--version"],
                                "pattern": "dummy (\\d+\\.\\d+)",
                                "advisories": [
                                    {
                                        "cve": "CVE-TEST",
                                        "fixed_version": "2.0",
                                        "description": "Test advisory",
                                        "remediation": "Update dummy",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            trumpet = ServiceVersionTrumpet()
            context = make_context(cve_feed=feed_path)

            fake_completed = subprocess.CompletedProcess(
                args=["dummy", "--version"], returncode=0, stdout="dummy 1.0\n", stderr=""
            )
            with mock.patch("RevelationScan.trumpets.service_versions.subprocess.run", return_value=fake_completed):
                findings = trumpet.blow(context)

        self.assertTrue(findings, "expected vulnerable finding")
        self.assertEqual(findings[0].cve, "CVE-TEST")
        self.assertIn("dummy 1.0", findings[0].details[0])


class TestListeningPortsTrumpet(unittest.TestCase):
    def test_parses_ss_output(self) -> None:
        sample_output = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nudp   UNCONN 0      0      0.0.0.0:9999    0.0.0.0:*     users:(\"proc\")"""
        fake_completed = subprocess.CompletedProcess(args=["ss"], returncode=0, stdout=sample_output, stderr="")
        with mock.patch("shutil.which", return_value="/usr/bin/ss"), mock.patch(
            "RevelationScan.trumpets.listening_ports.subprocess.run", return_value=fake_completed
        ):
            findings = ListeningPortsTrumpet().blow(make_context())

        self.assertEqual(len(findings), 1)
        summary_line, raw_header, *_ = findings[0].details
        self.assertIn("Interesting ports: 9999:proc", summary_line)
        self.assertEqual(raw_header, "Raw sockets:")
        self.assertTrue(any("0.0.0.0:9999" in line for line in findings[0].details[2:]))


class TestAccountsTrumpet(unittest.TestCase):
    def test_flags_service_shell(self) -> None:
        passwd_content = "service-user:x:1001:1001:service account:/srv/service:/bin/bash\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            passwd_path = Path(tmpdir) / "passwd"
            passwd_path.write_text(passwd_content, encoding="utf-8")
            trumpet = AccountsTrumpet()
            with mock.patch.object(AccountsTrumpet, "passwd_path", passwd_path):
                findings = trumpet.blow(make_context())
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "warning")


class TestFeedUtilities(unittest.TestCase):
    def test_resolve_update_sources(self) -> None:
        sources = resolve_update_sources({"update_sources": ["https://example.com/feed.json"]}, None)
        self.assertEqual(sources, ["https://example.com/feed.json"])

    def test_update_feed_merges_entries(self) -> None:
        payload = json.dumps(
            {
                "services": [
                    {
                        "name": "dummy",
                        "command": ["dummy", "--version"],
                        "pattern": "dummy (\\d+)",
                        "advisories": [
                            {"cve": "CVE-1", "fixed_version": "1", "description": "d", "remediation": "r"}
                        ],
                    }
                ]
            }
        )

        class FakeResponse(io.StringIO):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                self.close()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "feed.json"
            with mock.patch("urllib.request.urlopen", return_value=FakeResponse(payload)):
                success, errors = update_feed(target, ["https://example.com/feed.json"])
            self.assertTrue(success)
            self.assertFalse(errors)
            written = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(written["services"][0]["name"], "dummy")


class TestSudoersTrumpet(unittest.TestCase):
    def test_reports_nopasswd_commands(self) -> None:
        sample_output = """User tester may run the following commands on arch:
    (root) NOPASSWD: /usr/bin/vim, /usr/bin/find
"""
        fake_completed = subprocess.CompletedProcess(
            args=["sudo", "-n", "-l"], returncode=0, stdout=sample_output, stderr=""
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_dir = Path(tmpdir) / "sudoers.d"
            trumpet = SudoersTrumpet()
            with mock.patch.object(SudoersTrumpet, "include_dir", missing_dir), mock.patch(
                "RevelationScan.trumpets.sudoers.subprocess.run", return_value=fake_completed
            ):
                findings = trumpet.blow(make_context())

        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.severity == "critical" for f in findings))
        summary = " ".join(detail for f in findings for detail in f.details)
        self.assertIn("/usr/bin/vim", summary)
        self.assertIn("Common privesc", summary)


if __name__ == "__main__":
    unittest.main()
