"""Tests for the ``jet`` CLI. No live network required."""
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from jetscanner import __version__, cli
from jetscanner.engine import MODULES
from jetscanner.models import Finding, ModuleResult, ScanReport, Severity

_XSS = Finding("xss", "Reflected XSS", Severity.HIGH, "action=/search")


def _fake_run_scan(*findings, calls=None):
    """Stand-in for engine.run_scan that returns one canned XSS module."""

    def fake(target, modules, on_module_start=None, on_result=None):
        if calls is not None:
            calls.append(list(modules))
        result = ModuleResult(module="XSS")
        result.log("[*] XSS scan ...")
        for finding in findings:
            result.add(finding)
        if on_module_start:
            on_module_start(MODULES["xss"])
        if on_result:
            on_result(result)
        now = datetime.now(timezone.utc)
        return ScanReport(host="site.com", url="http://site.com",
                          started_at=now, finished_at=now, results=[result])

    return fake


def _run(argv, *findings, calls=None):
    """Run the CLI with a fake engine; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(cli, "run_scan", _fake_run_scan(*findings, calls=calls)), \
            redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestScanOutput(unittest.TestCase):
    def test_json_stdout_is_clean_and_progress_goes_to_stderr(self):
        code, out, err = _run(["scan", "site.com", "-m", "xss", "-f", "json"], _XSS)
        self.assertEqual(code, cli.EXIT_OK)
        data = json.loads(out)  # stdout must be pure JSON
        self.assertEqual(data["findings"][0]["key"], "xss")
        self.assertIn(cli.NOTICE, err)
        self.assertIn("[*] XSS ...", err)
        self.assertIn("1 finding(s)", err)

    def test_quiet_keeps_only_the_notice(self):
        _, _, err = _run(["scan", "site.com", "-m", "xss", "-f", "json", "-q"])
        self.assertEqual(err.strip(), cli.NOTICE)

    def test_sarif(self):
        _, out, _ = _run(["scan", "site.com", "-m", "xss", "-f", "sarif"], _XSS)
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_text_is_the_default_and_includes_advice(self):
        _, out, _ = _run(["scan", "site.com", "-m", "xss"], _XSS)
        self.assertIn("Jet Vulnerability Scanner", out)
        self.assertIn("Cross-Site Scripting (XSS)", out)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            code, out, err = _run(
                ["scan", "site.com", "-m", "xss", "-f", "json", "-o", str(path)], _XSS)
            self.assertEqual(code, cli.EXIT_OK)
            self.assertEqual(out, "")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))
                             ["findings"][0]["key"], "xss")
            self.assertIn("Written to", err)

    def test_unwritable_output_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:  # a directory, not a file
            code, _, err = _run(["scan", "site.com", "-m", "xss", "-o", tmp])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("cannot write", err)


class TestModulesArg(unittest.TestCase):
    def test_all_expands_to_every_module(self):
        calls = []
        _run(["scan", "site.com", "-m", "all"], calls=calls)
        self.assertEqual(calls, [list(MODULES)])

    def test_list_is_trimmed(self):
        calls = []
        _run(["scan", "site.com", "-m", " xss, sqli ,"], calls=calls)
        self.assertEqual(calls, [["xss", "sqli"]])

    def test_modules_is_required(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["scan", "site.com"])
        self.assertEqual(ctx.exception.code, 2)


class TestExitCodes(unittest.TestCase):
    def test_fail_on_threshold(self):
        argv = ["scan", "site.com", "-m", "xss", "-q", "--fail-on"]
        self.assertEqual(_run(argv + ["high"], _XSS)[0], cli.EXIT_FINDINGS)
        self.assertEqual(_run(argv + ["low"], _XSS)[0], cli.EXIT_FINDINGS)
        self.assertEqual(_run(argv + ["critical"], _XSS)[0], cli.EXIT_OK)
        self.assertEqual(_run(argv + ["info"])[0], cli.EXIT_OK)  # no findings

    def test_findings_alone_do_not_fail(self):
        self.assertEqual(_run(["scan", "site.com", "-m", "xss"], _XSS)[0], cli.EXIT_OK)

    def test_bad_input_is_a_clean_error(self):
        # Real engine: it rejects these before sending any traffic.
        for argv, needle in (
            (["scan", "not a host!", "-m", "xss"], "not a valid IP or domain"),
            (["scan", "site.com", "-m", "nope"], "Unknown module(s): nope"),
        ):
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = cli.main(argv)
            self.assertEqual(code, cli.EXIT_ERROR)
            self.assertIn("jet: error:", err.getvalue())
            self.assertIn(needle, err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

    def test_interrupt(self):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt

        err = io.StringIO()
        with mock.patch.object(cli, "run_scan", interrupted), \
                redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(["scan", "site.com", "-m", "xss"])
        self.assertEqual(code, cli.EXIT_INTERRUPTED)
        self.assertIn("Interrupted", err.getvalue())


class TestOtherCommands(unittest.TestCase):
    def test_modules_lists_every_key(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["modules"]), cli.EXIT_OK)
        self.assertEqual([line.split()[0] for line in out.getvalue().splitlines()],
                         list(MODULES))

    def test_python_dash_m_entry_point(self):
        proc = subprocess.run([sys.executable, "-m", "jetscanner", "--version"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), f"jet {__version__}")


if __name__ == "__main__":
    unittest.main()
