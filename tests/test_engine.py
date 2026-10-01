"""Tests for the headless engine. No live network required."""
import subprocess
import sys
import unittest
from unittest import mock

from jetscanner import engine
from jetscanner.engine import ModuleSpec, run_scan
from jetscanner.models import Finding, ModuleResult, Severity
from jetscanner.validators import InvalidTarget


def _fake(key, *findings, boom=False, calls=None):
    """A registry entry that returns canned findings (or raises)."""

    def run(net, web, host, url):
        if calls is not None:
            calls.append((key, host, url))
        if boom:
            raise RuntimeError("kaboom")
        result = ModuleResult(module=key)
        for finding in findings:
            result.add(finding)
        return result

    return ModuleSpec(key, key.title(), run)


def _registry(*specs):
    return mock.patch.dict(engine.MODULES, {s.key: s for s in specs}, clear=True)


class TestHeadless(unittest.TestCase):
    def test_package_imports_without_tkinter(self):
        # Fresh interpreter with tkinter made unimportable: the library (and
        # every engine module) must still load, and must not pull in the GUI.
        code = (
            "import sys; sys.modules['tkinter'] = None\n"
            "import jetscanner\n"
            "from jetscanner import advisor, reporting\n"
            "assert callable(jetscanner.run_scan)\n"
            "assert 'jetscanner.ui' not in sys.modules\n"
        )
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestRegistry(unittest.TestCase):
    def test_public_module_keys(self):
        # These keys are a public contract (CLI --modules, API). Don't rename.
        self.assertEqual(list(engine.MODULES),
                         ["socket", "nmap", "tech", "sqli", "xss", "dir"])


class TestRunScan(unittest.TestCase):
    def test_runs_in_registry_order_and_dedupes(self):
        calls = []
        with _registry(_fake("a", calls=calls), _fake("b", calls=calls)):
            report = run_scan("example.com", ["b", "a", "b"])
        self.assertEqual([c[0] for c in calls], ["a", "b"])
        self.assertEqual([r.module for r in report.results], ["a", "b"])

    def test_passes_normalized_host_and_url(self):
        calls = []
        with _registry(_fake("a", calls=calls)):
            report = run_scan("http://site.com/p?id=1", ["a"])
        self.assertEqual(calls, [("a", "site.com", "http://site.com/p?id=1")])
        self.assertEqual(report.host, "site.com")
        self.assertIsNotNone(report.started_at.tzinfo)
        self.assertLessEqual(report.started_at, report.finished_at)

    def test_rejects_bad_input_before_running_anything(self):
        calls = []
        with _registry(_fake("a", calls=calls)):
            with self.assertRaises(InvalidTarget):
                run_scan("not a host!", ["a"])
            with self.assertRaises(ValueError):
                run_scan("example.com", [])
            with self.assertRaisesRegex(ValueError, "Unknown module"):
                run_scan("example.com", ["a", "nope"])
        self.assertEqual(calls, [])

    def test_crashing_module_is_isolated(self):
        with _registry(_fake("a", boom=True), _fake("b")):
            report = run_scan("example.com", ["a", "b"])
        self.assertEqual(report.results[0].error, "kaboom")
        self.assertEqual(report.results[0].module, "A")
        self.assertIsNone(report.results[1].error)

    def test_callbacks_fire_per_module_in_order(self):
        events = []
        with _registry(_fake("a"), _fake("b")):
            run_scan("example.com", ["a", "b"],
                     on_module_start=lambda s: events.append(("start", s.key)),
                     on_result=lambda r: events.append(("done", r.module)))
        self.assertEqual(events, [("start", "a"), ("done", "a"),
                                  ("start", "b"), ("done", "b")])

    def test_findings_sorted_worst_first_and_stable(self):
        low1 = Finding("l1", "low 1", Severity.LOW)
        crit = Finding("c", "crit", Severity.CRITICAL)
        low2 = Finding("l2", "low 2", Severity.LOW)
        info = Finding("i", "info", Severity.INFO)
        with _registry(_fake("a", low1, info), _fake("b", low2, crit)):
            report = run_scan("example.com", ["a", "b"])
        self.assertEqual(report.findings, [crit, low1, low2, info])


if __name__ == "__main__":
    unittest.main()
