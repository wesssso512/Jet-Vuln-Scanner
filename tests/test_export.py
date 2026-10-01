"""Tests for JSON / SARIF output. No live network required."""
import json
import unittest
from datetime import datetime, timezone

from jetscanner import __version__
from jetscanner.export import to_dict, to_json, to_sarif, to_sarif_json
from jetscanner.models import Finding, ModuleResult, ScanReport, Severity


def _report():
    web = ModuleResult(module="Directory Busting")
    web.log("[+] 200 OK   http://site.com/admin")
    web.add(Finding("dir_found", "Path exposed: /admin", Severity.LOW,
                    "http://site.com/admin"))
    web.add(Finding("dir_found", "Path exposed: /backup", Severity.LOW,
                    "http://site.com/backup"))
    sqli = ModuleResult(module="SQL Injection")
    sqli.add(Finding("sqli", "SQL injection", Severity.CRITICAL,
                     "param=id db=MySQL"))
    nmap = ModuleResult(module="Nmap Scan", error="Nmap not found on this system.")
    return ScanReport(
        host="site.com",
        url="http://site.com/p?id=1",
        started_at=datetime(2026, 10, 1, 3, 41, 23, 511509, tzinfo=timezone.utc),
        finished_at=datetime(2026, 10, 1, 3, 41, 29, tzinfo=timezone.utc),
        results=[web, sqli, nmap],
    )


class TestJson(unittest.TestCase):
    def test_round_trips_through_json(self):
        self.assertEqual(json.loads(to_json(_report())), to_dict(_report()))

    def test_header(self):
        data = to_dict(_report())
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["tool"], {"name": "jetscanner", "version": __version__})
        self.assertEqual(data["target"],
                         {"host": "site.com", "url": "http://site.com/p?id=1"})
        self.assertEqual(data["started_at"], "2026-10-01T03:41:23.511509+00:00")

    def test_findings_mirror_finding_fields_worst_first(self):
        findings = to_dict(_report())["findings"]
        self.assertEqual(findings[0], {
            "key": "sqli", "title": "SQL injection", "severity": "critical",
            "detail": "param=id db=MySQL", "module": "SQL Injection",
        })
        self.assertEqual([f["title"] for f in findings[1:]],
                         ["Path exposed: /admin", "Path exposed: /backup"])

    def test_summary_counts(self):
        self.assertEqual(to_dict(_report())["summary"], {
            "total": 3, "critical": 1, "high": 0, "medium": 0, "low": 2, "info": 0,
        })

    def test_modules_keep_log_and_error(self):
        modules = to_dict(_report())["modules"]
        self.assertEqual([m["module"] for m in modules],
                         ["Directory Busting", "SQL Injection", "Nmap Scan"])
        self.assertEqual(modules[0]["log"], ["[+] 200 OK   http://site.com/admin"])
        self.assertIsNone(modules[0]["error"])
        self.assertEqual(modules[2]["error"], "Nmap not found on this system.")

    def test_unfinished_scan_has_null_finish_time(self):
        report = _report()
        report.finished_at = None
        self.assertIsNone(to_dict(report)["finished_at"])


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.log = to_sarif(_report())
        self.run = self.log["runs"][0]

    def test_envelope(self):
        self.assertEqual(self.log["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", self.log["$schema"])
        self.assertEqual(len(self.log["runs"]), 1)
        self.assertEqual(self.run["tool"]["driver"]["name"], "jetscanner")
        self.assertEqual(json.loads(to_sarif_json(_report())), self.log)

    def test_one_rule_per_key_with_advisor_text(self):
        rules = self.run["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], ["sqli", "dir_found"])
        sqli = rules[0]
        self.assertEqual(sqli["shortDescription"]["text"], "SQL Injection (SQLi)")
        self.assertIn("parameterized queries", sqli["help"]["text"])
        self.assertEqual(sqli["defaultConfiguration"]["level"], "error")
        self.assertEqual(sqli["properties"]["security-severity"], "9.5")

    def test_rule_without_advice_falls_back_to_title(self):
        report = _report()
        report.results[0].add(Finding("port_443", "HTTPS (443) open"))
        rules = to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]
        rule = next(r for r in rules if r["id"] == "port_443")
        self.assertEqual(rule["shortDescription"]["text"], "HTTPS (443) open")
        self.assertEqual(rule["defaultConfiguration"]["level"], "note")

    def test_results_reference_rules_and_target(self):
        rules = self.run["tool"]["driver"]["rules"]
        results = self.run["results"]
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertEqual(uri, "http://site.com/p?id=1")
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[0]["message"]["text"],
                         "SQL injection: param=id db=MySQL")
        self.assertEqual(results[1]["level"], "note")

    def test_module_errors_are_notifications_not_results(self):
        invocation = self.run["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        notes = invocation["toolExecutionNotifications"]
        self.assertEqual(notes, [{"level": "error", "message": {
            "text": "Nmap Scan: Nmap not found on this system."}}])
        self.assertNotIn("Nmap", json.dumps(self.run["results"]))

    def test_times_are_utc_with_z(self):
        invocation = self.run["invocations"][0]
        self.assertEqual(invocation["startTimeUtc"], "2026-10-01T03:41:23.511Z")
        self.assertEqual(invocation["endTimeUtc"], "2026-10-01T03:41:29.000Z")

    def test_clean_scan_is_valid_and_empty(self):
        report = ScanReport(host="a.com", url="http://a.com",
                            started_at=datetime.now(timezone.utc))
        run = to_sarif(report)["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])


if __name__ == "__main__":
    unittest.main()
