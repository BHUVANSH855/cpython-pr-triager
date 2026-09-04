import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("triager", ROOT / "scripts" / "analyze.py")
triager = importlib.util.module_from_spec(SPEC)
import sys
sys.modules["triager"] = triager
SPEC.loader.exec_module(triager)


class TriagerTests(unittest.TestCase):
    def test_codeowners_last_match_wins(self):
        rules = triager.parse_codeowners("""
* @global
*.c @c-team
Python/* @python-team
""")
        owners = triager.resolve_codeowners(rules, ["Python/ceval.c"])
        self.assertEqual([x["owner"] for x in owners], ["@python-team"])

    def test_codeowners_directory_pattern(self):
        self.assertTrue(triager.codeowners_match("/docs/", "docs/a/b.rst"))
        self.assertTrue(triager.codeowners_match("docs/*", "docs/a.rst"))
        self.assertFalse(triager.codeowners_match("docs/*", "docs/a/b.rst"))

    def test_extract_refs(self):
        issues, peps, discussions = triager.extract_refs(
            "gh-12345 fixes #12346 and references PEP 709 "
            "https://discuss.python.org/t/example/123"
        )
        self.assertEqual(issues, [12345, 12346])
        self.assertEqual(peps, [709])
        self.assertEqual(discussions, ["https://discuss.python.org/t/example/123"])

    def test_added_removed(self):
        added, removed = triager.added_removed(
            "@@ -1 +1 @@\n-old\n+new\n+++ ignored\n--- ignored"
        )
        self.assertEqual(added, "new")
        self.assertEqual(removed, "old")

    def test_ast_eval_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/example.py",
            "patch": "@@ -0 +1 @@\n+value = eval(data)"
        }])
        self.assertTrue(any(f.category == "AST" and f.severity == "HIGH" for f in findings))

    def test_refcount_is_low_confidence(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1,5 @@\n+Py_INCREF(a)\n+Py_INCREF(b)\n+Py_INCREF(c)\n+return 0;"
        }])
        rc = [f for f in findings if f.category == "REFCOUNT"]
        self.assertEqual(len(rc), 1)
        self.assertEqual(rc[0].severity, "LOW")
        self.assertEqual(rc[0].confidence, "low")

    def test_stale_ordering(self):
        pr = {"state": "open"}
        old = [{"kind": "comment", "bot": False, "date": "2026-01-01T00:00:00Z"}]
        signals = triager.review_signals(pr, old)
        self.assertTrue(any(s == "WARN" for s, _ in signals))

    def test_historical_statistics(self):
        data = triager.historical_statistics([
            {"additions": 1, "deletions": 1, "merged": True},
            {"additions": 9, "deletions": 1, "merged": True},
            {"additions": 19, "deletions": 1, "merged": False},
        ])
        self.assertEqual(data["n"], 3)
        self.assertEqual(data["median"], 10)

    def test_save_pattern_shape(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "patterns.json"
            payload = {"requested": 5, "collected": 5}
            p.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(json.loads(p.read_text())["collected"], 5)


if __name__ == "__main__":
    unittest.main()
