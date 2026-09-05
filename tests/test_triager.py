"""
Tests for scripts/analyze.py orchestration layer.

FIX (point 10): replaced the fragile importlib.util hack with a proper
sys.path approach that works identically to how analyze.py runs itself.
Tests now import from the package normally.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the repo root is on sys.path so imports work whether tests
# are run from the repo root or the tests/ directory.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Import the module under test the normal way.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location("triager_analyze", REPO_ROOT / "scripts" / "analyze.py")
triager = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(triager)  # type: ignore[union-attr]

# Also import sub-modules directly for specific tests.
from scripts.triager.analyzers import RULES
from scripts.triager.policy import (
    BACKPORT_LABEL_RE,
    branch_and_backport_signals,
    disposition,
)


class TriagerTests(unittest.TestCase):
    """Tests for the orchestration layer in analyze.py."""

    # ------------------------------------------------------------------
    # CODEOWNERS
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Reference extraction
    # ------------------------------------------------------------------

    def test_extract_refs(self):
        issues, peps, discussions = triager.extract_refs(
            "gh-12345 fixes #12346 and references PEP 709 "
            "https://discuss.python.org/t/example/123"
        )
        self.assertEqual(issues, [12345, 12346])
        self.assertEqual(peps, [709])
        self.assertIn("https://discuss.python.org/t/example/123", discussions)

    # ------------------------------------------------------------------
    # Diff helpers
    # ------------------------------------------------------------------

    def test_added_removed(self):
        added, removed = triager.added_removed(
            "@@ -1 +1 @@\n-old\n+new\n+++ ignored\n--- ignored"
        )
        self.assertEqual(added, "new")
        self.assertEqual(removed, "old")

    # ------------------------------------------------------------------
    # Static analysis (via analyze_diff wrapper)
    # ------------------------------------------------------------------

    def test_ast_eval_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/example.py",
            "patch": "@@ -0 +1 @@\n+value = eval(data)",
        }])
        self.assertTrue(any(f.category == "AST" and f.severity == "HIGH" for f in findings))

    def test_refcount_leak_fires(self):
        """FIX (point 5): refcount check now fires on inc > dec, not inc >= dec+3."""
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1,3 @@\n+Py_INCREF(a)\n+Py_INCREF(b)\n+return 0;",
        }])
        rc = [f for f in findings if f.category == "REFCOUNT"]
        self.assertEqual(len(rc), 1, "Expected exactly one REFCOUNT finding for 2 INCREF 0 DECREF")
        self.assertEqual(rc[0].severity, "LOW")
        self.assertEqual(rc[0].confidence, "low")
        self.assertIn("leak", rc[0].message.lower())

    def test_refcount_balanced_no_finding(self):
        """Balanced refcounts should not trigger the imbalance check."""
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1,2 @@\n+Py_INCREF(a)\n+Py_DECREF(a)",
        }])
        rc = [f for f in findings if f.category == "REFCOUNT"]
        self.assertEqual(len(rc), 0)

    def test_refcount_is_low_confidence(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1,5 @@\n+Py_INCREF(a)\n+Py_INCREF(b)\n+Py_INCREF(c)\n+return 0;",
        }])
        rc = [f for f in findings if f.category == "REFCOUNT"]
        self.assertTrue(rc, "Expected REFCOUNT finding for 3 INCREF 0 DECREF")
        self.assertEqual(rc[0].severity, "LOW")
        self.assertEqual(rc[0].confidence, "low")

    def test_malloc_finding(self):
        """FIX (point 13): raw malloc should now be flagged."""
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1 @@\n+ptr = malloc(sizeof(Foo));",
        }])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("c-raw-malloc", rule_ids, "malloc() should trigger c-raw-malloc finding")

    def test_deprecation_warning_stacklevel(self):
        """FIX (point 17): DeprecationWarning without stacklevel= should be flagged."""
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/example.py",
            "patch": "@@ -0 +1 @@\n+warnings.warn('old', DeprecationWarning)",
        }])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn(
            "python-deprecation-stacklevel", rule_ids,
            "DeprecationWarning without stacklevel= should be flagged",
        )

    def test_grammar_finding_includes_regen_command(self):
        """FIX (point 18): grammar signal must include exact make commands."""
        findings, _ = triager.analyze_diff([{
            "filename": "Grammar/python.gram",
            "patch": "@@ -0 +1 @@\n+new_rule: foo",
        }])
        grammar = [f for f in findings if f.category == "GRAMMAR"]
        self.assertTrue(grammar, "Expected GRAMMAR finding for Grammar/ change")
        self.assertIn("regen-pegen", grammar[0].message,
                      "Grammar message should include 'regen-pegen'")
        self.assertIn("regen-all", grammar[0].message,
                      "Grammar message should include 'regen-all'")

    def test_free_threading_risk_asyncio(self):
        """FIX (point 12): free-threading risk should fire for asyncio + threading patterns."""
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/asyncio/tasks.py",
            "patch": "@@ -0 +1 @@\n+global _task_registry",
        }])
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertTrue(ft, "Expected FREE-THREADING finding for asyncio global statement")

    def test_no_free_threading_risk_for_docs(self):
        """Doc/ files should not trigger free-threading warnings."""
        findings, _ = triager.analyze_diff([{
            "filename": "Doc/library/asyncio.rst",
            "patch": "@@ -0 +1 @@\n+global variable discussion",
        }])
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertEqual(len(ft), 0)

    # ------------------------------------------------------------------
    # Policy signals
    # ------------------------------------------------------------------

    def test_stale_ordering(self):
        pr = {"state": "open"}
        old = [{"kind": "comment", "bot": False, "date": "2026-01-01T00:00:00Z"}]
        signals = triager.review_signals(pr, old)
        self.assertTrue(any(s == "WARN" for s, _ in signals))

    def test_backport_label_regex_hyphens(self):
        """FIX (point 3): backport labels use hyphens, not spaces."""
        # Real CPython label format
        match = BACKPORT_LABEL_RE.fullmatch("needs-backport-to-3.13")
        self.assertIsNotNone(match, "Hyphenated backport label should match")
        self.assertEqual(match.group(1), "3.13")

        # Old broken format (spaces) should NOT match
        no_match = BACKPORT_LABEL_RE.fullmatch("needs backport to 3.13")
        self.assertIsNone(no_match, "Space-separated label should NOT match")

    def test_backport_signals_extracted(self):
        """FIX (point 3): backport targets list should be populated."""
        pr = {"base": {"ref": "main"}, "state": "open"}
        labels = ["needs-backport-to-3.13", "needs-backport-to-3.12", "type-bug"]
        signals, backports = branch_and_backport_signals(pr, labels)
        self.assertIn("3.13", backports)
        self.assertIn("3.12", backports)

    def test_security_only_branch_3_10_blocked(self):
        """FIX (point 14): 3.10 is security-only; bug-fix PRs should get BLOCK."""
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        labels = ["type-bug"]
        signals, backports = branch_and_backport_signals(pr, labels)
        block_signals = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(block_signals, "3.10 bug-fix PR should produce BLOCK signal")
        self.assertTrue(
            any("security" in msg.lower() for msg in block_signals),
            "BLOCK message should mention security-only status",
        )

    def test_security_only_branch_3_10_no_type_label_warns(self):
        """3.10 PR without a type label should WARN not BLOCK."""
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        labels = []
        signals, _ = branch_and_backport_signals(pr, labels)
        warn_signals = [msg for sig, msg in signals if sig == "WARN"]
        self.assertTrue(warn_signals, "Untyped 3.10 PR should produce WARN signal")

    def test_stable_branch_feature_blocked(self):
        """Feature PRs on 3.13 should be blocked."""
        pr = {"base": {"ref": "3.13"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-feature"])
        self.assertTrue(any(s == "BLOCK" for s, _ in signals))

    def test_disposition_process_blocked(self):
        self.assertEqual(
            disposition([("BLOCK", "reason")], []),
            "PROCESS_BLOCKED",
        )

    # ------------------------------------------------------------------
    # Historical statistics
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Layout table completeness (point 8)
    # ------------------------------------------------------------------

    def test_layout_covers_concurrent(self):
        component, subsystem, _ = triager.classify("Lib/concurrent/futures.py")
        self.assertEqual(subsystem, "concurrent.futures")

    def test_layout_covers_logging(self):
        component, subsystem, _ = triager.classify("Lib/logging/__init__.py")
        self.assertEqual(subsystem, "logging")

    def test_layout_covers_ctypes(self):
        component, subsystem, _ = triager.classify("Modules/_ctypes/ctypes.h")
        self.assertEqual(subsystem, "modules/ctypes")

    def test_layout_covers_email(self):
        component, subsystem, _ = triager.classify("Lib/email/parser.py")
        self.assertEqual(subsystem, "email")

    def test_layout_covers_posixmodule(self):
        component, subsystem, _ = triager.classify("Modules/posixmodule.c")
        self.assertEqual(subsystem, "modules/os")

    def test_layout_covers_socketmodule(self):
        component, subsystem, _ = triager.classify("Modules/socketmodule.c")
        self.assertEqual(subsystem, "modules/socket")


class RulesCompletenessTests(unittest.TestCase):
    """Verify that critical rules are present in the RULES dict."""

    def test_malloc_rule_present(self):
        """FIX (point 13)."""
        self.assertIn("c-raw-malloc", RULES)
        self.assertIn("c-raw-free", RULES)
        self.assertIn("c-raw-realloc", RULES)

    def test_deprecation_stacklevel_rule_present(self):
        """FIX (point 17)."""
        self.assertIn("python-deprecation-stacklevel", RULES)

    def test_md5_sha1_rule_present(self):
        self.assertIn("security-md5-sha1", RULES)

    def test_pycobject_rule_present(self):
        self.assertIn("cpython-pycobject", RULES)


if __name__ == "__main__":
    unittest.main()