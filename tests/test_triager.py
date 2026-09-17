"""
Tests for scripts/analyze.py orchestration layer.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "triager_analyze",
    REPO_ROOT / "scripts" / "analyze.py",
)
triager = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(triager)

from scripts.triager.analyzers import RULES
from scripts.triager.policy import (
    BACKPORT_LABEL_RE,
    LEGACY_BACKPORT_LABEL_RE,
    branch_and_backport_signals,
    disposition,
)


class FakeGitHub:
    def __init__(self, *args, **kwargs):
        pass

    def pull_request_evidence(
        self,
        pr_number,
        *,
        linked_issue_numbers=None,
    ):
        return {
            "evidence": {
                "pr": {
                    "number": pr_number,
                    "title": "Test PR",
                    "body": "",
                    "state": "open",
                    "base": {
                        "ref": "main",
                        "sha": "base-sha",
                    },
                    "head": {
                        "ref": "test-branch",
                        "sha": "head-sha",
                    },
                },
                "files": [],
                "reviews": [],
                "review_comments": [],
                "issue_comments": [],
                "timeline": [],
            },
            "errors": {},
        }


class TriagerTests(unittest.TestCase):
    """Tests for the orchestration layer in analyze.py."""

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
        self.assertIn(
            "https://discuss.python.org/t/example/123",
            discussions,
        )

    def test_added_removed(self):
        added, removed = triager.added_removed(
            "@@ -1 +1 @@\n-old\n+new\n+++ ignored\n--- ignored"
        )
        self.assertEqual(added, "new")
        self.assertEqual(removed, "old")

    def test_ast_eval_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/example.py",
            "patch": "@@ -0 +1 @@\n+value = eval(data)",
        }])
        self.assertTrue(
            any(
                f.category == "AST" and f.severity == "HIGH"
                for f in findings
            )
        )

    def test_refcount_diff_wide_counts_do_not_create_leak_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1,2 @@\n+Py_INCREF(obj);\n+Py_INCREF(obj);",
        }])

        refcount_findings = [
            finding
            for finding in findings
            if finding.category == "REFCOUNT"
        ]

        self.assertEqual(
            refcount_findings,
            [],
            "Diff-wide INCREF/DECREF counts must not imply a refcount leak",
        )

    def test_refcount_balanced_no_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1,2 @@\n+Py_INCREF(a)\n+Py_DECREF(a)",
        }])
        rc = [f for f in findings if f.category == "REFCOUNT"]
        self.assertEqual(len(rc), 0)

    def test_refcount_diff_wide_counts_do_not_create_low_confidence_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": (
                "@@ -0 +1,3 @@\n"
                "+Py_INCREF(obj);\n"
                "+Py_INCREF(obj);\n"
                "+Py_INCREF(obj);"
            ),
        }])

        refcount_findings = [
            finding
            for finding in findings
            if finding.category == "REFCOUNT"
        ]

        self.assertEqual(
            refcount_findings,
            [],
            "Diff-wide refcount operation counts must not create a finding",
        )

    def test_malloc_finding(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Objects/example.c",
            "patch": "@@ -0 +1 @@\n+ptr = malloc(sizeof(Foo));",
        }])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn(
            "c-raw-malloc",
            rule_ids,
            "malloc() should trigger c-raw-malloc finding",
        )

    def test_deprecation_warning_stacklevel(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/example.py",
            "patch": "@@ -0 +1 @@\n+warnings.warn('old', DeprecationWarning)",
        }])
        rule_ids = [f.rule_id for f in findings]
        self.assertIn(
            "python-deprecation-stacklevel",
            rule_ids,
            "DeprecationWarning without stacklevel= should be flagged",
        )

    def test_grammar_finding_includes_regen_command(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Grammar/python.gram",
            "patch": "@@ -0 +1 @@\n+new_rule: foo",
        }])
        grammar = [f for f in findings if f.category == "GRAMMAR"]
        self.assertTrue(
            grammar,
            "Expected GRAMMAR finding for Grammar/ change",
        )
        self.assertIn("regen-pegen", grammar[0].message)
        self.assertIn("regen-all", grammar[0].message)

    def test_free_threading_risk_asyncio(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Lib/asyncio/tasks.py",
            "patch": "@@ -0 +1 @@\n+global _task_registry",
        }])
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertTrue(
            ft,
            "Expected FREE-THREADING finding for asyncio global statement",
        )

    def test_no_free_threading_risk_for_docs(self):
        findings, _ = triager.analyze_diff([{
            "filename": "Doc/library/asyncio.rst",
            "patch": "@@ -0 +1 @@\n+global variable discussion",
        }])
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertEqual(len(ft), 0)

    def test_stale_ordering(self):
        pr = {"state": "open"}
        old = [{
            "kind": "comment",
            "bot": False,
            "date": "2026-01-01T00:00:00Z",
        }]
        signals = triager.review_signals(pr, old)
        self.assertTrue(any(s == "WARN" for s, _ in signals))

    def test_backport_label_regex(self):
        match = BACKPORT_LABEL_RE.fullmatch("needs backport to 3.13")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "3.13")

        no_match = BACKPORT_LABEL_RE.fullmatch("needs-backport-to-3.13")
        self.assertIsNone(no_match)

    def test_legacy_backport_label_regex(self):
        match = LEGACY_BACKPORT_LABEL_RE.fullmatch(
            "needs-backport-to-3.13"
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "3.13")

    def test_backport_signals_extracted(self):
        pr = {"base": {"ref": "main"}, "state": "open"}
        labels = [
            "needs backport to 3.13",
            "needs backport to 3.12",
            "type-bug",
        ]
        signals, backports = branch_and_backport_signals(pr, labels)
        self.assertIn("3.13", backports)
        self.assertIn("3.12", backports)

    def test_security_only_branch_3_10_blocked(self):
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        labels = ["type-bug"]
        signals, backports = branch_and_backport_signals(pr, labels)
        block_signals = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(
            block_signals,
            "3.10 bug-fix PR should produce BLOCK signal",
        )
        self.assertTrue(
            any("security" in msg.lower() for msg in block_signals),
            "BLOCK message should mention security-only status",
        )

    def test_security_only_branch_3_10_no_type_label_warns(self):
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        labels = []
        signals, _ = branch_and_backport_signals(pr, labels)
        warn_signals = [msg for sig, msg in signals if sig == "WARN"]
        self.assertTrue(
            warn_signals,
            "Untyped 3.10 PR should produce WARN signal",
        )

    def test_stable_branch_feature_blocked(self):
        pr = {"base": {"ref": "3.13"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-feature"])
        self.assertTrue(any(s == "BLOCK" for s, _ in signals))

    def test_disposition_process_blocked(self):
        self.assertEqual(
            disposition([("BLOCK", "reason")], []),
            "PROCESS_BLOCKED",
        )

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

    def test_layout_covers_concurrent(self):
        component, subsystem, _ = triager.classify(
            "Lib/concurrent/futures.py"
        )
        self.assertEqual(subsystem, "concurrent.futures")

    def test_layout_covers_logging(self):
        component, subsystem, _ = triager.classify(
            "Lib/logging/__init__.py"
        )
        self.assertEqual(subsystem, "logging")

    def test_layout_covers_ctypes(self):
        component, subsystem, _ = triager.classify(
            "Modules/_ctypes/ctypes.h"
        )
        self.assertEqual(subsystem, "modules/ctypes")

    def test_layout_covers_email(self):
        component, subsystem, _ = triager.classify(
            "Lib/email/parser.py"
        )
        self.assertEqual(subsystem, "email")

    def test_layout_covers_posixmodule(self):
        component, subsystem, _ = triager.classify(
            "Modules/posixmodule.c"
        )
        self.assertEqual(subsystem, "modules/os")

    def test_layout_covers_socketmodule(self):
        component, subsystem, _ = triager.classify(
            "Modules/socketmodule.c"
        )
        self.assertEqual(subsystem, "modules/socket")

    def test_ai_does_not_receive_anthropic_api_key_for_gemini(self):
        captured = {}

        def fake_synthesize(report, **kwargs):
            captured["report"] = report
            captured["kwargs"] = kwargs
            return {
                "triage": "READY_FOR_MAINTAINER_REVIEW",
                "confidence": 4,
                "summary": "Gemini test response",
                "top_risks": [],
                "review_questions": [],
                "expert_routing": [],
                "process_assessment": (
                    "No additional process concern is established."
                ),
                "test_assessment": "Tests are present.",
                "backport_assessment": (
                    "No backport conclusion is established."
                ),
                "uncertainties": [],
            }

        original = triager.ai_synthesize
        try:
            triager.ai_synthesize = fake_synthesize

            with patch.object(
                triager,
                "GITHUB_TOKEN",
                "test-token",
            ), patch.object(
                triager,
                "REPO",
                "python/cpython",
            ), patch.object(
                triager,
                "GitHub",
                FakeGitHub,
            ), patch(
                "sys.argv",
                [
                    "analyze.py",
                    "123",
                    "--ai",
                    "--ai-provider",
                    "gemini",
                ],
            ):
                triager.main()
        finally:
            triager.ai_synthesize = original

        self.assertEqual(
            captured["kwargs"],
            {
                "provider": "gemini",
                "model": None,
                "timeout": None,
            },
        )
        self.assertNotIn("api_key", captured["kwargs"])

    def test_ai_receives_copy_without_prior_ai_fields(self):
        captured = {}
        def fake_synthesize(report, **kwargs):
            captured["report"] = report
            return {"triage": "READY_FOR_MAINTAINER_REVIEW", "confidence": 3, "summary": "ok", "top_risks": [], "review_questions": [], "expert_routing": [], "process_assessment": "ok", "test_assessment": "ok", "backport_assessment": "ok", "uncertainties": []}
        original = triager.ai_synthesize
        try:
            triager.ai_synthesize = fake_synthesize
            with patch.object(triager, "GITHUB_TOKEN", "test-token"), patch.object(triager, "REPO", "python/cpython"), patch.object(triager, "GitHub", FakeGitHub), patch("sys.argv", ["analyze.py", "123", "--ai", "--ai-provider", "mock"]):
                triager.main()
        finally:
            triager.ai_synthesize = original
        self.assertNotIn("ai_synthesis", captured["report"])
        self.assertNotIn("ai_error", captured["report"])

    def test_ai_error_is_displayed_in_normal_output(self):
        original_argv = sys.argv
        sys.argv = [
            "analyze.py",
            "1",
            "--ai",
            "--ai-provider",
            "gemini",
        ]

        evidence = {
            "pr": {
                "base": {
                    "sha": "base-sha",
                    "ref": "main",
                },
                "title": "Test PR",
                "body": "",
            },
            "timeline": [],
            "files": [],
            "codeowners_path": None,
            "codeowners_text": "",
        }

        try:
            with patch.object(
                triager,
                "fetch_pr_evidence",
                return_value=evidence,
            ), patch.object(
                triager,
                "fetch_linked_issues",
                return_value=([], [], []),
            ), patch.object(
                triager,
                "make_report",
                return_value={
                    "triage": "READY_FOR_MAINTAINER_REVIEW",
                    "findings": [],
                },
            ), patch.object(
                triager,
                "parse_codeowners",
                return_value=[],
            ), patch.object(
                triager,
                "resolve_codeowners",
                return_value=[],
            ), patch.object(
                triager,
                "ai_synthesize",
                side_effect=triager.AISynthesisError(
                    "Gemini API returned HTTP 503: unavailable"
                ),
            ), patch.object(
                triager,
                "print_report",
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    triager.main()
        finally:
            sys.argv = original_argv

        rendered = output.getvalue()

        self.assertIn("AI synthesis: unavailable", rendered)
        self.assertIn(
            "Reason: Gemini API returned HTTP 503: unavailable",
            rendered,
        )


class RulesCompletenessTests(unittest.TestCase):
    """Verify that critical rules are present in the RULES dict."""

    def test_malloc_rule_present(self):
        self.assertIn("c-raw-malloc", RULES)
        self.assertIn("c-raw-free", RULES)
        self.assertIn("c-raw-realloc", RULES)

    def test_deprecation_stacklevel_rule_present(self):
        self.assertIn("python-deprecation-stacklevel", RULES)

    def test_md5_sha1_rule_present(self):
        self.assertIn("security-md5-sha1", RULES)

    def test_pycobject_rule_present(self):
        self.assertIn("cpython-pycobject", RULES)


class CIFreshnessTests(unittest.TestCase):
    """Verify CI evidence is independently validated against the PR's
    current head SHA rather than trusted purely from request parameters
    (see the "CI evidence tied to a head SHA" audit finding)."""

    def _pr(self, head_sha="abc123"):
        return {"head": {"sha": head_sha}}

    def test_fresh_when_all_check_runs_match_head(self):
        evidence = {
            "check_runs": {
                "check_runs": [
                    {"status": "completed", "conclusion": "success", "head_sha": "abc123"},
                    {"status": "completed", "conclusion": "success", "head_sha": "abc123"},
                ]
            },
            "statuses": [],
        }
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertTrue(checks["ci_fresh"])
        self.assertEqual(checks["pr_head_sha"], "abc123")
        self.assertNotIn("stale_check_shas", checks)

    def test_stale_when_a_check_run_belongs_to_a_different_sha(self):
        evidence = {
            "check_runs": {
                "check_runs": [
                    {"status": "completed", "conclusion": "success", "head_sha": "abc123"},
                    {"status": "completed", "conclusion": "success", "head_sha": "def456"},
                ]
            },
            "statuses": [],
        }
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertFalse(checks["ci_fresh"])
        self.assertEqual(checks["stale_check_shas"], ["def456"])

    def test_unknown_when_check_run_has_no_head_sha(self):
        evidence = {"check_runs": {"check_runs": [{"status": "completed", "conclusion": "success"}]}, "statuses": []}
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertEqual(checks["ci_freshness"], "unknown")
        self.assertFalse(checks["ci_fresh"])

    def test_legacy_status_failure_is_normalized_and_not_blocked_without_requiredness(self):
        evidence = {"check_runs": {"check_runs": [{"status": "completed", "conclusion": "success", "head_sha": "abc123"}]}, "statuses": {"state": "failure", "sha": "abc123", "statuses": []}}
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertEqual(checks["summary"]["legacy_status"], "failure")
        signals = triager.mergeability_signals(self._pr(), checks)
        self.assertFalse(any(level == "BLOCK" for level, _ in signals))
        self.assertTrue(any("Legacy commit status" in msg for _, msg in signals))

    def test_legacy_status_list_is_normalized(self):
        evidence = {
            "check_runs": {"check_runs": [{"status": "completed", "conclusion": "success", "head_sha": "abc123"}]},
            "statuses": [{"state": "failure", "sha": "abc123", "context": "legacy"}],
        }
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertEqual(checks["summary"]["legacy_status"], "failure")
        self.assertEqual(checks["summary"]["legacy_status_freshness"], "fresh")

    def test_mixed_status_shas_are_unverified(self):
        evidence = {
            "check_runs": {"check_runs": [{"status": "completed", "conclusion": "success", "head_sha": "abc123"}]},
            "statuses": [
                {"state": "success", "sha": "abc123"},
                {"state": "success", "sha": "def456"},
            ],
        }
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertEqual(checks["summary"]["legacy_status_freshness"], "unknown")

    def test_required_failure_blocks(self):
        evidence = {"check_runs": {"check_runs": [{"status": "completed", "conclusion": "failure", "head_sha": "abc123", "name": "required-test", "required": True}]}, "statuses": []}
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        signals = triager.mergeability_signals(self._pr(), checks)
        self.assertTrue(any(level == "BLOCK" for level, _ in signals))

    def test_freshness_unknown_when_no_check_runs(self):
        evidence = {"check_runs": {"check_runs": []}, "statuses": []}
        checks = triager.build_checks(None, self._pr("abc123"), evidence)
        self.assertIsNone(checks["ci_fresh"])

    def test_mergeability_signals_warn_on_stale_ci(self):
        checks = {
            "available": True,
            "pr_head_sha": "abc123",
            "ci_fresh": False,
            "stale_check_shas": ["def456"],
            "check_runs": [],
            "summary": {"failures": 0},
        }
        signals = triager.mergeability_signals(self._pr("abc123"), checks)
        self.assertTrue(any("STALE CI" in msg for _level, msg in signals))


class RequiredCheckAbsenceTests(unittest.TestCase):
    """Verify authoritative required checks are not silently treated as optional."""

    def _pr(self, head_sha="abc123"):
        return {"head": {"sha": head_sha}, "base": {"ref": "main"}}

    def _policy(self, status="complete", name="required-test", app_id=None):
        return {
            "status": status,
            "required_checks": [{
                "name": name,
                "integration_id": app_id,
            }],
        }

    def _run(self, **overrides):
        run = {
            "name": "required-test",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "abc123",
        }
        run.update(overrides)
        return run

    def test_required_check_missing_on_current_head_blocks(self):
        evidence = {
            "check_runs": {"check_runs": []},
            "statuses": [],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_missing"], 1)
        signals = triager.mergeability_signals(self._pr(), checks)
        self.assertTrue(any(level == "BLOCK" and "no current-head result" in msg
                            for level, msg in signals))

    def test_stale_only_required_result_blocks_as_stale(self):
        evidence = {
            "check_runs": {"check_runs": [self._run(head_sha="oldsha", conclusion="success")]},
            "statuses": [],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_stale"], 1)
        self.assertEqual(checks["summary"]["required_missing"], 0)

    def test_current_required_success_satisfies_requirement(self):
        evidence = {
            "check_runs": {"check_runs": [self._run()]},
            "statuses": [],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_satisfied"], 1)
        self.assertEqual(checks["summary"]["required_missing"], 0)

    def test_authoritative_policy_overrides_contradictory_run_required_flag(self):
        evidence = {
            "check_runs": {
                "check_runs": [{
                    "name": "required-test",
                    "status": "completed",
                    "conclusion": "failure",
                    "head_sha": "abc123",
                    "required": False,
                }]
            },
            "statuses": [],
            "required_checks": self._policy(),
        }

        checks = triager.build_checks(
            None,
            self._pr(),
            evidence,
        )

        self.assertEqual(
            checks["check_runs"][0]["requiredness"],
            "required",
        )
        self.assertEqual(
            checks["summary"]["required_failures"],
            1,
        )
        self.assertTrue(
            any(
                level == "BLOCK"
                for level, _ in triager.mergeability_signals(
                    self._pr(),
                    checks,
                )
            )
        )

    def test_newer_pending_rerun_supersedes_older_success(self):
        evidence = {
            "check_runs": {
                "check_runs": [
                    {
                        "id": 100,
                        "name": "required-test",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": "abc123",
                        "started_at": "2026-09-15T10:00:00Z",
                        "completed_at": "2026-09-15T10:05:00Z",
                    },
                    {
                        "id": 101,
                        "name": "required-test",
                        "status": "in_progress",
                        "conclusion": None,
                        "head_sha": "abc123",
                        "started_at": "2026-09-15T10:10:00Z",
                        "completed_at": None,
                    },
                ]
            },
            "statuses": [],
            "required_checks": self._policy(),
        }

        checks = triager.build_checks(
            None,
            self._pr(),
            evidence,
        )

        self.assertEqual(
            checks["summary"]["required_pending"],
            1,
        )
        self.assertEqual(
            checks["summary"]["required_satisfied"],
            0,
        )

        signals = triager.mergeability_signals(
            self._pr(),
            checks,
        )

        self.assertTrue(
            any(
                level == "WARN"
                and "required CI check(s) are incomplete" in message
                for level, message in signals
            )
        )

    def test_latest_required_run_is_not_selected_by_response_order(self):
        evidence = {
            "check_runs": {
                "check_runs": [
                    {
                        "id": 201,
                        "name": "required-test",
                        "status": "in_progress",
                        "conclusion": None,
                        "head_sha": "abc123",
                        "started_at": "2026-09-15T10:10:00Z",
                        "completed_at": None,
                    },
                    {
                        "id": 200,
                        "name": "required-test",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": "abc123",
                        "started_at": "2026-09-15T10:00:00Z",
                        "completed_at": "2026-09-15T10:05:00Z",
                    },
                ]
            },
            "statuses": [],
            "required_checks": self._policy(),
        }

        checks = triager.build_checks(
            None,
            self._pr(),
            evidence,
        )

        self.assertEqual(
            checks["summary"]["required_pending"],
            1,
        )
        self.assertEqual(
            checks["summary"]["required_satisfied"],
            0,
        )

    def test_required_result_without_head_sha_is_unknown_not_missing(self):
        evidence = {
            "check_runs": {"check_runs": [{
                "name": "required-test",
                "status": "completed",
                "conclusion": "success",
            }]},
            "statuses": [],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_unknown"], 1)
        self.assertEqual(checks["summary"]["required_missing"], 0)

    def test_current_required_pending_warns(self):
        evidence = {
            "check_runs": {"check_runs": [
                self._run(status="in_progress", conclusion=None),
            ]},
            "statuses": [],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_pending"], 1)
        self.assertTrue(any(level == "WARN" for level, _ in
                            triager.mergeability_signals(self._pr(), checks)))

    def test_required_cancelled_blocks(self):
        evidence = {
            "check_runs": {"check_runs": [
                self._run(conclusion="cancelled"),
            ]},
            "statuses": [],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_cancelled"], 1)
        self.assertTrue(any(level == "BLOCK" and "cancelled" in msg
                            for level, msg in triager.mergeability_signals(self._pr(), checks)))

    def test_required_app_identity_without_run_app_is_unknown_not_missing(self):
        evidence = {
            "check_runs": {"check_runs": [self._run()]},
            "statuses": [],
            "required_checks": self._policy(app_id=12345),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_unknown"], 1)
        self.assertEqual(checks["summary"]["required_missing"], 0)

    def test_optional_missing_does_not_block(self):
        evidence = {
            "check_runs": {"check_runs": []},
            "statuses": [],
            "required_checks": {
                "status": "complete",
                "required_checks": [{"name": "required-test", "integration_id": None}],
            },
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_missing"], 1)
        # A missing optional check is never synthesized as a requirement.
        self.assertFalse(any("optional" in msg.lower() and level == "BLOCK"
                             for level, msg in triager.mergeability_signals(self._pr(), checks)))

    def test_current_legacy_status_can_satisfy_context_requirement(self):
        evidence = {
            "check_runs": {"check_runs": []},
            "statuses": [{
                "state": "success",
                "sha": "abc123",
                "context": "required-test",
            }],
            "required_checks": self._policy(),
        }
        checks = triager.build_checks(None, self._pr(), evidence)
        self.assertEqual(checks["summary"]["required_satisfied"], 1)
        self.assertEqual(checks["summary"]["required_missing"], 0)


if __name__ == "__main__":
    unittest.main()
class ReviewStateTests(unittest.TestCase):
    def test_old_approval_is_reported_as_stale_candidate_not_invalidated(self):
        state = triager.policy_build_review_state(
            {"state": "open", "head": {"sha": "new"}},
            reviews=[{
                "id": 1,
                "user": {"login": "alice"},
                "state": "APPROVED",
                "submitted_at": "2026-09-10T00:00:00Z",
                "commit_id": "old",
            }],
            timeline=[],
            review_threads={"status": "complete", "threads": []},
        )
        self.assertEqual(state["effective_approval_count"], 1)
        self.assertEqual(state["approval_freshness"], "stale_candidate")
        self.assertEqual(state["stale_approval_candidates"][0]["head_sha"], "new")

    def test_later_changes_requested_supersedes_same_reviewer_approval(self):
        state = triager.policy_build_review_state(
            {"state": "open", "head": {"sha": "head"}},
            reviews=[
                {"id": 1, "user": {"login": "alice"}, "state": "APPROVED", "submitted_at": "2026-09-10T00:00:00Z", "commit_id": "head"},
                {"id": 2, "user": {"login": "alice"}, "state": "CHANGES_REQUESTED", "submitted_at": "2026-09-11T00:00:00Z", "commit_id": "head"},
            ],
            timeline=[],
            review_threads={"status": "complete", "threads": []},
        )
        self.assertEqual(state["effective_approval_count"], 0)
        self.assertEqual(state["effective_changes_requested_count"], 1)

    def test_unresolved_threads_are_first_class_state(self):
        state = triager.policy_build_review_state(
            {"state": "open", "head": {"sha": "head"}},
            reviews=[],
            timeline=[],
            review_threads={
                "status": "complete",
                "threads": [
                    {"id": "1", "is_resolved": True, "created_at": "2026-09-10T00:00:00Z"},
                    {"id": "2", "is_resolved": False, "created_at": "2026-09-11T00:00:00Z", "author": "alice"},
                ],
            },
        )
        self.assertEqual(state["resolved_threads"], 1)
        self.assertEqual(state["unresolved_threads"], 1)
        self.assertEqual(state["latest_unresolved_thread"]["id"], "2")

    def test_missing_thread_evidence_is_not_zero_threads(self):
        state = triager.policy_build_review_state(
            {"state": "open", "head": {"sha": "head"}},
            reviews=[],
            timeline=[],
            review_threads={"status": "unavailable", "threads": []},
        )
        self.assertEqual(state["unresolved_threads"], 0)
        self.assertEqual(state["review_threads_status"], "unavailable")
        signals = triager.review_signals(
            {"state": "open", "head": {"sha": "head"}},
            [],
            reviews=[],
            review_threads={"status": "unavailable", "threads": []},
        )
        self.assertTrue(any(level == "WARN" and "thread" in message.lower() for level, message in signals))

    def test_author_followup_after_changes_request_is_detected(self):
        pr = {"state": "open", "head": {"sha": "head"}, "user": {"login": "author"}}
        reviews = [{
            "id": 2,
            "user": {"login": "reviewer"},
            "state": "CHANGES_REQUESTED",
            "submitted_at": "2026-09-10T00:00:00Z",
            "commit_id": "head",
        }]
        timeline = [{
            "kind": "committed",
            "bot": False,
            "login": "author",
            "date": "2026-09-11T00:00:00Z",
        }]
        state = triager.policy_build_review_state(
            pr, reviews=reviews, timeline=timeline,
            review_threads={"status": "complete", "threads": []},
        )
        self.assertTrue(state["author_followup_after_changes_requested"])

    def test_process_signals_propagates_review_thread_blocking_signal(self):
        signals, _ = triager.policy_process_signals(
            {"state": "open", "title": "gh-123: review state", "base": {"ref": "main"}},
            [],
            [],
            [],
            {},
            reviews=[{
                "id": 1,
                "user": {"login": "alice"},
                "state": "APPROVED",
                "submitted_at": "2026-09-10T00:00:00Z",
                "commit_id": "head",
            }],
            review_threads={
                "status": "complete",
                "threads": [{"id": "thread-1", "is_resolved": False, "created_at": "2026-09-11T00:00:00Z"}],
            },
        )
        self.assertTrue(
            any(level == "WARN" and "unresolved review thread" in message.lower() for level, message in signals)
        )
