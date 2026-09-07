"""
Tests for scripts/triager/policy.py.

These tests validate the current deterministic CPython triage policy.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.triager.policy import (
    BACKPORT_LABEL_RE,
    DEFAULT_BRANCH_POLICIES,
    LEGACY_BACKPORT_LABEL_RE,
    SECURITY_ONLY_BRANCHES,
    branch_and_backport_signals,
    disposition,
    file_signals,
    process_signals,
    review_signals,
)


def messages_for(
    signals: list[tuple[str, str]],
    severity: str,
) -> list[str]:
    return [
        message
        for signal, message in signals
        if signal == severity
    ]


def make_pr(
    *,
    branch: str = "main",
    state: str = "open",
    title: str = "gh-123: test",
    additions: int = 1,
    deletions: int = 0,
    changed_files: int = 1,
    **extra,
) -> dict:
    pr = {
        "base": {"ref": branch},
        "state": state,
        "title": title,
        "additions": additions,
        "deletions": deletions,
        "changed_files": changed_files,
    }
    pr.update(extra)
    return pr


class BackportLabelRegexTests(unittest.TestCase):
    def test_current_space_separated_format_matches(self):
        for branch in ("3.10", "3.11", "3.12", "3.13", "3.14", "3.15"):
            label = f"needs backport to {branch}"

            match = BACKPORT_LABEL_RE.fullmatch(label)

            self.assertIsNotNone(
                match,
                f"{label!r} should match the current CPython label format",
            )
            self.assertEqual(match.group(1), branch)

    def test_hyphenated_format_does_not_match_current_regex(self):
        for branch in ("3.12", "3.13", "3.14"):
            label = f"needs-backport-to-{branch}"

            match = BACKPORT_LABEL_RE.fullmatch(label)

            self.assertIsNone(
                match,
                f"Legacy {label!r} must not be treated as current policy",
            )

    def test_legacy_regex_detects_old_project_format(self):
        for branch in ("3.12", "3.13", "3.14"):
            label = f"needs-backport-to-{branch}"

            match = LEGACY_BACKPORT_LABEL_RE.fullmatch(label)

            self.assertIsNotNone(match)
            self.assertEqual(match.group(1), branch)

    def test_current_format_is_case_insensitive(self):
        match = BACKPORT_LABEL_RE.fullmatch(
            "NEEDS BACKPORT TO 3.13",
        )

        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "3.13")

    def test_unrelated_labels_do_not_match(self):
        invalid_labels = [
            "needs backport",
            "needs backport to",
            "needs backport to 3",
            "needs backport to 3.x",
            "needs backport to 3.13 extra",
            "backport to 3.13",
        ]

        for label in invalid_labels:
            with self.subTest(label=label):
                self.assertIsNone(BACKPORT_LABEL_RE.fullmatch(label))


class BranchPolicyTests(unittest.TestCase):
    def test_security_branches_are_derived_from_policy_snapshot(self):
        expected = {
            branch
            for branch, status in DEFAULT_BRANCH_POLICIES.items()
            if status == "security"
        }

        self.assertEqual(
            SECURITY_ONLY_BRANCHES,
            frozenset(expected),
        )

    def test_current_security_branches_include_3_10_3_11_3_12(self):
        for branch in ("3.10", "3.11", "3.12"):
            with self.subTest(branch=branch):
                self.assertIn(branch, SECURITY_ONLY_BRANCHES)

    def test_bug_fix_on_security_branch_is_blocked(self):
        for branch in ("3.10", "3.11", "3.12"):
            with self.subTest(branch=branch):
                pr = make_pr(branch=branch)

                signals, _ = branch_and_backport_signals(
                    pr,
                    ["type-bug"],
                )

                block_messages = messages_for(signals, "BLOCK")

                self.assertTrue(
                    block_messages,
                    f"Bug fix on {branch} should be blocked",
                )
                self.assertTrue(
                    any(
                        "security" in message.lower()
                        for message in block_messages
                    )
                )

    def test_feature_on_security_branch_is_blocked(self):
        for branch in ("3.10", "3.11", "3.12"):
            with self.subTest(branch=branch):
                pr = make_pr(branch=branch)

                signals, _ = branch_and_backport_signals(
                    pr,
                    ["type-feature"],
                )

                self.assertTrue(messages_for(signals, "BLOCK"))

    def test_unlabelled_security_branch_warns_not_blocks(self):
        pr = make_pr(branch="3.10")

        signals, _ = branch_and_backport_signals(pr, [])

        self.assertTrue(messages_for(signals, "WARN"))
        self.assertFalse(messages_for(signals, "BLOCK"))

    def test_security_label_on_security_branch_is_ok(self):
        for branch in ("3.10", "3.11", "3.12"):
            with self.subTest(branch=branch):
                pr = make_pr(branch=branch)

                signals, _ = branch_and_backport_signals(
                    pr,
                    ["type-security"],
                )

                self.assertTrue(messages_for(signals, "OK"))
                self.assertFalse(messages_for(signals, "BLOCK"))

    def test_feature_on_bugfix_branch_is_blocked(self):
        for branch in ("3.13", "3.14"):
            with self.subTest(branch=branch):
                pr = make_pr(branch=branch)

                signals, _ = branch_and_backport_signals(
                    pr,
                    ["type-feature"],
                )

                block_messages = messages_for(signals, "BLOCK")

                self.assertTrue(block_messages)
                self.assertTrue(
                    any(branch in message for message in block_messages)
                )

    def test_bug_fix_on_bugfix_branch_is_not_blocked(self):
        for branch in ("3.13", "3.14"):
            with self.subTest(branch=branch):
                pr = make_pr(branch=branch)

                signals, _ = branch_and_backport_signals(
                    pr,
                    ["type-bug"],
                )

                self.assertFalse(messages_for(signals, "BLOCK"))

    def test_feature_on_prerelease_branch_is_flagged(self):
        pr = make_pr(branch="3.15")

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-feature"],
        )

        block_messages = messages_for(signals, "BLOCK")

        self.assertTrue(block_messages)
        self.assertTrue(
            any("prerelease" in message.lower() for message in block_messages)
        )

    def test_bug_fix_on_prerelease_branch_is_not_blocked(self):
        pr = make_pr(branch="3.15")

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-bug"],
        )

        self.assertFalse(messages_for(signals, "BLOCK"))

    def test_main_is_feature_branch(self):
        pr = make_pr(branch="main")

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-feature"],
        )

        self.assertTrue(messages_for(signals, "OK"))
        self.assertFalse(messages_for(signals, "BLOCK"))

    def test_eol_branch_is_blocked(self):
        pr = make_pr(branch="3.9")

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-bug"],
        )

        block_messages = messages_for(signals, "BLOCK")

        self.assertTrue(block_messages)
        self.assertTrue(
            any(
                "end-of-life" in message.lower()
                for message in block_messages
            )
        )

    def test_unknown_maintenance_branch_warns(self):
        pr = make_pr(branch="3.99")

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-bug"],
        )

        warn_messages = messages_for(signals, "WARN")

        self.assertTrue(warn_messages)
        self.assertFalse(messages_for(signals, "BLOCK"))

    def test_dynamic_branch_policy_overrides_fallback_snapshot(self):
        pr = make_pr(branch="3.14")

        custom_policy = {
            "3.14": "security",
        }

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-bug"],
            branch_policies=custom_policy,
        )

        block_messages = messages_for(signals, "BLOCK")

        self.assertTrue(block_messages)
        self.assertTrue(
            any("security" in message.lower() for message in block_messages)
        )

    def test_dynamic_policy_accepts_nested_status_mapping(self):
        pr = make_pr(branch="3.14")

        custom_policy = {
            "3.14": {
                "status": "security",
                "source": "test",
            }
        }

        signals, _ = branch_and_backport_signals(
            pr,
            ["type-security"],
            branch_policies=custom_policy,
        )

        self.assertTrue(messages_for(signals, "OK"))
        self.assertFalse(messages_for(signals, "BLOCK"))


class BackportSignalExtractionTests(unittest.TestCase):
    def test_multiple_current_backport_labels(self):
        pr = make_pr()

        labels = [
            "needs backport to 3.13",
            "needs backport to 3.12",
            "type-bug",
        ]

        signals, backports = branch_and_backport_signals(
            pr,
            labels,
        )

        self.assertIn("3.13", backports)
        self.assertIn("3.12", backports)

    def test_duplicate_backport_labels_are_deduplicated(self):
        pr = make_pr()

        labels = [
            "needs backport to 3.13",
            "NEEDS BACKPORT TO 3.13",
        ]

        signals, backports = branch_and_backport_signals(
            pr,
            labels,
        )

        self.assertEqual(backports, ["3.13"])

    def test_no_backport_labels_returns_empty_list(self):
        pr = make_pr()

        _, backports = branch_and_backport_signals(
            pr,
            ["type-bug"],
        )

        self.assertEqual(backports, [])

    def test_current_backport_info_signal_is_emitted(self):
        pr = make_pr()

        signals, _ = branch_and_backport_signals(
            pr,
            ["needs backport to 3.13"],
        )

        info_messages = messages_for(signals, "INFO")

        self.assertTrue(
            any("3.13" in message for message in info_messages)
        )

    def test_legacy_backport_label_produces_warning(self):
        pr = make_pr()

        signals, backports = branch_and_backport_signals(
            pr,
            ["needs-backport-to-3.13"],
        )

        warn_messages = messages_for(signals, "WARN")

        self.assertTrue(warn_messages)
        self.assertTrue(
            any("legacy" in message.lower() for message in warn_messages)
        )
        self.assertEqual(backports, [])


class ReviewSignalTests(unittest.TestCase):
    def test_approval_produces_ok(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "review",
                "state": "APPROVED",
                "bot": False,
                "date": "2026-08-31T00:00:00Z",
                "login": "alice",
            },
        ]

        signals = review_signals(pr, timeline)

        self.assertTrue(messages_for(signals, "OK"))

    def test_approval_state_is_case_insensitive(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "review",
                "state": "approved",
                "bot": False,
                "date": "2026-08-31T00:00:00Z",
                "login": "alice",
            },
        ]

        signals = review_signals(pr, timeline)

        self.assertTrue(messages_for(signals, "OK"))

    def test_changes_requested_without_followup_warns(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "review",
                "state": "CHANGES_REQUESTED",
                "bot": False,
                "date": "2026-08-31T00:00:00Z",
                "login": "alice",
            },
        ]

        signals = review_signals(pr, timeline)

        self.assertTrue(messages_for(signals, "WARN"))

    def test_changes_requested_with_followup_produces_info(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "review",
                "state": "CHANGES_REQUESTED",
                "bot": False,
                "date": "2026-08-30T00:00:00Z",
                "login": "alice",
            },
            {
                "kind": "comment",
                "state": None,
                "bot": False,
                "date": "2026-08-31T00:00:00Z",
                "login": "author",
            },
        ]

        signals = review_signals(pr, timeline)

        info_messages = messages_for(signals, "INFO")
        warn_messages = messages_for(signals, "WARN")

        self.assertTrue(info_messages)
        self.assertFalse(
            any(
                "changes-requested" in message.lower()
                for message in warn_messages
            )
        )

    def test_bot_events_are_ignored(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "review",
                "state": "APPROVED",
                "bot": True,
                "date": "2026-08-31T00:00:00Z",
            },
        ]

        signals = review_signals(pr, timeline)

        self.assertFalse(messages_for(signals, "OK"))

    def test_stale_human_activity_produces_warn(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "comment",
                "bot": False,
                "date": "2024-01-01T00:00:00Z",
            },
        ]

        signals = review_signals(pr, timeline)

        warn_messages = messages_for(signals, "WARN")

        self.assertTrue(warn_messages)
        self.assertTrue(
            any("days" in message for message in warn_messages)
        )

    def test_recent_human_activity_does_not_produce_stale_warning(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "comment",
                "bot": False,
                "date": "2026-08-31T00:00:00Z",
            },
        ]

        signals = review_signals(pr, timeline)

        stale_messages = [
            message
            for message in messages_for(signals, "WARN")
            if "human activity" in message.lower()
        ]

        self.assertFalse(stale_messages)

    def test_updated_at_is_used_when_timeline_has_no_human_events(self):
        pr = make_pr(
            updated_at="2024-01-01T00:00:00Z",
        )

        signals = review_signals(pr, [])

        warn_messages = messages_for(signals, "WARN")

        self.assertTrue(warn_messages)
        self.assertTrue(
            any("updated" in message.lower() for message in warn_messages)
        )

    def test_naive_iso_timestamp_is_supported(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "comment",
                "bot": False,
                "date": "2024-01-01T00:00:00",
            },
        ]

        signals = review_signals(pr, timeline)

        self.assertTrue(messages_for(signals, "WARN"))

    def test_malformed_date_does_not_crash(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "comment",
                "bot": False,
                "date": "not-a-date",
            },
        ]

        signals = review_signals(pr, timeline)

        self.assertIsInstance(signals, list)


class FileSignalsTests(unittest.TestCase):
    def test_news_file_detected(self):
        files = [
            {
                "filename": "Misc/NEWS.d/next/Library/gh-123.rst",
            }
        ]

        names, tests, news, docs = file_signals(files)

        self.assertEqual(
            names,
            ["Misc/NEWS.d/next/Library/gh-123.rst"],
        )
        self.assertEqual(len(news), 1)
        self.assertEqual(tests, [])
        self.assertEqual(docs, [])

    def test_test_file_detected(self):
        files = [
            {"filename": "Lib/test/test_asyncio.py"},
        ]

        names, tests, news, docs = file_signals(files)

        self.assertEqual(len(names), 1)
        self.assertEqual(len(tests), 1)
        self.assertEqual(news, [])
        self.assertEqual(docs, [])

    def test_doc_file_detected(self):
        files = [
            {"filename": "Doc/library/asyncio.rst"},
        ]

        names, tests, news, docs = file_signals(files)

        self.assertEqual(len(names), 1)
        self.assertEqual(len(docs), 1)
        self.assertEqual(tests, [])
        self.assertEqual(news, [])

    def test_empty_files_are_not_documentation_only(self):
        names, tests, news, docs = file_signals([])

        self.assertEqual(names, [])
        self.assertEqual(tests, [])
        self.assertEqual(news, [])
        self.assertEqual(docs, [])

    def test_empty_files_are_not_test_only(self):
        names, tests, news, docs = file_signals([])

        self.assertFalse(
            names and all(name.startswith("Doc/") for name in names)
        )
        self.assertFalse(
            names and all(name.startswith("Lib/test/") for name in names)
        )

    def test_mixed_test_paths_are_detected(self):
        files = [
            {"filename": "Lib/test/test_one.py"},
            {"filename": "SomePackage/test/test_two.py"},
            {"filename": "Other/test_example.py"},
        ]

        _, tests, _, _ = file_signals(files)

        self.assertEqual(len(tests), 3)


class ProcessSignalTests(unittest.TestCase):
    def test_current_awaiting_action_label_blocks(self):
        pr = make_pr()

        signals, _ = process_signals(
            pr,
            [],
            [],
            ["awaiting action"],
            None,
        )

        block_messages = messages_for(signals, "BLOCK")

        self.assertTrue(block_messages)
        self.assertTrue(
            any(
                "awaiting action" in message.lower()
                for message in block_messages
            )
        )

    def test_awaiting_action_is_case_insensitive(self):
        pr = make_pr()

        signals, _ = process_signals(
            pr,
            [],
            [],
            ["AWAITING ACTION"],
            None,
        )

        self.assertTrue(messages_for(signals, "BLOCK"))

    def test_legacy_awaiting_changes_is_warning_not_block(self):
        pr = make_pr()

        signals, _ = process_signals(
            pr,
            [],
            [],
            ["awaiting changes"],
            None,
        )

        warn_messages = messages_for(signals, "WARN")
        block_messages = messages_for(signals, "BLOCK")

        self.assertTrue(warn_messages)
        self.assertFalse(
            any(
                "awaiting changes" in message.lower()
                for message in block_messages
            )
        )

    def test_do_not_merge_label_blocks(self):
        pr = make_pr()

        signals, _ = process_signals(
            pr,
            [],
            [],
            ["DO-NOT-MERGE"],
            None,
        )

        self.assertTrue(messages_for(signals, "BLOCK"))

    def test_skip_news_suppresses_missing_news_warning(self):
        pr = make_pr()

        files = [
            {"filename": "Lib/foo.py"},
        ]

        signals, _ = process_signals(
            pr,
            files,
            [],
            ["skip news"],
            None,
        )

        self.assertFalse(
            any(
                "NEWS" in message
                for message in messages_for(signals, "WARN")
            )
        )

    def test_documentation_only_change_does_not_require_news(self):
        pr = make_pr()

        files = [
            {"filename": "Doc/library/foo.rst"},
        ]

        signals, _ = process_signals(
            pr,
            files,
            [],
            [],
            None,
        )

        self.assertTrue(
            any(
                "documentation-only" in message.lower()
                for message in messages_for(signals, "INFO")
            )
        )

        self.assertFalse(
            any(
                "NEWS" in message
                for message in messages_for(signals, "WARN")
            )
        )

    def test_test_only_change_does_not_require_news(self):
        pr = make_pr()

        files = [
            {"filename": "Lib/test/test_foo.py"},
        ]

        signals, _ = process_signals(
            pr,
            files,
            [],
            [],
            None,
        )

        self.assertFalse(
            any(
                "NEWS" in message
                for message in messages_for(signals, "WARN")
            )
        )

    def test_normal_code_change_without_news_warns(self):
        pr = make_pr()

        files = [
            {"filename": "Lib/foo.py"},
        ]

        signals, _ = process_signals(
            pr,
            files,
            [],
            [],
            None,
        )

        self.assertTrue(
            any(
                "NEWS" in message
                for message in messages_for(signals, "WARN")
            )
        )

    def test_normal_code_change_without_test_warns(self):
        pr = make_pr()

        files = [
            {"filename": "Lib/foo.py"},
        ]

        signals, _ = process_signals(
            pr,
            files,
            [],
            ["skip news"],
            None,
        )

        self.assertTrue(
            any(
                "test file" in message.lower()
                for message in messages_for(signals, "WARN")
            )
        )

    def test_empty_file_evidence_warns(self):
        pr = make_pr()

        signals, _ = process_signals(
            pr,
            [],
            [],
            [],
            None,
        )

        warn_messages = messages_for(signals, "WARN")

        self.assertTrue(warn_messages)
        self.assertTrue(
            any(
                "changed files" in message.lower()
                for message in warn_messages
            )
        )

    def test_dynamic_branch_policy_can_be_supplied_through_patterns(self):
        pr = make_pr(branch="3.14")

        patterns = {
            "branch_policies": {
                "3.14": "security",
            }
        }

        signals, _ = process_signals(
            pr,
            [{"filename": "Lib/foo.py"}],
            [],
            ["type-bug", "skip news"],
            patterns,
        )

        self.assertTrue(messages_for(signals, "BLOCK"))


class DispositionTests(unittest.TestCase):
    def test_block_overrides_all(self):
        result = disposition(
            [
                ("BLOCK", "reason"),
                ("WARN", "other"),
                ("OK", "fine"),
            ],
            [],
        )

        self.assertEqual(
            result,
            "PROCESS_BLOCKED",
        )

    def test_high_severity_needs_technical_review(self):
        class _Finding:
            severity = "HIGH"

        result = disposition(
            [("OK", "good")],
            [_Finding()],
        )

        self.assertEqual(
            result,
            "NEEDS_TECHNICAL_REVIEW",
        )

    def test_critical_severity_needs_technical_review(self):
        class _Finding:
            severity = "CRITICAL"

        result = disposition(
            [("OK", "good")],
            [_Finding()],
        )

        self.assertEqual(
            result,
            "NEEDS_TECHNICAL_REVIEW",
        )

    def test_block_overrides_high_finding(self):
        class _Finding:
            severity = "HIGH"

        result = disposition(
            [("BLOCK", "policy blocker")],
            [_Finding()],
        )

        self.assertEqual(
            result,
            "PROCESS_BLOCKED",
        )

    def test_warn_needs_attention(self):
        result = disposition(
            [("WARN", "something")],
            [],
        )

        self.assertEqual(
            result,
            "NEEDS_MAINTAINER_ATTENTION",
        )

    def test_info_does_not_prevent_ready_disposition(self):
        result = disposition(
            [
                ("OK", "good"),
                ("INFO", "note"),
            ],
            [],
        )

        self.assertEqual(
            result,
            "READY_FOR_MAINTAINER_REVIEW",
        )

    def test_empty_process_and_findings_is_ready_when_evidence_is_complete(self):
        evidence = {
            "attempted": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "available": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "missing": [],
            "errors": {},
        }

        result = disposition([], [], evidence)

        self.assertEqual(
            result,
            "READY_FOR_MAINTAINER_REVIEW",
        )

    def test_missing_evidence_needs_evidence_review(self):
        evidence = {
            "attempted": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "available": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "issue_comments",
            ],
            "missing": ["review_comments"],
            "errors": {},
        }

        result = disposition([], [], evidence)

        self.assertEqual(
            result,
            "NEEDS_EVIDENCE_REVIEW",
        )

    def test_evidence_error_needs_evidence_review(self):
        evidence = {
            "attempted": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "available": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "issue_comments",
            ],
            "missing": ["review_comments"],
            "errors": {
                "review_comments": "GitHub API request failed",
            },
        }

        result = disposition([], [], evidence)

        self.assertEqual(
            result,
            "NEEDS_EVIDENCE_REVIEW",
        )

    def test_evidence_gate_ignores_optional_sources(self):
        evidence = {
            "attempted": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "available": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "missing": [],
            "errors": {},
        }

        result = disposition([], [], evidence)

        self.assertEqual(
            result,
            "READY_FOR_MAINTAINER_REVIEW",
        )

    def test_process_block_overrides_missing_evidence(self):
        evidence = {
            "attempted": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "available": ["pr", "files"],
            "missing": [
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "errors": {},
        }

        result = disposition(
            [("BLOCK", "policy blocker")],
            [],
            evidence,
        )

        self.assertEqual(
            result,
            "PROCESS_BLOCKED",
        )

    def test_high_finding_overrides_missing_evidence(self):
        class _Finding:
            severity = "HIGH"

        evidence = {
            "attempted": [
                "pr",
                "files",
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "available": ["pr", "files"],
            "missing": [
                "timeline",
                "reviews",
                "review_comments",
                "issue_comments",
            ],
            "errors": {},
        }

        result = disposition(
            [("OK", "good")],
            [_Finding()],
            evidence,
        )

        self.assertEqual(
            result,
            "NEEDS_TECHNICAL_REVIEW",
        )

    def test_finding_without_severity_does_not_crash(self):
        class _Finding:
            pass

        result = disposition(
            [("OK", "good")],
            [_Finding()],
        )

        self.assertEqual(
            result,
            "READY_FOR_MAINTAINER_REVIEW",
        )


class PolicyCombinationTests(unittest.TestCase):
    def test_security_branch_and_awaiting_action_both_block(self):
        pr = make_pr(branch="3.10")

        signals, _ = process_signals(
            pr,
            [{"filename": "Lib/foo.py"}],
            [],
            ["type-security", "awaiting action"],
            None,
        )

        block_messages = messages_for(signals, "BLOCK")

        self.assertGreaterEqual(len(block_messages), 1)

    def test_feature_on_bugfix_branch_reaches_blocked_disposition(self):
        pr = make_pr(branch="3.14")

        signals, _ = process_signals(
            pr,
            [{"filename": "Lib/foo.py"}],
            [],
            ["type-feature", "skip news"],
            None,
        )

        result = disposition(signals, [])

        self.assertEqual(
            result,
            "PROCESS_BLOCKED",
        )

    def test_changes_requested_without_followup_needs_attention(self):
        pr = make_pr()

        timeline = [
            {
                "kind": "review",
                "state": "CHANGES_REQUESTED",
                "bot": False,
                "date": "2026-08-31T00:00:00Z",
                "login": "reviewer",
            },
        ]

        signals, _ = process_signals(
            pr,
            [{"filename": "Lib/foo.py"}],
            timeline,
            ["skip news"],
            None,
        )

        result = disposition(signals, [])

        self.assertEqual(
            result,
            "NEEDS_MAINTAINER_ATTENTION",
        )

    def test_high_finding_overrides_process_warning(self):
        class _Finding:
            severity = "HIGH"

        result = disposition(
            [
                ("WARN", "missing test"),
            ],
            [_Finding()],
        )

        self.assertEqual(
            result,
            "NEEDS_TECHNICAL_REVIEW",
        )


if __name__ == "__main__":
    unittest.main()