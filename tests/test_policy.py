"""
Tests for scripts/triager/policy.py

Covers all policy fixes:
- BACKPORT_LABEL_RE uses hyphens (point 3)
- 3.10 security-only branch blocking (point 14)
- Review signal logic
- Disposition logic

Note on dates: tests that check review state use dates close to the test
run date (2026-08-xx) so the stale-PR heuristic (>30 days no activity)
does not fire and produce unexpected WARN signals.
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
    SECURITY_ONLY_BRANCHES,
    branch_and_backport_signals,
    disposition,
    file_signals,
    process_signals,
    review_signals,
)


class BackportLabelRegexTests(unittest.TestCase):
    """FIX (point 3): backport labels use hyphens."""

    def test_hyphenated_format_matches(self):
        for branch in ("3.10", "3.11", "3.12", "3.13", "3.14"):
            label = f"needs-backport-to-{branch}"
            match = BACKPORT_LABEL_RE.fullmatch(label)
            self.assertIsNotNone(match, f"{label!r} should match")
            self.assertEqual(match.group(1), branch)

    def test_space_format_does_not_match(self):
        """The old broken regex format."""
        for branch in ("3.13", "3.12"):
            label = f"needs backport to {branch}"
            match = BACKPORT_LABEL_RE.fullmatch(label)
            self.assertIsNone(match, f"Space-separated {label!r} should NOT match")

    def test_case_insensitive(self):
        match = BACKPORT_LABEL_RE.fullmatch("NEEDS-BACKPORT-TO-3.13")
        self.assertIsNotNone(match)


class SecurityOnlyBranchTests(unittest.TestCase):
    """FIX (point 14): 3.10 is security-only."""

    def test_3_10_in_security_only_branches(self):
        self.assertIn("3.10", SECURITY_ONLY_BRANCHES)

    def test_3_13_not_in_security_only_branches(self):
        self.assertNotIn("3.13", SECURITY_ONLY_BRANCHES)

    def test_bug_fix_on_3_10_blocked(self):
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-bug"])
        block_msgs = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(block_msgs, "Bug fix on 3.10 should be BLOCKED")
        self.assertTrue(any("security" in m.lower() for m in block_msgs))

    def test_feature_on_3_10_blocked(self):
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-feature"])
        block_msgs = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(block_msgs)

    def test_crash_fix_on_3_10_blocked(self):
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-crash"])
        block_msgs = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(block_msgs, "Even crash fixes should be flagged on 3.10")

    def test_unlabelled_3_10_warns_not_blocks(self):
        """No type label on 3.10 → WARN (maintainer should decide)."""
        pr = {"base": {"ref": "3.10"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, [])
        warn_msgs = [msg for sig, msg in signals if sig == "WARN"]
        block_msgs = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(warn_msgs, "Unlabelled 3.10 PR should produce WARN")
        self.assertFalse(block_msgs, "Unlabelled 3.10 PR should not BLOCK")

    def test_feature_on_stable_branch_blocked(self):
        """3.13 is stable — no new features."""
        pr = {"base": {"ref": "3.13"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-feature"])
        block_msgs = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertTrue(block_msgs)

    def test_bug_fix_on_stable_branch_not_blocked(self):
        """Bug fixes on stable branches are fine."""
        pr = {"base": {"ref": "3.13"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["type-bug"])
        block_msgs = [msg for sig, msg in signals if sig == "BLOCK"]
        self.assertFalse(block_msgs)


class BackportSignalExtractionTests(unittest.TestCase):
    """FIX (point 3): backport targets should be populated."""

    def test_multiple_backport_labels(self):
        pr = {"base": {"ref": "main"}, "state": "open"}
        labels = ["needs-backport-to-3.13", "needs-backport-to-3.12", "type-bug"]
        signals, backports = branch_and_backport_signals(pr, labels)
        self.assertIn("3.13", backports)
        self.assertIn("3.12", backports)

    def test_no_backport_labels_empty_list(self):
        pr = {"base": {"ref": "main"}, "state": "open"}
        _, backports = branch_and_backport_signals(pr, ["type-bug"])
        self.assertEqual(backports, [])

    def test_backport_info_signal_emitted(self):
        pr = {"base": {"ref": "main"}, "state": "open"}
        signals, _ = branch_and_backport_signals(pr, ["needs-backport-to-3.13"])
        info = [msg for sig, msg in signals if sig == "INFO"]
        self.assertTrue(any("3.13" in m for m in info))


class ReviewSignalTests(unittest.TestCase):
    # Use dates close to the test run (2026-08-xx) so the stale-PR heuristic
    # (>30 days no activity) does not fire and interfere with signal assertions.

    def test_approval_produces_ok(self):
        pr = {"state": "open"}
        timeline = [
            {
                "kind": "review", "state": "APPROVED", "bot": False,
                "date": "2026-08-31T00:00:00Z", "login": "alice",
            },
        ]
        signals = review_signals(pr, timeline)
        self.assertTrue(any(s == "OK" for s, _ in signals))

    def test_changes_requested_no_followup_warns(self):
        pr = {"state": "open"}
        timeline = [
            {
                "kind": "review", "state": "CHANGES_REQUESTED", "bot": False,
                "date": "2026-08-31T00:00:00Z", "login": "alice",
            },
        ]
        signals = review_signals(pr, timeline)
        self.assertTrue(any(s == "WARN" for s, _ in signals))

    def test_changes_requested_with_followup_produces_no_warn(self):
        """
        After CHANGES_REQUESTED, if the author comments, the WARN should
        not fire for the changes-requested reason.  Both events are recent
        so the stale-PR heuristic also does not fire.
        """
        pr = {"state": "open"}
        timeline = [
            {
                "kind": "review", "state": "CHANGES_REQUESTED", "bot": False,
                "date": "2026-08-30T00:00:00Z", "login": "alice",
            },
            {
                "kind": "comment", "state": None, "bot": False,
                "date": "2026-08-31T00:00:00Z", "login": "author",
            },
        ]
        signals = review_signals(pr, timeline)
        # There should be an INFO (later activity exists) but no WARN.
        self.assertTrue(any(s == "INFO" for s, _ in signals))
        self.assertFalse(
            any(s == "WARN" for s, _ in signals),
            f"Expected no WARN but got: {[m for s,m in signals if s=='WARN']}",
        )

    def test_stale_pr_warns(self):
        """A PR with no activity for >90 days should produce a WARN."""
        pr = {"state": "open"}
        # 2024-01-01 is well over 90 days before Sept 2026.
        old = [{"kind": "comment", "bot": False, "date": "2024-01-01T00:00:00Z"}]
        signals = review_signals(pr, old)
        self.assertTrue(any(s == "WARN" for s, _ in signals))

    def test_bot_events_ignored(self):
        pr = {"state": "open"}
        timeline = [
            {
                "kind": "review", "state": "APPROVED", "bot": True,
                "date": "2026-08-31T00:00:00Z",
            },
        ]
        signals = review_signals(pr, timeline)
        # Bot approvals should not count as human approvals.
        self.assertFalse(any(s == "OK" for s, _ in signals))


class DispositionTests(unittest.TestCase):

    def test_block_overrides_all(self):
        self.assertEqual(
            disposition([("BLOCK", "reason"), ("WARN", "other")], []),
            "PROCESS_BLOCKED",
        )

    def test_high_severity_needs_technical_review(self):
        class _Finding:
            severity = "HIGH"
        self.assertEqual(
            disposition([("OK", "good")], [_Finding()]),
            "NEEDS_TECHNICAL_REVIEW",
        )

    def test_warn_needs_attention(self):
        self.assertEqual(
            disposition([("WARN", "something")], []),
            "NEEDS_MAINTAINER_ATTENTION",
        )

    def test_all_ok_ready(self):
        self.assertEqual(
            disposition([("OK", "good"), ("INFO", "note")], []),
            "READY_FOR_MAINTAINER_REVIEW",
        )


class FileSignalsTests(unittest.TestCase):

    def test_news_file_detected(self):
        files = [{"filename": "Misc/NEWS.d/next/Library/gh-123.rst"}]
        names, tests, news, docs = file_signals(files)
        self.assertEqual(len(news), 1)

    def test_test_file_detected(self):
        files = [{"filename": "Lib/test/test_asyncio.py"}]
        names, tests, news, docs = file_signals(files)
        self.assertEqual(len(tests), 1)

    def test_doc_file_detected(self):
        files = [{"filename": "Doc/library/asyncio.rst"}]
        names, tests, news, docs = file_signals(files)
        self.assertEqual(len(docs), 1)


class DoNotMergeTests(unittest.TestCase):

    def test_do_not_merge_label_blocks(self):
        pr = {"state": "open", "base": {"ref": "main"}, "title": "gh-123: test"}
        labels = ["DO-NOT-MERGE"]
        signals, _ = process_signals(pr, [], [], labels, None)
        self.assertTrue(any(s == "BLOCK" for s, _ in signals))

    def test_awaiting_changes_blocks(self):
        pr = {"state": "open", "base": {"ref": "main"}, "title": "gh-123: test"}
        labels = ["awaiting changes"]
        signals, _ = process_signals(pr, [], [], labels, None)
        self.assertTrue(any(s == "BLOCK" for s, _ in signals))


if __name__ == "__main__":
    unittest.main()