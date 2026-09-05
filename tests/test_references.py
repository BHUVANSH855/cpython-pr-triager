"""
Tests for scripts/triager/references.py

FIX (point 4): DISCUSS_RE now matches discuss.python.org URLs.
Tests updated to reflect this and to cover gh- shorthand extraction.

Note on URL selection: discuss.python.org URLs that contain "pep-NNN" in
their slug will cause PEP_RE to match the URL text and extract a PEP number.
Tests that assert peps==[] use slugs that do not contain "pep-" patterns.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.triager.references import (
    collect_issue_numbers,
    extract_references,
    issue_refs_from_timeline,
)


class ReferenceTests(unittest.TestCase):

    def test_extract_issue_bpo_and_github_references(self):
        issues, peps, discussions = extract_references(
            """
            bpo-46231
            issue 12345
            https://github.com/python/cpython/issues/67890
            https://github.com/python/cpython/pull/30391
            """
        )
        self.assertEqual(issues, [12345, 30391, 46231, 67890])
        self.assertEqual(peps, [])
        self.assertEqual(discussions, [])

    def test_extract_gh_shorthand(self):
        """gh-NNNNN shorthand is common in CPython PR titles and bodies."""
        issues, peps, discussions = extract_references("gh-128774: Fix asyncio bug")
        self.assertIn(128774, issues)

    def test_extract_closes_references(self):
        """Closes #NNNNN / fixes #NNNNN style."""
        issues, peps, discussions = extract_references(
            "Fixes #12345\nCloses #67890\nResolves #11111"
        )
        for n in [12345, 67890, 11111]:
            self.assertIn(n, issues)

    def test_extract_pep_references(self):
        issues, peps, discussions = extract_references(
            "See PEP 11 and PEP-657."
        )
        self.assertEqual(issues, [])
        self.assertEqual(peps, [11, 657])
        self.assertEqual(discussions, [])

    def test_extract_discuss_python_org_urls(self):
        """
        FIX (point 4): DISCUSS_RE now matches discuss.python.org not
        github.com/*/discussions.

        URLs are chosen without "pep-NNN" in the slug so that PEP_RE does
        not also extract a PEP number (which would make peps != []).
        """
        issues, peps, discussions = extract_references(
            """
            See https://discuss.python.org/t/typing-overload-and-never/12345
            Also https://discuss.python.org/t/asyncio-task-cancellation/67890/4
            """
        )
        self.assertEqual(issues, [])
        self.assertEqual(peps, [])
        self.assertEqual(len(discussions), 2)
        self.assertTrue(
            all("discuss.python.org" in d for d in discussions),
            "Discussions should be discuss.python.org URLs",
        )

    def test_discuss_url_with_pep_in_slug_extracts_pep(self):
        """
        A discuss.python.org URL that contains 'pep-750' in the slug will
        cause PEP_RE to match.  This is expected behaviour — document it
        rather than asserting peps==[].
        """
        issues, peps, discussions = extract_references(
            "https://discuss.python.org/t/pep-750-t-strings/67890/4"
        )
        # PEP 750 is correctly extracted from the URL slug.
        self.assertIn(750, peps)
        # The URL is still captured as a discussion.
        self.assertEqual(len(discussions), 1)
        self.assertIn("discuss.python.org", discussions[0])

    def test_github_discussions_not_matched(self):
        """
        FIX (point 4): github.com/*/discussions should NOT be matched as a
        discuss.python.org thread — CPython community discussion is on
        discuss.python.org, not GitHub Discussions.
        """
        issues, peps, discussions = extract_references(
            "https://github.com/python/cpython/discussions/123"
        )
        self.assertEqual(discussions, [])

    def test_extract_references_deduplicates(self):
        issues, peps, discussions = extract_references(
            """
            bpo-123
            bpo-123
            PEP 8
            PEP-8
            https://discuss.python.org/t/some-topic/1
            https://discuss.python.org/t/some-topic/1
            """
        )
        self.assertEqual(issues, [123])
        self.assertEqual(peps, [8])
        self.assertEqual(len(discussions), 1)

    def test_issue_refs_from_timeline(self):
        timeline = [
            {"event": "labeled", "source": {}},
            {
                "event": "cross-referenced",
                "source": {
                    "issue": {"number": 30341, "title": "Example issue"}
                },
            },
            {
                "event": "cross-referenced",
                "source": {
                    "issue": {"number": 30342, "title": "Another issue"}
                },
            },
        ]
        self.assertEqual(
            issue_refs_from_timeline(timeline),
            [
                {"number": 30341, "title": "Example issue"},
                {"number": 30342, "title": "Another issue"},
            ],
        )

    def test_collect_issue_numbers_excludes_current_pr(self):
        issues, peps, discussions = collect_issue_numbers(
            pr_number=30342,
            pr_body="bpo-30341 bpo-30341",
            timeline=[],
            limit=20,
        )
        self.assertEqual(issues, [30341])
        self.assertEqual(peps, [])

    def test_collect_issue_numbers_only_uses_human_timeline_bodies(self):
        timeline = [
            {"bot": True, "body": "bpo-99999", "event": {}},
            {"bot": False, "body": "bpo-11111", "event": {}},
        ]
        issues, _, _ = collect_issue_numbers(
            pr_number=123,
            pr_body="",
            timeline=timeline,
        )
        self.assertIn(11111, issues)
        self.assertNotIn(99999, issues)

    def test_collect_issue_numbers_applies_limit(self):
        issues, _, _ = collect_issue_numbers(
            pr_number=1,
            pr_body="bpo-2 bpo-3 bpo-4 bpo-5 bpo-6",
            limit=3,
        )
        self.assertEqual(len(issues), 3)

    def test_negative_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            collect_issue_numbers(pr_number=1, pr_body="bpo-2", limit=-1)


if __name__ == "__main__":
    unittest.main()