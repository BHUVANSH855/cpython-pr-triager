from __future__ import annotations

import unittest

from scripts.triager.references import (
    collect_issue_numbers,
    extract_references,
    issue_refs_from_timeline,
)


class ReferenceTests(unittest.TestCase):
    def test_extract_issue_bpo_and_github_references(self):
        issues, peps, discussions = (
            extract_references(
                """
                bpo-46231
                issue 12345
                https://github.com/python/cpython/issues/67890
                https://github.com/python/cpython/pull/30391
                """
            )
        )

        self.assertEqual(
            issues,
            [
                12345,
                30391,
                46231,
                67890,
            ],
        )

        self.assertEqual(
            peps,
            [],
        )

        self.assertEqual(
            discussions,
            [],
        )

    def test_extract_pep_and_discussion_references(self):
        issues, peps, discussions = (
            extract_references(
                """
                See PEP 11 and PEP-657.
                Discussion:
                https://github.com/python/cpython/discussions/123
                """
            )
        )

        self.assertEqual(
            issues,
            [],
        )

        self.assertEqual(
            peps,
            [
                11,
                657,
            ],
        )

        self.assertEqual(
            discussions,
            [
                123,
            ],
        )

    def test_extract_references_deduplicates(self):
        issues, peps, discussions = (
            extract_references(
                """
                bpo-123
                bpo-123
                PEP 8
                PEP-8
                https://github.com/python/cpython/discussions/1
                https://github.com/python/cpython/discussions/1
                """
            )
        )

        self.assertEqual(
            issues,
            [
                123,
            ],
        )

        self.assertEqual(
            peps,
            [
                8,
            ],
        )

        self.assertEqual(
            discussions,
            [
                1,
            ],
        )

    def test_issue_refs_from_timeline(self):
        timeline = [
            {
                "event": "labeled",
                "source": {},
            },
            {
                "event": "cross-referenced",
                "source": {
                    "issue": {
                        "number": 30341,
                        "title": "Example issue",
                    }
                },
            },
            {
                "event": "cross-referenced",
                "source": {
                    "issue": {
                        "number": 30342,
                        "title": "Another issue",
                    }
                },
            },
        ]

        self.assertEqual(
            issue_refs_from_timeline(
                timeline
            ),
            [
                {
                    "number": 30341,
                    "title": "Example issue",
                },
                {
                    "number": 30342,
                    "title": "Another issue",
                },
            ],
        )

    def test_collect_issue_numbers_excludes_current_pr(self):
        timeline = [
            {
                "bot": False,
                "body": "issue 30341",
                "event": {
                    "event": "comment",
                },
            },
            {
                "bot": False,
                "body": "",
                "event": {
                    "event": "cross-referenced",
                    "source": {
                        "issue": {
                            "number": 30342,
                            "title": "Linked issue",
                        }
                    },
                },
            },
        ]

        issues, peps, discussions = (
            collect_issue_numbers(
                pr_number=30342,
                pr_body="bpo-30341 bpo-30341",
                timeline=timeline,
                limit=20,
            )
        )

        self.assertEqual(
            issues,
            [
                30341,
            ],
        )

        self.assertEqual(
            peps,
            [],
        )

        self.assertEqual(
            discussions,
            [],
        )

    def test_collect_issue_numbers_only_uses_human_timeline_bodies(self):
        timeline = [
            {
                "bot": True,
                "body": "bpo-99999",
                "event": {},
            },
            {
                "bot": False,
                "body": "bpo-11111",
                "event": {},
            },
        ]

        issues, _, _ = (
            collect_issue_numbers(
                pr_number=123,
                pr_body="",
                timeline=timeline,
            )
        )

        self.assertEqual(
            issues,
            [
                11111,
            ],
        )

    def test_collect_issue_numbers_applies_limit(self):
        issues, _, _ = (
            collect_issue_numbers(
                pr_number=1,
                pr_body=(
                    "bpo-1 bpo-2 bpo-3 "
                    "bpo-4 bpo-5"
                ),
                limit=3,
            )
        )

        self.assertEqual(
            issues,
            [
                2,
                3,
                4,
            ],
        )

    def test_negative_limit_is_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            collect_issue_numbers(
                pr_number=1,
                pr_body="bpo-2",
                limit=-1,
            )


if __name__ == "__main__":
    unittest.main()