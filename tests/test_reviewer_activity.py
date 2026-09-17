"""Tests for scripts/triager/reviewer_activity.py"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.triager.reviewer_activity import (
    ReviewerActivity,
    ReviewerActivityCache,
    _build_activity_from_reviews,
    _extract_concern_keywords,
    _extract_quoted_phrases,
    format_activity_for_report,
)


class ConcernKeywordTests(unittest.TestCase):

    def test_needs_test_detected(self):
        self.assertIn(
            "needs_test",
            _extract_concern_keywords(
                "Can you add a test for this case?"
            ),
        )

    def test_needs_news_detected(self):
        self.assertIn(
            "needs_news",
            _extract_concern_keywords(
                "Please add a NEWS entry in Misc/NEWS.d/"
            ),
        )

    def test_needs_regen_detected(self):
        self.assertIn(
            "needs_regen",
            _extract_concern_keywords(
                "Run make regen-pegen after grammar changes"
            ),
        )

    def test_needs_benchmark_detected(self):
        self.assertIn(
            "needs_benchmark",
            _extract_concern_keywords(
                "Please provide a benchmark showing no performance regression"
            ),
        )

    def test_thread_safety_detected(self):
        self.assertIn(
            "thread_safety",
            _extract_concern_keywords(
                "Is this thread safe under free-threading?"
            ),
        )

    def test_security_detected(self):
        self.assertIn(
            "security",
            _extract_concern_keywords(
                "This has a security vulnerability — injection risk"
            ),
        )

    def test_empty_body_no_concerns(self):
        self.assertEqual(
            _extract_concern_keywords(""),
            [],
        )

    def test_unrelated_text_no_concerns(self):
        self.assertEqual(
            _extract_concern_keywords(
                "LGTM, thanks!"
            ),
            [],
        )

    def test_multiple_concerns_same_comment(self):
        text = (
            "Please add a test and a NEWS entry "
            "and run make regen-all"
        )

        concerns = _extract_concern_keywords(text)

        self.assertIn(
            "needs_test",
            concerns,
        )
        self.assertIn(
            "needs_news",
            concerns,
        )
        self.assertIn(
            "needs_regen",
            concerns,
        )


class ExtractPhrasesTests(unittest.TestCase):

    def test_extracts_quoted_strings(self):
        phrases = _extract_quoted_phrases(
            'The function "should be renamed" to avoid confusion.'
        )

        self.assertTrue(
            any(
                "renamed" in phrase
                for phrase in phrases
            )
        )

    def test_extracts_please_requests(self):
        phrases = _extract_quoted_phrases(
            "Please add a test that covers the error path."
        )

        self.assertTrue(
            any(
                "Please" in phrase
                or "add a test" in phrase
                for phrase in phrases
            )
        )

    def test_empty_body(self):
        self.assertEqual(
            _extract_quoted_phrases(""),
            [],
        )

    def test_max_phrases_respected(self):
        text = (
            '"phrase one" '
            '"phrase two" '
            '"phrase three" '
            '"phrase four" '
            '"phrase five" '
            '"phrase six"'
        )

        phrases = _extract_quoted_phrases(
            text,
            max_phrases=3,
        )

        self.assertLessEqual(
            len(phrases),
            3,
        )


class BuildActivityTests(unittest.TestCase):

    def test_builds_from_empty(self):
        activity = _build_activity_from_reviews(
            "alice",
            [],
            [],
        )

        self.assertEqual(
            activity.username,
            "alice",
        )
        self.assertEqual(
            activity.total_reviews,
            0,
        )
        self.assertIsNone(
            activity.approval_rate
        )

    def test_calculates_approval_rate(self):
        # Five or more APPROVED/CHANGES_REQUESTED verdicts are required.
        reviews = [
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "CHANGES_REQUESTED"},
            {"state": "CHANGES_REQUESTED"},
        ]

        activity = _build_activity_from_reviews(
            "alice",
            [],
            reviews,
        )

        self.assertAlmostEqual(
            activity.approval_rate,
            0.67,
            places=1,
        )

        self.assertEqual(
            activity.approval_rate_sample_size,
            6,
        )

        self.assertEqual(
            activity.total_reviews,
            6,
        )

    def test_approval_rate_suppressed_below_min_sample(self):
        """A tiny verdict sample must not produce a precise percentage."""
        reviews = [
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "CHANGES_REQUESTED"},
        ]

        activity = _build_activity_from_reviews(
            "alice",
            [],
            reviews,
        )

        self.assertIsNone(
            activity.approval_rate
        )

        self.assertEqual(
            activity.approval_rate_sample_size,
            3,
        )

        self.assertEqual(
            activity.total_reviews,
            3,
        )

    def test_inline_comments_do_not_count_as_submitted_reviews(self):
        """
        Inline review comments are conversation evidence, not submitted
        review records.

        total_reviews must therefore remain zero when only comments are
        supplied.
        """
        comments = [
            {
                "body": "Please add a test.",
                "path": "Lib/asyncio/tasks.py",
            },
            {
                "body": "This needs a test case.",
                "path": "Lib/asyncio/base.py",
            },
            {
                "body": "Can you add a NEWS entry?",
                "path": "",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            comments,
            [],
        )

        self.assertEqual(
            activity.total_reviews,
            0,
        )

        self.assertIn(
            "needs_test",
            activity.concern_frequency,
        )

        self.assertEqual(
            activity.concern_frequency["needs_test"],
            2,
        )

        self.assertIn(
            "needs_news",
            activity.concern_frequency,
        )

    def test_submitted_reviews_count_as_reviews(self):
        reviews = [
            {
                "state": "APPROVED",
                "body": "Looks good.",
            },
            {
                "state": "CHANGES_REQUESTED",
                "body": "Please add a test.",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            [],
            reviews,
        )

        self.assertEqual(
            activity.total_reviews,
            2,
        )

    def test_inline_comments_and_submitted_reviews_both_contribute_concerns(self):
        comments = [
            {
                "body": "Please add a test.",
                "path": "Lib/asyncio/tasks.py",
            },
        ]

        reviews = [
            {
                "state": "CHANGES_REQUESTED",
                "body": "Please add a NEWS entry.",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            comments,
            reviews,
        )

        self.assertEqual(
            activity.concern_frequency["needs_test"],
            1,
        )

        self.assertEqual(
            activity.concern_frequency["needs_news"],
            1,
        )

        self.assertEqual(
            activity.total_reviews,
            1,
        )

    def test_non_verdict_review_states_do_not_affect_approval_rate(self):
        reviews = [
            {"state": "COMMENT"},
            {"state": "COMMENTED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "CHANGES_REQUESTED"},
        ]

        activity = _build_activity_from_reviews(
            "alice",
            [],
            reviews,
        )

        self.assertAlmostEqual(
            activity.approval_rate,
            0.80,
            places=2,
        )

        self.assertEqual(
            activity.approval_rate_sample_size,
            5,
        )

        self.assertEqual(
            activity.total_reviews,
            7,
        )

    def test_top_concerns_ordered(self):
        comments = [
            {
                "body": "Please add a test.",
                "path": "",
            },
            {
                "body": "Another test needed.",
                "path": "",
            },
            {
                "body": "Please add a test.",
                "path": "",
            },
            {
                "body": "Add a NEWS entry.",
                "path": "",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            comments,
            [],
        )

        self.assertEqual(
            activity.top_concerns[0],
            "needs_test",
        )

    def test_active_subsystems_from_paths(self):
        comments = [
            {
                "body": "ok",
                "path": "Lib/asyncio/tasks.py",
            },
            {
                "body": "ok",
                "path": "Lib/asyncio/base.py",
            },
            {
                "body": "ok",
                "path": "Python/gc.c",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            comments,
            [],
        )

        self.assertTrue(
            any(
                "Lib/asyncio" in subsystem
                for subsystem in activity.active_subsystems
            )
        )

    def test_response_time_uses_first_review_per_pr(self):
        reviews = [
            {
                "state": "COMMENT",
                "pr_number": 1,
                "pr_created_at": "2026-01-01T00:00:00Z",
                "submitted_at": "2026-01-03T00:00:00Z",
            },
            {
                "state": "APPROVED",
                "pr_number": 1,
                "pr_created_at": "2026-01-01T00:00:00Z",
                "submitted_at": "2026-01-10T00:00:00Z",
            },
            {
                "state": "APPROVED",
                "pr_number": 2,
                "pr_created_at": "2026-01-01T00:00:00Z",
                "submitted_at": "2026-01-05T00:00:00Z",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            [],
            reviews,
        )

        # First review on PR #1 = 2 days.
        # First review on PR #2 = 4 days.
        # Median = 3 days.
        self.assertEqual(
            activity.median_response_days,
            3.0,
        )

    def test_invalid_response_timestamp_is_ignored(self):
        reviews = [
            {
                "state": "APPROVED",
                "pr_number": 1,
                "pr_created_at": "not-a-date",
                "submitted_at": "2026-01-05T00:00:00Z",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            [],
            reviews,
        )

        self.assertIsNone(
            activity.median_response_days
        )

    def test_duplicate_phrases_are_removed(self):
        comments = [
            {
                "body": 'Please "add a test for this case".',
                "path": "",
            },
            {
                "body": 'Please "add a test for this case".',
                "path": "",
            },
        ]

        activity = _build_activity_from_reviews(
            "alice",
            comments,
            [],
        )

        self.assertEqual(
            len(activity.sample_phrases),
            len(set(activity.sample_phrases)),
        )


class ReviewerActivityCacheTests(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gh = MagicMock()
        self.gh.cache_dir = self.tmpdir

        # Default: every endpoint returns a successful empty response.
        self.gh.request.return_value = []

    def test_get_returns_activity(self):
        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        activity = cache.get(
            "markshannon"
        )

        self.assertIsInstance(
            activity,
            ReviewerActivity,
        )

        self.assertEqual(
            activity.username,
            "markshannon",
        )

        self.assertTrue(
            activity.available
        )

    def test_memory_cache_avoids_second_fetch(self):
        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        cache.get("markshannon")
        first_call_count = (
            self.gh.request.call_count
        )

        cache.get("markshannon")

        self.assertEqual(
            self.gh.request.call_count,
            first_call_count,
        )

    def test_disk_cache_round_trip(self):
        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        cache.get("markshannon")

        cache._memory.clear()

        activity = cache.get(
            "markshannon"
        )

        self.assertTrue(
            activity.from_cache
        )

    def test_stale_disk_cache_refetches(self):
        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=1,
        )

        stale = ReviewerActivity(
            username="markshannon",
            fetched_at=time.time() - 10,
        )

        cache._save_to_disk(stale)

        cache._memory.clear()

        activity = cache.get(
            "markshannon"
        )

        self.assertFalse(
            activity.from_cache
        )

    def test_github_failure_returns_empty_activity_marked_unavailable(self):
        """
        A complete collection failure must be distinguishable from a
        successful zero-activity result.
        """
        self.gh.request.side_effect = Exception(
            "rate limited"
        )

        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        activity = cache.get(
            "markshannon"
        )

        self.assertIsInstance(
            activity,
            ReviewerActivity,
        )

        self.assertEqual(
            activity.total_reviews,
            0,
        )

        self.assertFalse(
            activity.available
        )

        self.assertIn(
            "rate limited",
            activity.error,
        )

        cache_path = cache._cache_path(
            "markshannon"
        )

        self.assertFalse(
            cache_path.exists()
        )

    def test_failed_fetch_is_retried_next_call_not_frozen(self):
        """
        A failed fetch is never persisted, so a subsequent call retries
        the network instead of returning the same unavailable result.
        """
        call_count = {
            "n": 0
        }

        def flaky_request(path):
            call_count["n"] += 1
            raise Exception(
                "boom"
            )

        self.gh.request.side_effect = (
            flaky_request
        )

        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        cache.get(
            "markshannon"
        )

        first_calls = call_count["n"]

        cache._memory.clear()

        cache.get(
            "markshannon"
        )

        self.assertGreater(
            call_count["n"],
            first_calls,
        )

    def test_partial_failure_still_reports_available_with_error(self):
        """
        If one evidence source fails but another succeeds, the result is
        still available and the failure is explicitly reported.

        Here the inline-comment endpoint fails while the reviewer-search
        endpoint succeeds with an empty result set.
        """

        def one_endpoint_fails(path):
            if "/pulls/comments" in path:
                raise Exception(
                    "pulls/comments down"
                )

            if "/search/issues" in path:
                return {
                    "total_count": 0,
                    "incomplete_results": False,
                    "items": [],
                }

            # No PR review endpoints should be reached because search
            # returned zero reviewed PRs.
            return []

        self.gh.request.side_effect = (
            one_endpoint_fails
        )

        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        activity = cache.get(
            "markshannon"
        )

        self.assertTrue(
            activity.available
        )

        self.assertIsNotNone(
            activity.error
        )

        self.assertIn(
            "pulls/comments",
            activity.error,
        )

    def test_submitted_review_endpoint_failure_is_partial(self):
        """
        Inline comments can still provide usable activity if submitted
        review collection fails.
        """

        def submitted_reviews_fail(path):
            if "/pulls/comments" in path:
                return [
                    {
                        "user": {
                            "login": "markshannon"
                        },
                        "body": "Please add a test.",
                        "path": "Lib/asyncio/tasks.py",
                    }
                ]

            if "/search/issues" in path:
                return {
                    "total_count": 1,
                    "incomplete_results": False,
                    "items": [
                        {
                            "number": 123,
                            "created_at": (
                                "2026-01-01T00:00:00Z"
                            ),
                        }
                    ],
                }

            if "/pulls/123/reviews" in path:
                raise Exception(
                    "reviews endpoint down"
                )

            return []

        self.gh.request.side_effect = (
            submitted_reviews_fail
        )

        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        activity = cache.get(
            "markshannon"
        )

        self.assertTrue(
            activity.available
        )

        self.assertIsNotNone(
            activity.error
        )

        self.assertIn(
            "reviews endpoint down",
            activity.error,
        )

        self.assertIn(
            "needs_test",
            activity.concern_frequency,
        )

    def test_successful_empty_result_is_available(self):
        """
        Empty API results are valid evidence, not API failures.

        /pulls/comments returns a list, while /search/issues returns an
        object containing an empty `items` list. Both are valid successful
        responses.
        """

        def empty_successful_response(path):
            if "/pulls/comments" in path:
                return []

            if "/search/issues" in path:
                return {
                    "total_count": 0,
                    "incomplete_results": False,
                    "items": [],
                }

            return []

        self.gh.request.side_effect = (
            empty_successful_response
        )

        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        activity = cache.get(
            "markshannon"
        )

        self.assertTrue(
            activity.available
        )

        self.assertEqual(
            activity.total_reviews,
            0,
        )

        self.assertEqual(
            activity.approval_rate_sample_size,
            0,
        )

        self.assertIsNone(
            activity.approval_rate
        )

        self.assertIsNone(
            activity.error
        )

    def test_get_batch(self):
        cache = ReviewerActivityCache(
            self.gh,
            cache_dir=self.tmpdir,
            ttl=3600,
        )

        result = cache.get_batch(
            [
                "markshannon",
                "picnixz",
            ],
            delay_seconds=0,
        )

        self.assertIn(
            "markshannon",
            result,
        )

        self.assertIn(
            "picnixz",
            result,
        )

        self.assertTrue(
            all(
                isinstance(
                    activity,
                    ReviewerActivity,
                )
                for activity in result.values()
            )
        )


class ReviewerActivityModelTests(unittest.TestCase):

    def test_is_stale_fresh(self):
        activity = ReviewerActivity(
            username="alice",
            fetched_at=time.time(),
        )

        self.assertFalse(
            activity.is_stale(
                ttl_seconds=3600
            )
        )

    def test_is_stale_old(self):
        activity = ReviewerActivity(
            username="alice",
            fetched_at=time.time() - 7200,
        )

        self.assertTrue(
            activity.is_stale(
                ttl_seconds=3600
            )
        )

    def test_as_dict_round_trip(self):
        activity = ReviewerActivity(
            username="alice",
            total_reviews=42,
            approval_rate=0.75,
            approval_rate_sample_size=8,
            concern_frequency={
                "needs_test": 10
            },
            top_concerns=[
                "needs_test"
            ],
            sample_phrases=[
                "Please add a test."
            ],
            median_response_days=2.5,
            active_subsystems=[
                "Lib/asyncio"
            ],
            fetched_at=1000.0,
            available=True,
        )

        data = activity.as_dict()

        restored = ReviewerActivity.from_dict(
            data
        )

        self.assertEqual(
            restored.username,
            "alice",
        )

        self.assertEqual(
            restored.total_reviews,
            42,
        )

        self.assertAlmostEqual(
            restored.approval_rate,
            0.75,
        )

        self.assertEqual(
            restored.approval_rate_sample_size,
            8,
        )

        self.assertEqual(
            restored.median_response_days,
            2.5,
        )

        self.assertTrue(
            restored.from_cache
        )


class FormatActivityTests(unittest.TestCase):

    def test_format_merges_static_and_dynamic(self):
        activity = ReviewerActivity(
            username="markshannon",
            top_concerns=[
                "needs_test",
                "needs_benchmark",
            ],
            approval_rate=0.80,
            approval_rate_sample_size=10,
            median_response_days=2.5,
            available=True,
        )

        result = format_activity_for_report(
            {
                "username": "markshannon"
            },
            activity,
        )

        self.assertIn(
            "known_concerns",
            result,
        )

        self.assertIn(
            "dynamic_concerns",
            result,
        )

        self.assertTrue(
            len(
                result["known_concerns"]
            ) > 0,
            "Should have static known concerns from profile",
        )

        self.assertTrue(
            any(
                "test" in concern.lower()
                for concern in result[
                    "dynamic_concerns"
                ]
            ),
            "needs_test should map to a human-readable concern",
        )

        self.assertEqual(
            result["approval_rate_sample_size"],
            10,
        )

        self.assertEqual(
            result["median_response_days"],
            2.5,
        )

        self.assertTrue(
            result["activity_available"]
        )

    def test_format_unknown_reviewer(self):
        activity = ReviewerActivity(
            username="unknown_dev"
        )

        result = format_activity_for_report(
            {
                "username": "unknown_dev"
            },
            activity,
        )

        self.assertEqual(
            result["known_concerns"],
            [],
        )

        self.assertEqual(
            result["subsystems"],
            [],
        )


if __name__ == "__main__":
    unittest.main()