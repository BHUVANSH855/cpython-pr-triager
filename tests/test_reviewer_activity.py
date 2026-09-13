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
        self.assertIn("needs_test", _extract_concern_keywords(
            "Can you add a test for this case?"))

    def test_needs_news_detected(self):
        self.assertIn("needs_news", _extract_concern_keywords(
            "Please add a NEWS entry in Misc/NEWS.d/"))

    def test_needs_regen_detected(self):
        self.assertIn("needs_regen", _extract_concern_keywords(
            "Run make regen-pegen after grammar changes"))

    def test_needs_benchmark_detected(self):
        self.assertIn("needs_benchmark", _extract_concern_keywords(
            "Please provide a benchmark showing no performance regression"))

    def test_thread_safety_detected(self):
        self.assertIn("thread_safety", _extract_concern_keywords(
            "Is this thread safe under free-threading?"))

    def test_security_detected(self):
        self.assertIn("security", _extract_concern_keywords(
            "This has a security vulnerability — injection risk"))

    def test_empty_body_no_concerns(self):
        self.assertEqual(_extract_concern_keywords(""), [])

    def test_unrelated_text_no_concerns(self):
        self.assertEqual(_extract_concern_keywords("LGTM, thanks!"), [])

    def test_multiple_concerns_same_comment(self):
        text = "Please add a test and a NEWS entry and run make regen-all"
        concerns = _extract_concern_keywords(text)
        self.assertIn("needs_test", concerns)
        self.assertIn("needs_news", concerns)
        self.assertIn("needs_regen", concerns)


class ExtractPhrasesTests(unittest.TestCase):

    def test_extracts_quoted_strings(self):
        phrases = _extract_quoted_phrases(
            'The function "should be renamed" to avoid confusion.')
        self.assertTrue(any("renamed" in p for p in phrases))

    def test_extracts_please_requests(self):
        phrases = _extract_quoted_phrases(
            "Please add a test that covers the error path.")
        self.assertTrue(any("Please" in p or "add a test" in p for p in phrases))

    def test_empty_body(self):
        self.assertEqual(_extract_quoted_phrases(""), [])

    def test_max_phrases_respected(self):
        text = '"phrase one" "phrase two" "phrase three" "phrase four" "phrase five" "phrase six"'
        phrases = _extract_quoted_phrases(text, max_phrases=3)
        self.assertLessEqual(len(phrases), 3)


class BuildActivityTests(unittest.TestCase):

    def test_builds_from_empty(self):
        activity = _build_activity_from_reviews("alice", [], [])
        self.assertEqual(activity.username, "alice")
        self.assertEqual(activity.total_reviews, 0)
        self.assertIsNone(activity.approval_rate)

    def test_calculates_approval_rate(self):
        # MIN_APPROVAL_RATE_SAMPLE verdicts are required before a rate is
        # reported at all — see test_approval_rate_suppressed_below_min_sample.
        reviews = [
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "CHANGES_REQUESTED"},
            {"state": "CHANGES_REQUESTED"},
        ]
        activity = _build_activity_from_reviews("alice", [], reviews)
        self.assertAlmostEqual(activity.approval_rate, 0.67, places=1)
        self.assertEqual(activity.approval_rate_sample_size, 6)

    def test_approval_rate_suppressed_below_min_sample(self):
        """A tiny sample must not be reported as a precise percentage —
        see the reviewer sample-size audit finding."""
        reviews = [
            {"state": "APPROVED"},
            {"state": "APPROVED"},
            {"state": "CHANGES_REQUESTED"},
        ]
        activity = _build_activity_from_reviews("alice", [], reviews)
        self.assertIsNone(activity.approval_rate)
        # The sample size itself is still exposed so a report can say
        # "insufficient sample (n=3)" instead of just omitting the field.
        self.assertEqual(activity.approval_rate_sample_size, 3)

    def test_counts_concern_frequency(self):
        comments = [
            {"body": "Please add a test.", "path": "Lib/asyncio/tasks.py"},
            {"body": "This needs a test case.", "path": "Lib/asyncio/base.py"},
            {"body": "Can you add a NEWS entry?", "path": ""},
        ]
        activity = _build_activity_from_reviews("alice", comments, [])
        self.assertEqual(activity.total_reviews, 3)
        self.assertIn("needs_test", activity.concern_frequency)
        self.assertEqual(activity.concern_frequency["needs_test"], 2)
        self.assertIn("needs_news", activity.concern_frequency)

    def test_top_concerns_ordered(self):
        comments = [
            {"body": "Please add a test.", "path": ""},
            {"body": "Another test needed.", "path": ""},
            {"body": "Please add a test.", "path": ""},
            {"body": "Add a NEWS entry.", "path": ""},
        ]
        activity = _build_activity_from_reviews("alice", comments, [])
        self.assertEqual(activity.top_concerns[0], "needs_test")

    def test_active_subsystems_from_paths(self):
        comments = [
            {"body": "ok", "path": "Lib/asyncio/tasks.py"},
            {"body": "ok", "path": "Lib/asyncio/base.py"},
            {"body": "ok", "path": "Python/gc.c"},
        ]
        activity = _build_activity_from_reviews("alice", comments, [])
        self.assertTrue(any("Lib/asyncio" in s for s in activity.active_subsystems))


class ReviewerActivityCacheTests(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gh = MagicMock()
        self.gh.cache_dir = self.tmpdir
        # Default: return empty lists to avoid real API calls
        self.gh.request.return_value = []

    def test_get_returns_activity(self):
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        activity = cache.get("markshannon")
        self.assertIsInstance(activity, ReviewerActivity)
        self.assertEqual(activity.username, "markshannon")

    def test_memory_cache_avoids_second_fetch(self):
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        cache.get("markshannon")
        cache.get("markshannon")
        # Should only have called request once per page (memory hit on second call)
        self.assertLessEqual(self.gh.request.call_count, 6)

    def test_disk_cache_round_trip(self):
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        cache.get("markshannon")  # fetches and saves
        # Clear memory cache
        cache._memory.clear()
        # Second get should load from disk
        activity = cache.get("markshannon")
        self.assertTrue(activity.from_cache)

    def test_stale_disk_cache_refetches(self):
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=1)
        # Save a stale entry directly
        stale = ReviewerActivity(username="markshannon", fetched_at=time.time() - 10)
        cache._save_to_disk(stale)
        cache._memory.clear()
        # Should re-fetch because TTL=1s and entry is 10s old
        activity = cache.get("markshannon")
        self.assertFalse(activity.from_cache)

    def test_github_failure_returns_empty_activity_marked_unavailable(self):
        """Regression test: a failed fetch used to be indistinguishable
        from a real, successful "this reviewer has zero recent activity"
        result — both produced total_reviews=0 with no other signal. See
        CHANGELOG.md. A caller must be able to tell these apart via
        `available`/`error`, and a failed fetch must never be persisted
        to disk as if it were confirmed data (it would otherwise be
        frozen as "zero activity" for the full cache TTL)."""
        self.gh.request.side_effect = Exception("rate limited")
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        activity = cache.get("markshannon")

        self.assertIsInstance(activity, ReviewerActivity)
        self.assertEqual(activity.total_reviews, 0)
        self.assertFalse(activity.available)
        self.assertIn("rate limited", activity.error)

        # And it must not have been cached to disk as if it were real.
        cache_path = cache._cache_path("markshannon")
        self.assertFalse(cache_path.exists())

    def test_failed_fetch_is_retried_next_call_not_frozen(self):
        """A failed fetch is not persisted, so the very next call (even
        with the same short-lived cache instance) retries rather than
        returning the same stale failure."""
        call_count = {"n": 0}

        def flaky_request(path):
            call_count["n"] += 1
            raise Exception("boom")

        self.gh.request.side_effect = flaky_request
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        cache.get("markshannon")
        first_calls = call_count["n"]
        cache._memory.clear()  # simulate a fresh process picking up disk cache
        cache.get("markshannon")
        # Since nothing was persisted, the second call must hit the
        # network again rather than silently reusing a cached failure.
        self.assertGreater(call_count["n"], first_calls)

    def test_partial_failure_still_reports_available_with_error(self):
        """If only ONE of the two source endpoints fails, the reviewer
        may still have a partial, honestly-labeled signal rather than
        being marked fully unavailable."""

        def one_endpoint_fails(path):
            if "/pulls/comments" in path:
                raise Exception("pulls/comments down")
            return []

        self.gh.request.side_effect = one_endpoint_fails
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        activity = cache.get("markshannon")

        self.assertTrue(activity.available)
        self.assertIsNotNone(activity.error)
        self.assertIn("pulls/comments", activity.error)

    def test_github_failure_returns_empty_activity(self):
        self.gh.request.side_effect = Exception("rate limited")
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        activity = cache.get("markshannon")
        self.assertIsInstance(activity, ReviewerActivity)
        self.assertEqual(activity.total_reviews, 0)

    def test_get_batch(self):
        cache = ReviewerActivityCache(self.gh, cache_dir=self.tmpdir, ttl=3600)
        result = cache.get_batch(["markshannon", "picnixz"], delay_seconds=0)
        self.assertIn("markshannon", result)
        self.assertIn("picnixz", result)


class ReviewerActivityModelTests(unittest.TestCase):

    def test_is_stale_fresh(self):
        activity = ReviewerActivity(username="alice", fetched_at=time.time())
        self.assertFalse(activity.is_stale(ttl_seconds=3600))

    def test_is_stale_old(self):
        activity = ReviewerActivity(username="alice", fetched_at=time.time() - 7200)
        self.assertTrue(activity.is_stale(ttl_seconds=3600))

    def test_as_dict_round_trip(self):
        activity = ReviewerActivity(
            username="alice",
            total_reviews=42,
            approval_rate=0.75,
            concern_frequency={"needs_test": 10},
            top_concerns=["needs_test"],
            fetched_at=1000.0,
        )
        d = activity.as_dict()
        restored = ReviewerActivity.from_dict(d)
        self.assertEqual(restored.username, "alice")
        self.assertEqual(restored.total_reviews, 42)
        self.assertAlmostEqual(restored.approval_rate, 0.75)
        self.assertTrue(restored.from_cache)


class FormatActivityTests(unittest.TestCase):

    def test_format_merges_static_and_dynamic(self):
        activity = ReviewerActivity(
            username="markshannon",
            top_concerns=["needs_test", "needs_benchmark"],
            approval_rate=0.80,
        )
        result = format_activity_for_report(
            {"username": "markshannon"},
            activity,
        )
        self.assertIn("known_concerns", result)
        self.assertIn("dynamic_concerns", result)
        self.assertTrue(len(result["known_concerns"]) > 0,
                        "Should have static known concerns from profile")
        self.assertTrue(
            any("test" in c.lower() for c in result["dynamic_concerns"]),
            "needs_test should map to a human-readable concern",
        )

    def test_format_unknown_reviewer(self):
        activity = ReviewerActivity(username="unknown_dev")
        result = format_activity_for_report({"username": "unknown_dev"}, activity)
        self.assertEqual(result["known_concerns"], [])
        self.assertEqual(result["subsystems"], [])


if __name__ == "__main__":
    unittest.main()