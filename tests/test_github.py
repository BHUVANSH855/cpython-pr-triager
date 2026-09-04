from __future__ import annotations

import base64
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from scripts.triager.github import GitHub, GitHubError


class FakeResponse:
    def __init__(
        self,
        payload,
        *,
        headers=None,
    ):
        self.payload = payload
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(
            self.payload
        ).encode("utf-8")


def get_query_page(url: str) -> int:
    from urllib.parse import parse_qs, urlsplit

    query = parse_qs(
        urlsplit(url).query
    )

    return int(
        query.get("page", ["1"])[0]
    )


class GitHubTests(unittest.TestCase):
    def test_paginate_fetches_all_pages(self):
        requests = []

        responses = {
            1: [{"id": 1}, {"id": 2}],
            2: [{"id": 3}],
        }

        def opener(request, timeout):
            url = request.full_url
            requests.append(url)

            page = get_query_page(url)

            return FakeResponse(
                responses.get(page, [])
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                opener=opener,
            )

            result = client.paginate(
                "/test",
                per_page=2,
            )

        self.assertEqual(
            result,
            [
                {"id": 1},
                {"id": 2},
                {"id": 3},
            ],
        )

        self.assertEqual(
            len(requests),
            2,
        )

        self.assertEqual(
            get_query_page(requests[0]),
            1,
        )

        self.assertEqual(
            get_query_page(requests[1]),
            2,
        )

    def test_cache_hit_avoids_second_request(self):
        calls = []

        def opener(request, timeout):
            calls.append(request.full_url)

            return FakeResponse(
                {"value": 123}
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=900,
                opener=opener,
            )

            first = client.request(
                "/test"
            )

            second = client.request(
                "/test"
            )

        self.assertEqual(
            first,
            {"value": 123},
        )

        self.assertEqual(
            second,
            {"value": 123},
        )

        self.assertEqual(
            len(calls),
            1,
        )

        self.assertEqual(
            client.cache_hits,
            1,
        )

        self.assertEqual(
            client.calls,
            1,
        )

    def test_cache_can_be_disabled(self):
        calls = []

        def opener(request, timeout):
            calls.append(request.full_url)

            return FakeResponse(
                {"value": len(calls)}
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=900,
                opener=opener,
            )

            first = client.request(
                "/test",
                use_cache=False,
            )

            second = client.request(
                "/test",
                use_cache=False,
            )

        self.assertEqual(
            first,
            {"value": 1},
        )

        self.assertEqual(
            second,
            {"value": 2},
        )

        self.assertEqual(
            len(calls),
            2,
        )

    def test_request_retries_transient_http_failure(self):
        calls = []

        def opener(request, timeout):
            calls.append(request.full_url)

            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    503,
                    "temporary",
                    {},
                    None,
                )

            return FakeResponse(
                {"ok": True}
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=2,
                opener=opener,
            )

            with patch(
                "scripts.triager.github.time.sleep"
            ):
                result = client.request(
                    "/retry"
                )

        self.assertEqual(
            result,
            {"ok": True},
        )

        self.assertEqual(
            len(calls),
            2,
        )

    def test_request_raises_on_non_retryable_http_failure(self):
        def opener(request, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                404,
                "not found",
                {},
                None,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=4,
                opener=opener,
            )

            with self.assertRaises(
                GitHubError
            ) as context:
                client.request(
                    "/missing"
                )

        self.assertIn(
            "GitHub HTTP 404",
            str(context.exception),
        )

        self.assertIn(
            "not found",
            str(context.exception),
        )

    def test_rate_limit_metadata_is_recorded(self):
        headers = {
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": "1234567890",
        }

        def opener(request, timeout):
            return FakeResponse(
                {"ok": True},
                headers=headers,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                opener=opener,
            )

            result = client.request(
                "/metadata"
            )

            stats = client.stats()

        self.assertEqual(
            result,
            {"ok": True},
        )

        self.assertEqual(
            stats["rate_limit_remaining"],
            "4999",
        )

        self.assertEqual(
            stats["rate_limit_reset"],
            "1234567890",
        )

    def test_check_runs_are_paginated(self):
        requests = []

        responses = {
            1: {
                "total_count": 3,
                "check_runs": [
                    {"name": "check-1"},
                    {"name": "check-2"},
                ],
            },
            2: {
                "total_count": 3,
                "check_runs": [
                    {"name": "check-3"},
                ],
            },
        }

        def opener(request, timeout):
            url = request.full_url
            requests.append(url)

            page = get_query_page(url)

            return FakeResponse(
                responses.get(
                    page,
                    {
                        "total_count": 3,
                        "check_runs": [],
                    },
                )
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                opener=opener,
            )

            result = client.check_runs(
                "abc123",
                per_page=2,
            )

        self.assertEqual(
            result["total_count"],
            3,
        )

        self.assertEqual(
            result["check_runs"],
            [
                {"name": "check-1"},
                {"name": "check-2"},
                {"name": "check-3"},
            ],
        )

        self.assertEqual(
            len(requests),
            2,
        )

        self.assertEqual(
            get_query_page(requests[0]),
            1,
        )

        self.assertEqual(
            get_query_page(requests[1]),
            2,
        )

    def test_content_encodes_path_and_ref(self):
        captured = []

        def opener(request, timeout):
            captured.append(
                request.full_url
            )

            return FakeResponse(
                {
                    "encoding": "base64",
                    "content": base64.b64encode(
                        b"hello"
                    ).decode("ascii"),
                }
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                opener=opener,
            )

            text = client.raw_content(
                "path/with space.txt",
                "feature/test branch",
            )

        self.assertEqual(
            text,
            "hello",
        )

        self.assertEqual(
            len(captured),
            1,
        )

        self.assertIn(
            "path/with%20space.txt",
            captured[0],
        )

        self.assertIn(
            "ref=feature%2Ftest%20branch",
            captured[0],
        )

    def test_codeowners_uses_first_available_candidate(self):
        requests = []

        encoded = base64.b64encode(
            b"src/* @python/core\n"
        ).decode("ascii")

        def opener(request, timeout):
            url = request.full_url
            requests.append(url)

            if (
                ".github/CODEOWNERS"
                in url
            ):
                raise urllib.error.HTTPError(
                    url,
                    404,
                    "not found",
                    {},
                    None,
                )

            return FakeResponse(
                {
                    "encoding": "base64",
                    "content": encoded,
                }
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=1,
                opener=opener,
            )

            path, text = client.codeowners(
                "abc123"
            )

        self.assertEqual(
            path,
            "CODEOWNERS",
        )

        self.assertEqual(
            text,
            "src/* @python/core\n",
        )

        self.assertEqual(
            len(requests),
            2,
        )

    def test_pull_request_evidence_records_secondary_errors(self):
        def opener(request, timeout):
            url = request.full_url

            if url.endswith(
                "/pulls/123"
            ):
                return FakeResponse(
                    {
                        "number": 123,
                        "base": {
                            "sha": "base-sha",
                        },
                        "head": {
                            "sha": "head-sha",
                        },
                    }
                )

            raise urllib.error.HTTPError(
                url,
                500,
                "temporary failure",
                {},
                None,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=1,
                opener=opener,
            )

            result = client.pull_request_evidence(
                123
            )

        self.assertEqual(
            result["evidence"]["pr"]["number"],
            123,
        )

        self.assertIn(
            "files",
            result["errors"],
        )

        self.assertIn(
            "reviews",
            result["errors"],
        )

        self.assertIn(
            "check_runs",
            result["errors"],
        )

        self.assertIn(
            "statuses",
            result["errors"],
        )

        self.assertIn(
            "stats",
            result,
        )

    def test_stats_start_empty(self):
        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
            )

            self.assertEqual(
                client.stats(),
                {
                    "api_calls": 0,
                    "cache_hits": 0,
                    "rate_limit_remaining": None,
                    "rate_limit_reset": None,
                },
            )

    def test_issue_fetches_issue_resource(self):
        requests = []

        def opener(request, timeout):
            requests.append(
                request.full_url
            )

            return FakeResponse(
                {
                    "number": 30341,
                    "title": "Example issue",
                    "state": "closed",
                }
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                opener=opener,
            )

            result = client.issue(30341)

        self.assertEqual(
            result["number"],
            30341,
        )

        self.assertEqual(
            result["title"],
            "Example issue",
        )

        self.assertEqual(
            requests,
            [
                "https://api.github.com/repos/python/cpython/issues/30341"
            ],
        )

    def test_linked_issues_deduplicates_numbers(self):
        requested = []

        def opener(request, timeout):
            url = request.full_url

            number = int(
                url.rsplit("/", 1)[1]
            )

            requested.append(number)

            return FakeResponse(
                {
                    "number": number,
                    "title": f"Issue {number}",
                }
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                opener=opener,
            )

            result = client.linked_issues(
                [30341, 30342, 30341, 30342]
            )

        self.assertEqual(
            requested,
            [
                30341,
                30342,
            ],
        )

        self.assertEqual(
            [item["number"] for item in result],
            [
                30341,
                30342,
            ],
        )

    def test_pull_request_evidence_includes_linked_issues(self):
        requested = []

        def opener(request, timeout):
            url = request.full_url
            requested.append(url)

            if url.endswith(
                "/pulls/123"
            ):
                return FakeResponse(
                    {
                        "number": 123,
                        "base": {
                            "sha": "base-sha",
                        },
                        "head": {
                            "sha": "head-sha",
                        },
                    }
                )

            if url.endswith(
                "/issues/456"
            ):
                return FakeResponse(
                    {
                        "number": 456,
                        "title": "Linked issue",
                    }
                )

            raise urllib.error.HTTPError(
                url,
                404,
                "not found",
                {},
                None,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=1,
                opener=opener,
            )

            result = client.pull_request_evidence(
                123,
                linked_issue_numbers=[456],
            )

        self.assertEqual(
            result["evidence"]["linked_issues"],
            [
                {
                    "number": 456,
                    "title": "Linked issue",
                }
            ],
        )

        self.assertNotIn(
            "linked_issues",
            result["errors"],
        )

    def test_pull_request_evidence_records_linked_issue_failure(self):
        def opener(request, timeout):
            url = request.full_url

            if url.endswith(
                "/pulls/123"
            ):
                return FakeResponse(
                    {
                        "number": 123,
                        "base": {
                            "sha": "base-sha",
                        },
                        "head": {
                            "sha": "head-sha",
                        },
                    }
                )

            raise urllib.error.HTTPError(
                url,
                404,
                "not found",
                {},
                None,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=1,
                opener=opener,
            )

            result = client.pull_request_evidence(
                123,
                linked_issue_numbers=[456],
            )

        self.assertEqual(
            result["evidence"]["linked_issues"],
            [],
        )

        self.assertIn(
            "linked_issues",
            result["errors"],
        )

    def test_linked_issue_evidence_normalizes_human_comments_and_labels(
        self
    ):
        def opener(request, timeout):
            url = request.full_url

            if url.endswith("/issues/30341"):
                return FakeResponse(
                    {
                        "number": 30341,
                        "title": "Example issue",
                        "state": "closed",
                        "state_reason": None,
                        "labels": [
                            {"name": "skip news"},
                        ],
                        "created_at": "2022-01-02T00:00:00Z",
                        "closed_at": "2022-01-04T00:00:00Z",
                        "body": "Issue body",
                    }
                )

            if "/issues/30341/comments?" in url:
                return FakeResponse(
                    [
                        {
                            "user": {
                                "login": "alice",
                            },
                            "created_at": "2022-01-03T00:00:00Z",
                            "body": "Human comment",
                        },
                        {
                            "user": {
                                "login": "bedevere-bot",
                            },
                            "created_at": "2022-01-03T00:01:00Z",
                            "body": "Bot comment",
                        },
                    ]
                )

            if "/issues/30341/timeline?" in url:
                return FakeResponse(
                    [
                        {
                            "event": "labeled",
                            "created_at": "2022-01-03T00:02:00Z",
                            "actor": {
                                "login": "alice",
                            },
                            "label": {
                                "name": "skip news",
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
                )

            raise urllib.error.HTTPError(
                url,
                404,
                "not found",
                {},
                None,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=1,
                opener=opener,
            )

            result = client.linked_issue_evidence(
                30341,
                bot_logins={"bedevere-bot"},
            )

        self.assertEqual(
            result["number"],
            30341,
        )

        self.assertEqual(
            result["title"],
            "Example issue",
        )

        self.assertEqual(
            result["labels"],
            ["skip news"],
        )

        self.assertEqual(
            result["comments"],
            [
                {
                    "login": "alice",
                    "date": "2022-01-03T00:00:00Z",
                    "body": "Human comment",
                }
            ],
        )

        self.assertEqual(
            result["label_history"],
            [
                {
                    "label": "skip news",
                    "actor": "alice",
                    "date": "2022-01-03T00:02:00Z",
                }
            ],
        )

        self.assertEqual(
            result["cross_references"],
            [
                {
                    "number": 30342,
                    "title": "Another issue",
                }
            ],
        )

    def test_linked_issue_evidence_batch_isolates_failures(self):
        def opener(request, timeout):
            url = request.full_url

            if url.endswith("/issues/1"):
                return FakeResponse(
                    {
                        "number": 1,
                        "title": "Issue 1",
                        "state": "open",
                        "labels": [],
                    }
                )

            if "/issues/1/comments?" in url:
                return FakeResponse([])

            if "/issues/1/timeline?" in url:
                return FakeResponse([])

            raise urllib.error.HTTPError(
                url,
                404,
                "not found",
                {},
                None,
            )

        with tempfile.TemporaryDirectory() as temp:
            client = GitHub(
                cache_dir=Path(temp),
                cache_ttl=0,
                retries=1,
                opener=opener,
            )

            result = client.linked_issue_evidence_batch(
                [1, 2, 1],
            )

        self.assertEqual(
            result[0]["number"],
            1,
        )

        self.assertEqual(
            result[0]["title"],
            "Issue 1",
        )

        self.assertEqual(
            result[1]["number"],
            2,
        )

        self.assertIn(
            "error",
            result[1],
        )

        self.assertEqual(
            len(result),
            2,
        )


if __name__ == "__main__":
    unittest.main()
