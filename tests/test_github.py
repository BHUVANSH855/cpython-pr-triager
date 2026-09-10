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


class SourceEvidenceGitHubTests(unittest.TestCase):
    class FakeGitHub(GitHub):
        def __init__(self):
            super().__init__(cache_ttl=0)
            self.content_calls = []

        def raw_content(self, path, ref=None):
            self.content_calls.append((path, ref))

            contents = {
                ("Lib/foo.py", "base-sha"): "base python\n",
                ("Lib/foo.py", "head-sha"): "head python\n",
                ("Objects/foo.c", "base-sha"): "base c\n",
                ("Objects/foo.c", "head-sha"): "head c\n",
                ("Include/foo.h", "base-sha"): "base header\n",
                ("Include/foo.h", "head-sha"): "head header\n",
                ("added.py", "head-sha"): "new file\n",
                ("deleted.py", "base-sha"): "old file\n",
            }

            return contents.get((path, ref))

    def test_source_file_contents_collects_base_and_head_for_modified_files(
        self
    ):
        gh = self.FakeGitHub()

        files = [
            {
                "filename": "Lib/foo.py",
                "status": "modified",
            },
            {
                "filename": "Objects/foo.c",
                "status": "modified",
            },
            {
                "filename": "Include/foo.h",
                "status": "modified",
            },
        ]

        result = gh.source_file_contents(
            files,
            "base-sha",
            "head-sha",
        )

        self.assertEqual(
            result["base"],
            {
                "Lib/foo.py": "base python\n",
                "Objects/foo.c": "base c\n",
                "Include/foo.h": "base header\n",
            },
        )

        self.assertEqual(
            result["head"],
            {
                "Lib/foo.py": "head python\n",
                "Objects/foo.c": "head c\n",
                "Include/foo.h": "head header\n",
            },
        )

    def test_source_file_contents_collects_only_head_for_added_files(self):
        gh = self.FakeGitHub()

        files = [
            {
                "filename": "added.py",
                "status": "added",
            },
        ]

        result = gh.source_file_contents(
            files,
            "base-sha",
            "head-sha",
        )

        self.assertEqual(
            result["base"],
            {},
        )

        self.assertEqual(
            result["head"],
            {
                "added.py": "new file\n",
            },
        )

        self.assertNotIn(
            ("added.py", "base-sha"),
            gh.content_calls,
        )

    def test_source_file_contents_collects_only_base_for_removed_files(self):
        gh = self.FakeGitHub()

        files = [
            {
                "filename": "deleted.py",
                "status": "removed",
            },
        ]

        result = gh.source_file_contents(
            files,
            "base-sha",
            "head-sha",
        )

        self.assertEqual(
            result["base"],
            {
                "deleted.py": "old file\n",
            },
        )

        self.assertEqual(
            result["head"],
            {},
        )

        self.assertNotIn(
            ("deleted.py", "head-sha"),
            gh.content_calls,
        )

    def test_source_file_contents_skips_unsupported_files(self):
        gh = self.FakeGitHub()

        files = [
            {
                "filename": "Doc/library/foo.rst",
                "status": "modified",
            },
            {
                "filename": "Misc/NEWS.d/next/Example.rst",
                "status": "modified",
            },
        ]

        result = gh.source_file_contents(
            files,
            "base-sha",
            "head-sha",
        )

        self.assertEqual(
            result,
            {
                "base": {},
                "head": {},
            },
        )

        self.assertEqual(
            gh.content_calls,
            [],
        )

    def test_source_file_contents_does_not_fetch_base_without_base_sha(
        self
    ):
        gh = self.FakeGitHub()

        files = [
            {
                "filename": "Lib/foo.py",
                "status": "modified",
            },
        ]

        result = gh.source_file_contents(
            files,
            None,
            "head-sha",
        )

        self.assertEqual(
            result["base"],
            {},
        )

        self.assertEqual(
            result["head"],
            {
                "Lib/foo.py": "head python\n",
            },
        )

        self.assertNotIn(
            ("Lib/foo.py", None),
            gh.content_calls,
        )

    def test_source_file_contents_does_not_fetch_head_without_head_sha(
        self
    ):
        gh = self.FakeGitHub()

        files = [
            {
                "filename": "Lib/foo.py",
                "status": "modified",
            },
        ]

        result = gh.source_file_contents(
            files,
            "base-sha",
            None,
        )

        self.assertEqual(
            result["base"],
            {
                "Lib/foo.py": "base python\n",
            },
        )

        self.assertEqual(
            result["head"],
            {},
        )

        self.assertNotIn(
            ("Lib/foo.py", None),
            gh.content_calls,
        )

    def test_source_file_contents_records_retrieval_failures(self):
        gh = self.FakeGitHub()

        def failing_raw_content(path, ref=None):
            if path == "Objects/foo.c" and ref == "base-sha":
                raise GitHubError("base content unavailable")

            return "content\n"

        gh.raw_content = failing_raw_content

        errors = {}

        result = gh.source_file_contents(
            [
                {
                    "filename": "Objects/foo.c",
                    "status": "modified",
                },
            ],
            "base-sha",
            "head-sha",
            errors,
        )

        self.assertEqual(
            result["base"],
            {},
        )

        self.assertEqual(
            result["head"],
            {
                "Objects/foo.c": "content\n",
            },
        )

        self.assertIn(
            "base_file:Objects/foo.c",
            errors,
        )

        self.assertEqual(
            errors["base_file:Objects/foo.c"],
            "base content unavailable",
        )


class SourceEvidenceIntegrationGitHubTests(unittest.TestCase):
    class FakeGitHub(GitHub):
        def __init__(self):
            super().__init__(cache_ttl=0)
            self.source_calls = []

        def pr(self, number):
            return {
                "number": number,
                "base": {"sha": "base-sha"},
                "head": {"sha": "head-sha"},
            }

        def files(self, number):
            return [
                {
                    "filename": "Lib/foo.py",
                    "status": "modified",
                },
                {
                    "filename": "Objects/foo.c",
                    "status": "modified",
                },
                {
                    "filename": "added.py",
                    "status": "added",
                },
                {
                    "filename": "deleted.py",
                    "status": "removed",
                },
            ]

        def reviews(self, number):
            return []

        def review_comments(self, number):
            return []

        def issue_comments(self, number):
            return []

        def timeline(self, number):
            return []

        def codeowners(self, base_sha):
            return None, None

        def source_file_contents(
            self,
            files,
            base_sha,
            head_sha,
            errors=None,
        ):
            self.source_calls.append(
                (files, base_sha, head_sha)
            )
            return {
                "base": {
                    "Lib/foo.py": "base python\n",
                    "Objects/foo.c": "base c\n",
                    "deleted.py": "old file\n",
                },
                "head": {
                    "Lib/foo.py": "head python\n",
                    "Objects/foo.c": "head c\n",
                    "added.py": "new file\n",
                },
            }

        def base_file_contents(
            self,
            files,
            base_sha,
            errors=None,
        ):
            return {
                "Lib/foo.py": "base python\n",
            }

        def check_runs(self, sha):
            return {
                "total_count": 0,
                "check_runs": [],
            }

        def statuses(self, sha):
            return []

        def _collect_file_histories(
            self,
            files,
            base_sha,
            errors,
        ):
            return

        def stats(self):
            return {
                "api_calls": self.calls,
                "cache_hits": self.cache_hits,
            }

    def test_pull_request_evidence_includes_source_file_contents(self):
        gh = self.FakeGitHub()

        result = gh.pull_request_evidence(123)

        self.assertEqual(
            result["evidence"]["source_file_contents"],
            {
                "base": {
                    "Lib/foo.py": "base python\n",
                    "Objects/foo.c": "base c\n",
                    "deleted.py": "old file\n",
                },
                "head": {
                    "Lib/foo.py": "head python\n",
                    "Objects/foo.c": "head c\n",
                    "added.py": "new file\n",
                },
            },
        )

        self.assertEqual(
            gh.source_calls[0][1:],
            ("base-sha", "head-sha"),
        )

    def test_pull_request_evidence_preserves_base_file_contents(
        self,
    ):
        gh = self.FakeGitHub()

        result = gh.pull_request_evidence(123)

        self.assertEqual(
            result["evidence"]["base_file_contents"],
            {
                "Lib/foo.py": "base python\n",
            },
        )


class HistoryIntegrationGitHubTests(unittest.TestCase):
    class FakeGitHub(GitHub):
        def __init__(self):
            super().__init__(cache_ttl=0)
            self.history_calls = []

        def pr(self, number):
            return {
                "number": number,
                "base": {"sha": "base-sha"},
                "head": {"sha": "head-sha"},
            }

        def files(self, number):
            return [
                {
                    "filename": "Objects/dictobject.c",
                    "status": "modified",
                },
                {
                    "filename": "Lib/foo.py",
                    "status": "modified",
                },
                {
                    "filename": "Doc/library/foo.rst",
                    "status": "modified",
                },
                {
                    "filename": "Lib/test/test_foo.py",
                    "status": "modified",
                },
                {
                    "filename": "added.py",
                    "status": "added",
                },
                {
                    "filename": "deleted.py",
                    "status": "removed",
                },
            ]

        def reviews(self, number):
            return []

        def review_comments(self, number):
            return []

        def issue_comments(self, number):
            return []

        def timeline(self, number):
            return []

        def codeowners(self, base_sha):
            return None, None

        def base_file_contents(self, files, base_sha, errors=None):
            return {}

        def source_file_contents(self, files, base_sha, errors=None):
            return {}

        def check_runs(self, sha):
            return {
                "total_count": 0,
                "check_runs": [],
            }

        def statuses(self, sha):
            return []

        def file_history(
            self,
            path,
            base_sha,
            *,
            max_count=5,
        ):
            self.history_calls.append(
                (path, base_sha, max_count)
            )
            return [
                {
                    "sha": "abc123",
                    "message": f"history for {path}",
                }
            ]

        def stats(self):
            return {
                "api_calls": self.calls,
                "cache_hits": self.cache_hits,
            }

    def test_pull_request_evidence_attaches_history_to_eligible_files(self):
        gh = self.FakeGitHub()
        result = gh.pull_request_evidence(123)

        files = result["evidence"]["files"]
        files_by_name = {
            item["filename"]: item
            for item in files
        }

        self.assertTrue(
            files_by_name["Objects/dictobject.c"].get("history")
        )
        self.assertTrue(
            files_by_name["Lib/foo.py"].get("history")
        )

        self.assertNotIn(
            "history",
            files_by_name["Doc/library/foo.rst"],
        )
        self.assertNotIn(
            "history",
            files_by_name["Lib/test/test_foo.py"],
        )
        self.assertNotIn(
            "history",
            files_by_name["added.py"],
        )
        self.assertNotIn(
            "history",
            files_by_name["deleted.py"],
        )

    def test_history_uses_pr_base_sha(self):
        gh = self.FakeGitHub()
        gh.pull_request_evidence(123)

        self.assertEqual(
            {call[1] for call in gh.history_calls},
            {"base-sha"},
        )

    def test_history_collection_is_bounded(self):
        gh = self.FakeGitHub()
        files = [
            {
                "filename": f"Objects/object_{index}.c",
                "status": "modified",
            }
            for index in range(30)
        ]
        gh.files = lambda number: files

        gh.pull_request_evidence(123)

        self.assertEqual(
            len(gh.history_calls),
            20,
        )
        self.assertTrue(
            all(
                call[2] == 5
                for call in gh.history_calls
            )
        )

    def test_history_failure_is_partial_and_recorded(self):
        gh = self.FakeGitHub()

        def failing_history(
            path,
            base_sha,
            *,
            max_count=5,
        ):
            if path == "Objects/dictobject.c":
                raise RuntimeError("history unavailable")
            return [
                {
                    "sha": "abc123",
                    "message": "ok",
                }
            ]

        gh.file_history = failing_history
        result = gh.pull_request_evidence(123)

        files = result["evidence"]["files"]
        target = next(
            item
            for item in files
            if item["filename"] == "Objects/dictobject.c"
        )

        self.assertEqual(
            target["history"],
            [],
        )
        self.assertIn(
            "history:Objects/dictobject.c",
            result["errors"],
        )
        self.assertTrue(
            any(
                item.get("history")
                for item in files
                if item["filename"] == "Lib/foo.py"
            )
        )

    def test_history_is_not_collected_without_base_sha(self):
        gh = self.FakeGitHub()
        gh.pr = lambda number: {
            "number": number,
            "base": {},
            "head": {},
        }

        result = gh.pull_request_evidence(123)

        self.assertEqual(
            gh.history_calls,
            [],
        )
        self.assertNotIn(
            "history:Objects/dictobject.c",
            result["errors"],
        )



if __name__ == "__main__":
    unittest.main()
