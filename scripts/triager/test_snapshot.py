from __future__ import annotations

from scripts.triager.snapshot import ReviewSnapshot


class FakeGitHub:
    repo = "python/cpython"

    def __init__(self, result):
        self.result = result
        self.calls = []

    def pull_request_evidence(self, number, *, linked_issue_numbers=None):
        self.calls.append(
            (
                number,
                linked_issue_numbers,
            )
        )
        return self.result


def make_result():
    return {
        "evidence": {
            "pr": {
                "number": 123456,
                "title": "Test PR",
                "base": {
                    "sha": "base-sha",
                    "repo": {
                        "full_name": "python/cpython",
                    },
                },
                "head": {
                    "sha": "head-sha",
                },
            },
            "files": [
                {
                    "filename": "Python/example.c",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@",
                }
            ],
            "reviews": [
                {
                    "id": 1,
                    "state": "APPROVED",
                }
            ],
            "review_comments": [
                {
                    "id": 2,
                    "body": "Looks good.",
                }
            ],
            "issue_comments": [
                {
                    "id": 3,
                    "body": "Thanks!",
                }
            ],
            "timeline": [
                {
                    "event": "committed",
                    "sha": "head-sha",
                }
            ],
            "linked_issues": [
                {
                    "number": 999999,
                    "title": "Related issue",
                }
            ],
            "base_file_contents": {
                "Python/example.c": "old source\n",
            },
            "codeowners_path": ".github/CODEOWNERS",
            "codeowners_text": "* @python/core-workgroup",
            "check_runs": {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "CI",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            },
            "statuses": [
                {
                    "state": "success",
                }
            ],
            "head_sha": "head-sha",
        },
        "errors": {},
        "stats": {
            "api_calls": 10,
            "cache_hits": 2,
            "rate_limit_remaining": 4900,
            "rate_limit_reset": 1234567890,
        },
    }


def test_collect_builds_snapshot_from_existing_evidence():
    gh = FakeGitHub(make_result())

    snapshot = ReviewSnapshot.collect(
        gh,
        123456,
        linked_issue_numbers=[999999],
    )

    assert snapshot.pr_number == 123456
    assert snapshot.repository == "python/cpython"
    assert snapshot.base_sha == "base-sha"
    assert snapshot.head_sha == "head-sha"

    assert len(snapshot.files) == 1
    assert len(snapshot.reviews) == 1
    assert len(snapshot.review_comments) == 1
    assert len(snapshot.issue_comments) == 1
    assert len(snapshot.timeline) == 1
    assert len(snapshot.linked_issues) == 1

    assert snapshot.base_file_contents == {
        "Python/example.c": "old source\n",
    }

    assert snapshot.codeowners_path == ".github/CODEOWNERS"
    assert snapshot.codeowners_text == "* @python/core-workgroup"

    assert snapshot.check_runs["total_count"] == 1
    assert snapshot.statuses == [{"state": "success"}]

    assert snapshot.evidence_errors == {}
    assert snapshot.collection_stats["api_calls"] == 10
    assert snapshot.is_complete is True

    assert gh.calls == [
        (
            123456,
            [999999],
        )
    ]


def test_snapshot_completeness_reports_collection_errors():
    result = make_result()
    result["errors"] = {
        "timeline": "timeline unavailable",
        "statuses": "statuses unavailable",
    }

    gh = FakeGitHub(result)

    snapshot = ReviewSnapshot.collect(gh, 123456)

    assert snapshot.is_complete is False

    completeness = snapshot.completeness()

    assert "timeline" in completeness["missing"]
    assert "statuses" in completeness["missing"]
    assert "files" in completeness["available"]
    assert completeness["complete"] is False
    assert completeness["error_count"] == 2


def test_empty_base_contents_are_not_assumed_to_be_an_error():
    result = make_result()
    result["evidence"]["base_file_contents"] = {}

    gh = FakeGitHub(result)

    snapshot = ReviewSnapshot.collect(gh, 123456)

    assert snapshot.base_file_contents == {}
    assert "base_file_contents" in snapshot.completeness()["available"]


def test_to_evidence_preserves_report_compatible_shape():
    gh = FakeGitHub(make_result())

    snapshot = ReviewSnapshot.collect(gh, 123456)

    evidence = snapshot.to_evidence()

    assert evidence["pr"] == snapshot.pr
    assert evidence["files"] == snapshot.files
    assert evidence["reviews"] == snapshot.reviews
    assert evidence["review_comments"] == snapshot.review_comments
    assert evidence["issue_comments"] == snapshot.issue_comments
    assert evidence["timeline"] == snapshot.timeline
    assert evidence["linked_issues"] == snapshot.linked_issues
    assert evidence["base_file_contents"] == snapshot.base_file_contents
    assert evidence["codeowners_path"] == snapshot.codeowners_path
    assert evidence["codeowners_text"] == snapshot.codeowners_text
    assert evidence["check_runs"] == snapshot.check_runs
    assert evidence["statuses"] == snapshot.statuses
    assert evidence["head_sha"] == snapshot.head_sha
    assert evidence["evidence_errors"] == snapshot.evidence_errors


def test_collect_rejects_invalid_pr_numbers():
    gh = FakeGitHub(make_result())

    for number in (0, -1, "123456", None):
        try:
            ReviewSnapshot.collect(gh, number)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"expected ValueError for PR number {number!r}"
            )


def test_collect_rejects_invalid_collector_result():
    gh = FakeGitHub(None)

    try:
        ReviewSnapshot.collect(gh, 123456)
    except TypeError as exc:
        assert "dictionary" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_collect_rejects_missing_pr_data():
    result = make_result()
    result["evidence"]["pr"] = None

    gh = FakeGitHub(result)

    try:
        ReviewSnapshot.collect(gh, 123456)
    except TypeError as exc:
        assert "invalid PR data" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_head_sha_falls_back_to_pr_head():
    result = make_result()
    result["evidence"].pop("head_sha")

    gh = FakeGitHub(result)

    snapshot = ReviewSnapshot.collect(gh, 123456)

    assert snapshot.head_sha == "head-sha"


def test_repository_falls_back_to_github_client_repo():
    result = make_result()
    result["evidence"]["pr"]["base"]["repo"] = {}

    gh = FakeGitHub(result)

    snapshot = ReviewSnapshot.collect(gh, 123456)

    assert snapshot.repository == "python/cpython"