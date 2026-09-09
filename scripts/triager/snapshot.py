"""Review snapshot orchestration for CPython pull-request triage.

This module coordinates the existing GitHub evidence collectors into one
review snapshot. It deliberately does not perform semantic analysis or AI
synthesis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _list_value(mapping: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a list-valued evidence field without exposing mutable input."""
    value = mapping.get(key)
    if not isinstance(value, list):
        return []
    return list(value)


def _dict_value(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    """Return a dictionary-valued evidence field without exposing input."""
    value = mapping.get(key)
    if not isinstance(value, dict):
        return {}
    return dict(value)


def _optional_string(value: Any) -> str | None:
    """Normalize an optional string value."""
    if isinstance(value, str) and value:
        return value
    return None


def _check_runs_value(value: Any) -> dict[str, Any]:
    """Normalize the check-runs evidence structure."""
    if not isinstance(value, dict):
        return {
            "total_count": 0,
            "check_runs": [],
        }

    result = dict(value)

    check_runs = result.get("check_runs")
    if not isinstance(check_runs, list):
        result["check_runs"] = []

    total_count = result.get("total_count")
    if not isinstance(total_count, int):
        result["total_count"] = len(result["check_runs"])

    return result


@dataclass
class ReviewSnapshot:
    """Immutable-in-practice evidence snapshot for one pull request."""

    pr_number: int
    captured_at: str
    repository: str
    pr: dict[str, Any]

    files: list[dict[str, Any]] = field(default_factory=list)
    reviews: list[dict[str, Any]] = field(default_factory=list)
    review_comments: list[dict[str, Any]] = field(default_factory=list)
    issue_comments: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    linked_issues: list[dict[str, Any]] = field(default_factory=list)

    base_file_contents: dict[str, str] = field(default_factory=dict)
    codeowners_path: str | None = None
    codeowners_text: str | None = None

    check_runs: dict[str, Any] = field(
        default_factory=lambda: {
            "total_count": 0,
            "check_runs": [],
        }
    )
    statuses: list[dict[str, Any]] = field(default_factory=list)

    head_sha: str | None = None
    base_sha: str | None = None

    evidence_errors: dict[str, str] = field(default_factory=dict)
    collection_stats: dict[str, Any] = field(default_factory=dict)

    references: dict[str, list[Any]] = field(
        default_factory=lambda: {
            "issues": [],
            "peps": [],
            "discussions": [],
        }
    )

    @classmethod
    def collect(
        cls,
        gh: Any,
        number: int,
        *,
        linked_issue_numbers: (
            list[int] | tuple[int, ...] | set[int] | None
        ) = None,
    ) -> ReviewSnapshot:
        """Collect one complete PR review snapshot.

        Existing GitHub collection remains responsible for network access.
        This layer owns orchestration and reference discovery.
        """
        if not isinstance(number, int) or number <= 0:
            raise ValueError("number must be a positive integer")

        result = gh.pull_request_evidence(
            number,
            linked_issue_numbers=linked_issue_numbers,
        )

        if not isinstance(result, dict):
            raise TypeError("pull_request_evidence() must return a dictionary")

        evidence = result.get("evidence")
        if not isinstance(evidence, dict):
            raise TypeError("pull_request_evidence() returned invalid evidence")

        pr = evidence.get("pr")
        if not isinstance(pr, dict):
            raise TypeError("pull_request_evidence() returned invalid PR data")

        base = pr.get("base") or {}
        head = pr.get("head") or {}

        files = _list_value(evidence, "files")
        reviews = _list_value(evidence, "reviews")
        review_comments = _list_value(evidence, "review_comments")
        issue_comments = _list_value(evidence, "issue_comments")
        timeline = _list_value(evidence, "timeline")

        references = cls._discover_references(
            number,
            pr,
            reviews,
            review_comments,
            issue_comments,
            timeline,
        )

        linked_issues = _list_value(evidence, "linked_issues")

        # If the caller did not explicitly provide issue identifiers, the
        # snapshot owns discovery and fetches the discovered issue evidence.
        if linked_issue_numbers is None and references["issues"]:
            try:
                linked_issues = gh.linked_issue_evidence_batch(
                    references["issues"],
                )
            except Exception as exc:
                linked_issues = []
                result.setdefault("errors", {})["linked_issues"] = str(exc)

        repository = cls._repository_name(gh, pr)

        return cls(
            pr_number=number,
            captured_at=datetime.now(timezone.utc).isoformat(),
            repository=repository,
            pr=pr,
            files=files,
            reviews=reviews,
            review_comments=review_comments,
            issue_comments=issue_comments,
            timeline=timeline,
            linked_issues=linked_issues,
            base_file_contents=_dict_value(
                evidence,
                "base_file_contents",
            ),
            codeowners_path=_optional_string(
                evidence.get("codeowners_path"),
            ),
            codeowners_text=_optional_string(
                evidence.get("codeowners_text"),
            ),
            check_runs=_check_runs_value(
                evidence.get("check_runs"),
            ),
            statuses=_list_value(evidence, "statuses"),
            base_sha=_optional_string(base.get("sha")),
            head_sha=_optional_string(
                evidence.get("head_sha") or head.get("sha"),
            ),
            evidence_errors={
                str(key): str(value)
                for key, value in (result.get("errors") or {}).items()
            },
            collection_stats={
                str(key): value
                for key, value in (result.get("stats") or {}).items()
            },
            references=references,
        )

    @staticmethod
    def _discover_references(
        pr_number: int,
        pr: dict[str, Any],
        reviews: list[dict[str, Any]],
        review_comments: list[dict[str, Any]],
        issue_comments: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> dict[str, list[Any]]:
        """Discover references across the complete PR discussion surface."""
        from scripts.triager.references import (
            collect_issue_numbers,
        )

        title = pr.get("title") or ""
        body = pr.get("body") or ""

        text_parts = [f"{title}\n{body}"]

        for collection in (
            reviews,
            review_comments,
            issue_comments,
        ):
            for item in collection:
                body_text = item.get("body")
                if isinstance(body_text, str) and body_text:
                    text_parts.append(body_text)

        issues, peps, discussions = collect_issue_numbers(
            pr_number=pr_number,
            pr_body="\n".join(text_parts),
            timeline=timeline,
        )

        return {
            "issues": issues,
            "peps": peps,
            "discussions": discussions,
        }

    @staticmethod
    def _repository_name(
        gh: Any,
        pr: dict[str, Any],
    ) -> str:
        """Resolve the repository name without another API request."""
        repository = getattr(gh, "repo", None)

        if isinstance(repository, str) and repository:
            return repository

        base = pr.get("base") or {}
        repo_data = base.get("repo") or {}

        full_name = repo_data.get("full_name")
        if isinstance(full_name, str) and full_name:
            return full_name

        return "python/cpython"

    @property
    def is_complete(self) -> bool:
        """Return whether the core PR evidence collectors all succeeded."""
        required = {
            "files",
            "reviews",
            "review_comments",
            "issue_comments",
            "timeline",
            "base_file_contents",
            "check_runs",
            "statuses",
        }

        return not any(
            key in self.evidence_errors
            for key in required
        )

    def completeness(self) -> dict[str, Any]:
        """Return a machine-readable evidence completeness summary."""
        attempted = [
            "pr",
            "files",
            "reviews",
            "review_comments",
            "issue_comments",
            "timeline",
            "linked_issues",
            "base_file_contents",
            "codeowners",
            "check_runs",
            "statuses",
        ]

        missing = [
            source
            for source in attempted
            if self._source_missing(source)
        ]

        available = [
            source
            for source in attempted
            if source not in missing
        ]

        return {
            "attempted": attempted,
            "available": available,
            "missing": missing,
            "complete": not missing,
            "error_count": len(self.evidence_errors),
        }

    def _source_missing(self, source: str) -> bool:
        """Determine whether a snapshot evidence source is unavailable."""
        if source in self.evidence_errors:
            return True

        if source == "pr":
            return not bool(self.pr)

        if source == "codeowners":
            return (
                self.codeowners_path is None
                and self.codeowners_text is None
            )

        if source == "check_runs":
            return not isinstance(self.check_runs, dict)

        if source == "base_file_contents":
            return False

        value = getattr(self, source, None)
        return value is None

    def to_evidence(self) -> dict[str, Any]:
        """Return the existing report-compatible evidence shape."""
        return {
            "pr": self.pr,
            "files": list(self.files),
            "reviews": list(self.reviews),
            "review_comments": list(self.review_comments),
            "issue_comments": list(self.issue_comments),
            "timeline": list(self.timeline),
            "linked_issues": list(self.linked_issues),
            "base_file_contents": dict(self.base_file_contents),
            "codeowners_path": self.codeowners_path,
            "codeowners_text": self.codeowners_text,
            "check_runs": dict(self.check_runs),
            "statuses": list(self.statuses),
            "head_sha": self.head_sha,
            "evidence_errors": dict(self.evidence_errors),
            "references": {
                key: list(value)
                for key, value in self.references.items()
            },
        }