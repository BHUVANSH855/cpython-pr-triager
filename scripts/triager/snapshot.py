"""Review snapshot orchestration for CPython pull-request triage.

This module coordinates the existing GitHub evidence collectors into one
review snapshot. It deliberately does not perform semantic analysis or AI
synthesis.

The snapshot is the deterministic boundary between GitHub collection and
downstream analysis/reporting. Collection failures are preserved explicitly
so downstream consumers cannot accidentally interpret incomplete evidence as
complete evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# Core evidence sources are the collectors whose failure prevents the
# snapshot from being considered operationally complete.
#
# Keep this separate from the broader evidence inventory used by
# ``completeness()``. A source can be legitimately empty without making the
# snapshot unusable.
CORE_EVIDENCE_SOURCES: tuple[str, ...] = (
    "files",
    "reviews",
    "review_comments",
    "issue_comments",
    "timeline",
    "base_file_contents",
    "check_runs",
    "statuses",
)

# This is the complete evidence inventory exposed by the snapshot.
#
# ``completeness()`` reports all of these surfaces, while ``is_complete``
# retains its established meaning of checking the core collector failures.
EVIDENCE_SOURCES: tuple[str, ...] = (
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
)

OPTIONAL_EMPTY_EVIDENCE_SOURCES: frozenset[str] = frozenset(
    {
        "reviews",
        "review_comments",
        "issue_comments",
        "timeline",
        "linked_issues",
        "base_file_contents",
        "check_runs",
        "statuses",
    }
)


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
    """Normalize the check-runs evidence structure.

    An empty check-run collection is valid evidence when GitHub successfully
    reports zero check runs. Collector failures are represented separately in
    ``evidence_errors`` and therefore must not be hidden here.
    """
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
    else:
        result["total_count"] = max(0, total_count)

    return result


def _normalise_errors(value: Any) -> dict[str, str]:
    """Normalize collector errors into a deterministic string mapping."""
    if not isinstance(value, dict):
        return {}

    errors: dict[str, str] = {}

    for key, message in value.items():
        normalized_key = str(key).strip()

        if not normalized_key:
            continue

        if message is None:
            continue

        errors[normalized_key] = str(message)

    return errors


def _normalise_stats(value: Any) -> dict[str, Any]:
    """Normalize collection statistics without exposing mutable input."""
    if not isinstance(value, dict):
        return {}

    return {
        str(key): stat_value
        for key, stat_value in value.items()
        if str(key).strip()
    }


@dataclass
class ReviewSnapshot:
    """Evidence snapshot for one pull request.

    The object is intentionally an orchestration/data boundary rather than an
    analysis engine. It records the evidence collected at a particular point
    in time and preserves collection failures for downstream consumers.

    The contained dictionaries/lists are copied at construction time where
    practical, making the snapshot immutable-in-practice even though the
    dataclass itself remains mutable for backwards compatibility.
    """

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

    def __post_init__(self) -> None:
        """Validate and defensively normalize snapshot data."""
        if not isinstance(self.pr_number, int) or self.pr_number <= 0:
            raise ValueError("pr_number must be a positive integer")

        if not isinstance(self.captured_at, str) or not self.captured_at:
            raise ValueError("captured_at must be a non-empty string")

        if not isinstance(self.repository, str) or not self.repository:
            raise ValueError("repository must be a non-empty string")

        if not isinstance(self.pr, dict):
            raise TypeError("pr must be a dictionary")
        self.pr = dict(self.pr)

        for attr in (
            "files",
            "reviews",
            "review_comments",
            "issue_comments",
            "timeline",
            "linked_issues",
            "statuses",
        ):
            value = getattr(self, attr)
            if not isinstance(value, list):
                setattr(self, attr, [])
            else:
                setattr(self, attr, list(value))

        if not isinstance(self.base_file_contents, dict):
            self.base_file_contents = {}
        else:
            self.base_file_contents = dict(self.base_file_contents)

        if not isinstance(self.check_runs, dict):
            self.check_runs = {
                "total_count": 0,
                "check_runs": [],
            }
        else:
            self.check_runs = _check_runs_value(self.check_runs)

        if self.codeowners_path is not None and not isinstance(
            self.codeowners_path,
            str,
        ):
            self.codeowners_path = None

        if self.codeowners_text is not None and not isinstance(
            self.codeowners_text,
            str,
        ):
            self.codeowners_text = None

        if self.head_sha is not None and not isinstance(self.head_sha, str):
            self.head_sha = None

        if self.base_sha is not None and not isinstance(self.base_sha, str):
            self.base_sha = None

        self.evidence_errors = _normalise_errors(self.evidence_errors)
        self.collection_stats = _normalise_stats(self.collection_stats)

        if not isinstance(self.references, dict):
            self.references = {}

        normalized_references: dict[str, list[Any]] = {}

        for key in ("issues", "peps", "discussions"):
            value = self.references.get(key, [])
            normalized_references[key] = (
                list(value) if isinstance(value, list) else []
            )

        self.references = normalized_references

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
        This layer owns orchestration, normalization, and reference discovery.

        Any collector errors returned by ``pull_request_evidence`` are
        preserved in ``evidence_errors``. This is critical: an unavailable
        evidence source must never silently become an apparently successful
        empty result.
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

        errors = _normalise_errors(result.get("errors"))

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
        #
        # A failure is retained as an evidence error rather than being
        # converted into an apparently successful empty list.
        if linked_issue_numbers is None and references["issues"]:
            try:
                linked_issues = gh.linked_issue_evidence_batch(
                    references["issues"],
                )
                if not isinstance(linked_issues, list):
                    raise TypeError(
                        "linked_issue_evidence_batch() must return a list"
                    )
                linked_issues = list(linked_issues)
            except Exception as exc:
                linked_issues = []
                errors["linked_issues"] = str(exc)

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
            evidence_errors=errors,
            collection_stats=_normalise_stats(result.get("stats")),
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
            "issues": list(issues),
            "peps": list(peps),
            "discussions": list(discussions),
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
        """Return whether the core PR evidence collectors all succeeded.

        This deliberately preserves the established snapshot contract:
        empty-but-valid evidence is not a collection failure. The property
        only becomes false when one of the core collectors recorded an error.

        The richer ``completeness()`` method is available when callers need
        the full evidence inventory and diagnostic information.
        """
        return not any(
            source in self.evidence_errors
            for source in CORE_EVIDENCE_SOURCES
        )

    def completeness(self) -> dict[str, Any]:
        """Return a machine-readable evidence completeness summary.

        This reports the full evidence inventory separately from
        ``is_complete``. Empty collections are valid evidence states; explicit
        collector errors are represented as missing evidence and retained in
        the ``errors`` mapping.

        The returned shape intentionally remains compatible with the existing
        snapshot contract while adding a normalized ``status`` field.
        """
        attempted = list(EVIDENCE_SOURCES)

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

        errors = {
            source: self.evidence_errors[source]
            for source in self.evidence_errors
            if source in attempted
        }

        if not missing:
            status = "complete"
        elif available:
            status = "partial"
        else:
            status = "unavailable"

        return {
            "attempted": attempted,
            "available": available,
            "missing": missing,
            "complete": not missing,
            "status": status,
            "error_count": len(self.evidence_errors),
            "errors": errors,
        }

    def _source_missing(self, source: str) -> bool:
        """Determine whether a snapshot evidence source is unavailable."""
        if source in self.evidence_errors:
            return True

        if source == "pr":
            return not bool(self.pr)

        if source == "codeowners":
            # Absence of CODEOWNERS is a legitimate repository state.
            # A collector error is handled above and therefore still marks
            # this source unavailable.
            return False

        if source == "check_runs":
            # The GitHub collector intentionally returns an empty dictionary
            # only when the field is genuinely malformed/missing. A normal
            # zero-check-runs response is represented by a dictionary.
            return not isinstance(self.check_runs, dict)

        if source == "base_file_contents":
            # An empty mapping is valid: added files and non-Python files may
            # legitimately have no base content.
            return False

        if source in OPTIONAL_EMPTY_EVIDENCE_SOURCES:
            # Empty list evidence is valid. Only ``None`` means that the
            # source was not represented at all.
            return getattr(self, source, None) is None

        return getattr(self, source, None) is None

    def to_evidence(self) -> dict[str, Any]:
        """Return the existing report-compatible evidence shape.

        This method intentionally preserves the existing public evidence
        structure so downstream analyzers and report serializers do not need
        to change merely because the snapshot internals became stricter.
        """
        return {
            "pr": dict(self.pr),
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
            "base_sha": self.base_sha,
            "evidence_errors": dict(self.evidence_errors),
            "references": {
                key: list(value)
                for key, value in self.references.items()
            },
        }