"""Canonical evidence snapshot for CPython pull-request review.

This module is the deterministic boundary between GitHub evidence collection
and downstream analysis/reporting.

The snapshot deliberately does not perform semantic analysis or AI synthesis.
Its responsibilities are to:

* preserve the evidence returned by the collector;
* preserve collection failures instead of turning them into empty evidence;
* describe the completeness/freshness of each evidence source;
* bind evidence to the PR base/head SHAs when known;
* preserve provenance and collection metadata;
* provide deterministic serialization for snapshot/replay testing.

Important trust rule:

    EMPTY != COMPLETE

An empty collection is only considered valid when the collector explicitly
reported that source as successfully collected. A missing field, failed
request, bounded/sampled collection, or stale source must remain visible to
downstream consumers.

The module keeps the existing ``ReviewSnapshot`` public fields and
``to_evidence()`` shape for compatibility with the current analyzers.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

SCHEMA_VERSION = 2


class EvidenceStatus(str, Enum):
    """State of one evidence source.

    The distinction between these states is important for a review assistant.

    COMPLETE
        The collector successfully obtained all evidence it intended to
        obtain for this source.

    EMPTY
        The collector successfully queried the source and the source
        legitimately contained no items.

    PARTIAL
        The collector attempted collection but did not obtain the complete
        evidence surface.

    SAMPLED
        Collection intentionally used a bounded/sample strategy. The result
        may be useful, but must never be interpreted as exhaustive.

    FAILED
        Collection was attempted and failed.

    UNAVAILABLE
        The source cannot currently be obtained.

    NOT_COLLECTED
        Collection was not attempted.

    STALE
        Evidence exists but is older than the freshness guarantee required
        for the decision consuming it.
    """

    COMPLETE = "complete"
    EMPTY = "empty"
    PARTIAL = "partial"
    SAMPLED = "sampled"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    NOT_COLLECTED = "not_collected"
    STALE = "stale"


# Core evidence sources are the sources whose failure prevents the snapshot
# from being operationally complete.
#
# This does NOT mean every core source must contain at least one item.
# For example, a PR with no reviews can still have COMPLETE review evidence.
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

# Complete evidence inventory exposed by the snapshot.
EVIDENCE_SOURCES: tuple[str, ...] = (
    "pr",
    "files",
    "reviews",
    "review_comments",
    "issue_comments",
    "timeline",
    "linked_issues",
    "base_file_contents",
    "source_file_contents",
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
        "source_file_contents",
        "check_runs",
        "statuses",
    }
)


def _list_value(
    mapping: Mapping[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    """Return a defensive copy of a list-valued evidence field."""
    value = mapping.get(key)

    if not isinstance(value, list):
        return []

    return deepcopy(value)


def _dict_value(
    mapping: Mapping[str, Any],
    key: str,
) -> dict[str, Any]:
    """Return a defensive copy of a dictionary-valued evidence field."""
    value = mapping.get(key)

    if not isinstance(value, dict):
        return {}

    return deepcopy(value)


def _optional_string(value: Any) -> str | None:
    """Normalize an optional string value."""
    if isinstance(value, str) and value.strip():
        return value

    return None


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
        str(key): deepcopy(stat_value)
        for key, stat_value in value.items()
        if str(key).strip()
    }


def _normalise_status(value: Any) -> EvidenceStatus:
    """Convert a serialized status into ``EvidenceStatus``.

    Unknown values deliberately fall back to ``UNAVAILABLE`` rather than
    inventing a stronger state such as COMPLETE.
    """
    if isinstance(value, EvidenceStatus):
        return value

    if isinstance(value, str):
        try:
            return EvidenceStatus(value.lower())
        except ValueError:
            pass

    return EvidenceStatus.UNAVAILABLE


def _normalise_evidence_statuses(
    value: Any,
) -> dict[str, EvidenceStatus]:
    """Normalize the per-source evidence status mapping."""
    if not isinstance(value, dict):
        return {}

    result: dict[str, EvidenceStatus] = {}

    for source, status in value.items():
        source_name = str(source).strip()

        if not source_name:
            continue

        result[source_name] = _normalise_status(status)

    return result


def _normalise_provenance(
    value: Any,
) -> dict[str, dict[str, Any]]:
    """Normalize per-source provenance records."""
    if not isinstance(value, dict):
        return {}

    result: dict[str, dict[str, Any]] = {}

    for source, record in value.items():
        source_name = str(source).strip()

        if not source_name:
            continue

        if isinstance(record, dict):
            result[source_name] = deepcopy(record)
        else:
            result[source_name] = {
                "source": str(record),
            }

    return result


def _check_runs_value(value: Any) -> dict[str, Any]:
    """Normalize the check-runs evidence structure.

    An empty check-run collection is valid evidence when GitHub successfully
    reports zero check runs.

    Collector failures are represented separately through evidence status and
    evidence errors, so they must never be hidden here.
    """
    if not isinstance(value, dict):
        return {
            "total_count": 0,
            "check_runs": [],
        }

    result = deepcopy(value)

    check_runs = result.get("check_runs")

    if not isinstance(check_runs, list):
        result["check_runs"] = []

    total_count = result.get("total_count")

    if not isinstance(total_count, int):
        result["total_count"] = len(result["check_runs"])
    else:
        result["total_count"] = max(0, total_count)

    return result


def _normalise_source_file_contents(value: Any) -> dict[str, Any]:
    """Normalize base/head source-file evidence.

    ``github.py`` returns source-file evidence in this form:

        {
            "base": {...},
            "head": {...},
        }

    Preserve that structure because downstream analyzers already consume it.
    """
    if not isinstance(value, dict):
        return {
            "base": {},
            "head": {},
        }

    base = value.get("base")
    head = value.get("head")

    return {
        "base": deepcopy(base) if isinstance(base, dict) else {},
        "head": deepcopy(head) if isinstance(head, dict) else {},
    }


def _normalise_datetime_string(value: Any) -> str:
    """Validate and normalize a snapshot timestamp.

    Snapshot timestamps must be timezone-aware ISO-8601 timestamps. We keep the
    original textual representation when valid rather than rewriting it, so
    replayed snapshots remain byte-stable when serialized.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("captured_at must be a non-empty ISO-8601 string")

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            "captured_at must be a valid ISO-8601 timestamp"
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "captured_at must include timezone information"
        )

    return value


def _safe_json_value(value: Any) -> Any:
    """Return a JSON-compatible defensive copy.

    Snapshot data originates from GitHub JSON, so normal values are already
    JSON-compatible. This helper primarily exists to make serialization
    failures explicit instead of silently stringifying arbitrary objects.
    """
    try:
        json.dumps(value)
    except TypeError as exc:
        raise TypeError(
            f"snapshot contains a non-JSON-serializable value: {value!r}"
        ) from exc

    return deepcopy(value)


@dataclass
class EvidenceRecord:
    """Metadata describing one collected evidence source.

    This record is intentionally separate from the actual evidence payload.
    A source can therefore contain useful data while still being explicitly
    marked PARTIAL or SAMPLED.
    """

    source: str
    status: EvidenceStatus

    collected: int | None = None
    total: int | None = None
    limit: int | None = None
    captured_at: str | None = None

    source_ref: str | None = None
    base_sha: str | None = None
    head_sha: str | None = None

    truncated: bool | None = None
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the record."""
        self.source = str(self.source).strip()

        if not self.source:
            raise ValueError("evidence source must be non-empty")

        self.status = _normalise_status(self.status)

        if self.collected is not None:
            if not isinstance(self.collected, int) or self.collected < 0:
                raise ValueError("collected must be a non-negative integer")

        if self.total is not None:
            if not isinstance(self.total, int) or self.total < 0:
                raise ValueError("total must be a non-negative integer")

        if self.limit is not None:
            if not isinstance(self.limit, int) or self.limit < 0:
                raise ValueError("limit must be a non-negative integer")

        if self.collected is not None and self.total is not None:
            if self.collected > self.total:
                raise ValueError(
                    "collected cannot be greater than total"
                )

        if self.captured_at is not None:
            self.captured_at = _normalise_datetime_string(
                self.captured_at
            )

        self.source_ref = _optional_string(self.source_ref)
        self.base_sha = _optional_string(self.base_sha)
        self.head_sha = _optional_string(self.head_sha)

        if self.error is not None:
            self.error = str(self.error)

        if not isinstance(self.details, dict):
            self.details = {}
        else:
            self.details = deepcopy(self.details)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to JSON-compatible data."""
        result = asdict(self)
        result["status"] = self.status.value
        return _safe_json_value(result)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EvidenceRecord:
        """Reconstruct a record from serialized data."""
        if not isinstance(value, Mapping):
            raise TypeError("evidence record must be a mapping")

        return cls(
            source=str(value.get("source", "")),
            status=_normalise_status(value.get("status")),
            collected=value.get("collected"),
            total=value.get("total"),
            limit=value.get("limit"),
            captured_at=value.get("captured_at"),
            source_ref=value.get("source_ref"),
            base_sha=value.get("base_sha"),
            head_sha=value.get("head_sha"),
            truncated=value.get("truncated"),
            details=_dict_value(value, "details"),
            error=value.get("error"),
        )


@dataclass
class ReviewSnapshot:
    """Evidence snapshot for one CPython pull request.

    ``ReviewSnapshot`` is intentionally a data/orchestration boundary rather
    than an analysis engine.

    The snapshot records:

    * the PR identity;
    * base/head revisions;
    * collected evidence;
    * per-source evidence state;
    * collection errors;
    * source provenance;
    * collection statistics;
    * discovered references;
    * capture metadata.

    The dataclass remains mutable for backwards compatibility, but all values
    entering the snapshot are defensively copied.
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

    # Source evidence contains both base and head content. Keep the old
    # ``base_file_contents`` field for compatibility while preserving the
    # richer evidence collected by github.py.
    source_file_contents: dict[str, Any] = field(
        default_factory=lambda: {
            "base": {},
            "head": {},
        }
    )

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

    # Explicit evidence state per source.
    evidence_statuses: dict[str, EvidenceStatus] = field(
        default_factory=dict
    )

    # Detailed provenance for sources where available.
    evidence_provenance: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )

    references: dict[str, list[Any]] = field(
        default_factory=lambda: {
            "issues": [],
            "peps": [],
            "discussions": [],
        }
    )

    schema_version: int = SCHEMA_VERSION
    analyzer_version: str | None = None

    def __post_init__(self) -> None:
        """Validate and defensively normalize snapshot data."""
        if not isinstance(self.pr_number, int) or self.pr_number <= 0:
            raise ValueError("pr_number must be a positive integer")

        self.captured_at = _normalise_datetime_string(self.captured_at)

        if not isinstance(self.repository, str) or not self.repository.strip():
            raise ValueError("repository must be a non-empty string")

        self.repository = self.repository.strip()

        if not isinstance(self.pr, dict):
            raise TypeError("pr must be a dictionary")

        self.pr = deepcopy(self.pr)

        list_fields = (
            "files",
            "reviews",
            "review_comments",
            "issue_comments",
            "timeline",
            "linked_issues",
            "statuses",
        )

        for attr in list_fields:
            value = getattr(self, attr)

            if not isinstance(value, list):
                setattr(self, attr, [])
            else:
                setattr(self, attr, deepcopy(value))

        if not isinstance(self.base_file_contents, dict):
            self.base_file_contents = {}
        else:
            self.base_file_contents = deepcopy(
                self.base_file_contents
            )

        self.source_file_contents = _normalise_source_file_contents(
            self.source_file_contents
        )

        if not isinstance(self.check_runs, dict):
            self.check_runs = {
                "total_count": 0,
                "check_runs": [],
            }
        else:
            self.check_runs = _check_runs_value(self.check_runs)

        if self.codeowners_path is not None:
            self.codeowners_path = _optional_string(
                self.codeowners_path
            )

        if self.codeowners_text is not None:
            self.codeowners_text = _optional_string(
                self.codeowners_text
            )

        self.head_sha = _optional_string(self.head_sha)
        self.base_sha = _optional_string(self.base_sha)

        if not isinstance(self.evidence_errors, dict):
            self.evidence_errors = {}
        else:
            self.evidence_errors = _normalise_errors(
                self.evidence_errors
            )

        self.collection_stats = _normalise_stats(
            self.collection_stats
        )

        self.evidence_statuses = _normalise_evidence_statuses(
            self.evidence_statuses
        )

        self.evidence_provenance = _normalise_provenance(
            self.evidence_provenance
        )

        if not isinstance(self.references, dict):
            self.references = {}

        normalized_references: dict[str, list[Any]] = {}

        for key in ("issues", "peps", "discussions"):
            value = self.references.get(key, [])

            normalized_references[key] = (
                deepcopy(value)
                if isinstance(value, list)
                else []
            )

        self.references = normalized_references

        if not isinstance(self.schema_version, int):
            raise TypeError("schema_version must be an integer")

        if self.schema_version <= 0:
            raise ValueError("schema_version must be positive")

        self.analyzer_version = _optional_string(
            self.analyzer_version
        )

        # If callers construct a snapshot directly without supplying explicit
        # statuses, derive conservative statuses from the legacy fields.
        self._ensure_evidence_statuses()

        # Add snapshot-level provenance for the capture if no explicit
        # collector timestamp exists.
        self._ensure_provenance()

    def _ensure_evidence_statuses(self) -> None:
        """Populate missing per-source statuses conservatively.

        This method deliberately never upgrades a source to COMPLETE merely
        because a field happens to be present.

        Legacy snapshots with no explicit status information can only safely
        infer:

        * FAILED when an explicit error exists;
        * EMPTY when an empty collection is known to be represented;
        * NOT_COLLECTED when the source is absent.

        ``collect()`` supplies stronger statuses from collector metadata.
        """
        statuses = dict(self.evidence_statuses)

        for source in EVIDENCE_SOURCES:
            if source in statuses:
                continue

            if source in self.evidence_errors:
                statuses[source] = EvidenceStatus.FAILED
                continue

            if has_scoped_error:
                # Per-item retrieval failures mean the source cannot be
                # represented as exhaustive.  If useful evidence exists, mark
                # it PARTIAL; otherwise mark it FAILED.
                value = evidence.get(source)
                has_value = bool(value)
                if source == "source_file_contents":
                    has_value = bool(
                        source_file_contents.get("base")
                        or source_file_contents.get("head")
                    )
                elif source == "check_runs":
                    has_value = bool(
                        _check_runs_value(value).get("check_runs")
                    )
                statuses[source] = (
                    EvidenceStatus.PARTIAL
                    if has_value
                    else EvidenceStatus.FAILED
                )
                continue

            if source == "pr":
                statuses[source] = (
                    EvidenceStatus.COMPLETE
                    if self.pr
                    else EvidenceStatus.NOT_COLLECTED
                )
                continue

            if source == "codeowners":
                # A missing CODEOWNERS file is a legitimate repository state.
                # Without explicit collector metadata we cannot prove whether
                # the absence means "no CODEOWNERS" or "not collected".
                if self.codeowners_path or self.codeowners_text:
                    statuses[source] = EvidenceStatus.COMPLETE
                else:
                    statuses[source] = EvidenceStatus.NOT_COLLECTED
                continue

            if source == "check_runs":
                statuses[source] = (
                    EvidenceStatus.EMPTY
                    if self.check_runs.get("total_count", 0) == 0
                    else EvidenceStatus.COMPLETE
                )
                continue

            if source == "base_file_contents":
                statuses[source] = (
                    EvidenceStatus.EMPTY
                    if not self.base_file_contents
                    else EvidenceStatus.COMPLETE
                )
                continue

            if source == "source_file_contents":
                has_base = bool(
                    self.source_file_contents.get("base")
                )
                has_head = bool(
                    self.source_file_contents.get("head")
                )

                if has_base or has_head:
                    statuses[source] = EvidenceStatus.COMPLETE
                else:
                    statuses[source] = EvidenceStatus.EMPTY

                continue

            value = getattr(self, source, None)

            if isinstance(value, list):
                statuses[source] = (
                    EvidenceStatus.EMPTY
                    if not value
                    else EvidenceStatus.COMPLETE
                )
            elif value is None:
                statuses[source] = EvidenceStatus.NOT_COLLECTED
            else:
                statuses[source] = EvidenceStatus.COMPLETE

        self.evidence_statuses = statuses

    def _ensure_provenance(self) -> None:
        """Ensure every known source has a minimal provenance record."""
        provenance = deepcopy(self.evidence_provenance)

        for source in EVIDENCE_SOURCES:
            record = provenance.setdefault(source, {})

            if not isinstance(record, dict):
                record = {}
                provenance[source] = record

            record.setdefault("captured_at", self.captured_at)

            status = self.evidence_statuses.get(
                source,
                EvidenceStatus.NOT_COLLECTED,
            )

            record.setdefault("status", status.value)

            if self.base_sha:
                record.setdefault("base_sha", self.base_sha)

            if self.head_sha:
                record.setdefault("head_sha", self.head_sha)

        self.evidence_provenance = provenance

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
        """Collect one review snapshot.

        ``gh`` remains responsible for network access. This layer owns:

        * orchestration;
        * normalization;
        * reference discovery;
        * evidence status;
        * provenance;
        * snapshot identity.

        Any collector errors are preserved explicitly.
        """
        if not isinstance(number, int) or number <= 0:
            raise ValueError("number must be a positive integer")

        result = gh.pull_request_evidence(
            number,
            linked_issue_numbers=linked_issue_numbers,
        )

        if not isinstance(result, dict):
            raise TypeError(
                "pull_request_evidence() must return a dictionary"
            )

        evidence = result.get("evidence")

        if not isinstance(evidence, dict):
            raise TypeError(
                "pull_request_evidence() returned invalid evidence"
            )

        errors = _normalise_errors(result.get("errors"))

        pr = evidence.get("pr")

        if not isinstance(pr, dict):
            raise TypeError(
                "pull_request_evidence() returned invalid PR data"
            )

        base = pr.get("base") or {}
        head = pr.get("head") or {}

        if not isinstance(base, dict):
            base = {}

        if not isinstance(head, dict):
            head = {}

        files = _list_value(evidence, "files")
        reviews = _list_value(evidence, "reviews")
        review_comments = _list_value(
            evidence,
            "review_comments",
        )
        issue_comments = _list_value(
            evidence,
            "issue_comments",
        )
        timeline = _list_value(evidence, "timeline")

        references = cls._discover_references(
            number,
            pr,
            reviews,
            review_comments,
            issue_comments,
            timeline,
        )

        linked_issues = _list_value(
            evidence,
            "linked_issues",
        )

        # If the caller did not explicitly provide issue identifiers, the
        # snapshot owns discovery and fetches discovered issue evidence.
        if linked_issue_numbers is None and references["issues"]:
            try:
                linked_issues = gh.linked_issue_evidence_batch(
                    references["issues"],
                )

                if not isinstance(linked_issues, list):
                    raise TypeError(
                        "linked_issue_evidence_batch() must return a list"
                    )

                linked_issues = deepcopy(linked_issues)

            except Exception as exc:
                linked_issues = []
                errors["linked_issues"] = str(exc)

        repository = cls._repository_name(
            gh,
            pr,
        )

        captured_at = datetime.now(UTC).isoformat()

        base_sha = _optional_string(base.get("sha"))
        head_sha = _optional_string(
            evidence.get("head_sha")
            or head.get("sha")
        )

        source_file_contents = _normalise_source_file_contents(
            evidence.get("source_file_contents")
        )

        snapshot = cls(
            pr_number=number,
            captured_at=captured_at,
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
            source_file_contents=source_file_contents,
            codeowners_path=_optional_string(
                evidence.get("codeowners_path"),
            ),
            codeowners_text=_optional_string(
                evidence.get("codeowners_text"),
            ),
            check_runs=_check_runs_value(
                evidence.get("check_runs"),
            ),
            statuses=_list_value(
                evidence,
                "statuses",
            ),
            base_sha=base_sha,
            head_sha=head_sha,
            evidence_errors=errors,
            collection_stats=_normalise_stats(
                result.get("stats")
            ),
            references=references,
            evidence_statuses=cls._build_evidence_statuses(
                evidence=evidence,
                errors=errors,
                stats=result.get("stats"),
                source_file_contents=source_file_contents,
            ),
            evidence_provenance=cls._build_provenance(
                evidence=evidence,
                errors=errors,
                stats=result.get("stats"),
                captured_at=captured_at,
                base_sha=base_sha,
                head_sha=head_sha,
            ),
        )

        return snapshot

    @staticmethod
    def _source_has_error(
        errors: Mapping[str, str],
        source: str,
    ) -> bool:
        """Return whether collection recorded an error for ``source``.

        Some collectors report per-item failures using keys such as
        ``base_file:<path>`` or ``history:<path>`` rather than one exact
        source key.  Exact-key checks alone would incorrectly upgrade a
        partially collected source to COMPLETE.
        """
        if source in errors:
            return True

        prefixes = (
            f"{source}:",
            f"{source}_",
        )

        return any(
            isinstance(key, str) and key.startswith(prefixes)
            for key in errors
        )

    @classmethod
    def _build_evidence_statuses(
        cls,
        *,
        evidence: Mapping[str, Any],
        errors: Mapping[str, str],
        stats: Any,
        source_file_contents: Mapping[str, Any],
    ) -> dict[str, EvidenceStatus]:
        """Build conservative per-source status metadata.

        ``github.py`` may provide richer source metadata in future versions.
        This method understands several useful conventions while remaining
        backwards compatible with the current collector result shape.

        The critical rule is that a successful bounded collector is not
        automatically COMPLETE.
        """
        statuses: dict[str, EvidenceStatus] = {}

        explicit = evidence.get("evidence_statuses")

        if isinstance(explicit, dict):
            statuses.update(
                _normalise_evidence_statuses(explicit)
            )

        stats_mapping = (
            stats
            if isinstance(stats, dict)
            else {}
        )

        source_stats = stats_mapping.get("evidence")

        if isinstance(source_stats, dict):
            for source, metadata in source_stats.items():
                if source in statuses:
                    continue

                if not isinstance(metadata, dict):
                    continue

                status = metadata.get("status")

                if status is not None:
                    statuses[str(source)] = _normalise_status(
                        status
                    )

        for source in EVIDENCE_SOURCES:
            # An exact collector failure is FAILED.  Per-item failures are
            # handled below so a source with some successfully collected
            # evidence becomes PARTIAL rather than falsely COMPLETE.
            if source in errors:
                existing = statuses.get(source)
                statuses[source] = (
                    EvidenceStatus.PARTIAL
                    if existing in {
                        EvidenceStatus.COMPLETE,
                        EvidenceStatus.EMPTY,
                        EvidenceStatus.SAMPLED,
                        EvidenceStatus.PARTIAL,
                    }
                    else EvidenceStatus.FAILED
                )
                continue

            if source in statuses:
                continue

            has_scoped_error = cls._source_has_error(errors, source)

            if source == "pr":
                statuses[source] = (
                    EvidenceStatus.COMPLETE
                    if isinstance(evidence.get("pr"), dict)
                    and bool(evidence.get("pr"))
                    else EvidenceStatus.NOT_COLLECTED
                )
                continue

            if source == "source_file_contents":
                base = source_file_contents.get("base", {})
                head = source_file_contents.get("head", {})

                statuses[source] = (
                    EvidenceStatus.COMPLETE
                    if base or head
                    else EvidenceStatus.EMPTY
                )
                continue

            if source == "codeowners":
                if (
                    evidence.get("codeowners_path")
                    or evidence.get("codeowners_text")
                ):
                    statuses[source] = EvidenceStatus.COMPLETE
                else:
                    statuses[source] = EvidenceStatus.EMPTY
                continue

            if source == "check_runs":
                check_runs = _check_runs_value(
                    evidence.get("check_runs")
                )

                statuses[source] = (
                    EvidenceStatus.EMPTY
                    if check_runs.get("total_count", 0) == 0
                    else EvidenceStatus.COMPLETE
                )
                continue

            value = evidence.get(source)

            if isinstance(value, list) or isinstance(value, dict):
                statuses[source] = (
                    EvidenceStatus.EMPTY
                    if not value
                    else EvidenceStatus.COMPLETE
                )
            elif value is None:
                statuses[source] = EvidenceStatus.NOT_COLLECTED
            else:
                statuses[source] = EvidenceStatus.COMPLETE

        return statuses

    @classmethod
    def _build_provenance(
        cls,
        *,
        evidence: Mapping[str, Any],
        errors: Mapping[str, str],
        stats: Any,
        captured_at: str,
        base_sha: str | None,
        head_sha: str | None,
    ) -> dict[str, dict[str, Any]]:
        """Build minimal provenance records for every evidence source."""
        provenance: dict[str, dict[str, Any]] = {}

        explicit = evidence.get("evidence_provenance")

        if isinstance(explicit, dict):
            provenance = _normalise_provenance(explicit)

        stats_mapping = (
            stats
            if isinstance(stats, dict)
            else {}
        )

        source_stats = stats_mapping.get("evidence")

        for source in EVIDENCE_SOURCES:
            record = provenance.setdefault(
                source,
                {},
            )

            if not isinstance(record, dict):
                record = {}
                provenance[source] = record

            record.setdefault(
                "captured_at",
                captured_at,
            )

            if base_sha:
                record.setdefault(
                    "base_sha",
                    base_sha,
                )

            if head_sha:
                record.setdefault(
                    "head_sha",
                    head_sha,
                )

            if source in errors:
                record.setdefault(
                    "status",
                    EvidenceStatus.FAILED.value,
                )
            elif cls._source_has_error(errors, source):
                record.setdefault(
                    "status",
                    EvidenceStatus.PARTIAL.value,
                )

            if isinstance(source_stats, dict):
                metadata = source_stats.get(source)

                if isinstance(metadata, dict):
                    for key in (
                        "source",
                        "source_ref",
                        "endpoint",
                        "limit",
                        "collected",
                        "total",
                        "truncated",
                        "status",
                    ):
                        if key in metadata:
                            record.setdefault(
                                key,
                                deepcopy(metadata[key]),
                            )

        return provenance

    @staticmethod
    def _discover_references(
        pr_number: int,
        pr: dict[str, Any],
        reviews: list[dict[str, Any]],
        review_comments: list[dict[str, Any]],
        issue_comments: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> dict[str, list[Any]]:
        """Discover references across the PR discussion surface."""
        from scripts.triager.references import collect_issue_numbers

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
        """Resolve repository name without another API request."""
        repository = getattr(gh, "repo", None)

        if isinstance(repository, str) and repository.strip():
            return repository.strip()

        base = pr.get("base") or {}

        if not isinstance(base, dict):
            base = {}

        repo_data = base.get("repo") or {}

        if not isinstance(repo_data, dict):
            repo_data = {}

        full_name = repo_data.get("full_name")

        if isinstance(full_name, str) and full_name.strip():
            return full_name.strip()

        # This fallback is retained for compatibility with the CPython
        # project, but callers should prefer the authoritative repository
        # identity supplied by GitHub.
        return "python/cpython"

    @property
    def is_complete(self) -> bool:
        """Return whether all core evidence sources are operationally usable.

        This property intentionally does not equate "non-empty" with
        completeness.

        A source marked EMPTY is valid evidence.

        A source marked SAMPLED, PARTIAL, FAILED, UNAVAILABLE, NOT_COLLECTED,
        or STALE means the snapshot is not operationally complete for that
        source.
        """
        return all(
            self.evidence_statuses.get(
                source,
                EvidenceStatus.NOT_COLLECTED,
            )
            in {
                EvidenceStatus.COMPLETE,
                EvidenceStatus.EMPTY,
            }
            for source in CORE_EVIDENCE_SOURCES
        )

    def completeness(self) -> dict[str, Any]:
        """Return a machine-readable evidence completeness summary.

        The summary distinguishes:

        * complete evidence;
        * legitimate empty evidence;
        * sampled evidence;
        * partial evidence;
        * failed evidence;
        * unavailable evidence;
        * uncollected evidence;
        * stale evidence.

        This prevents downstream code from reducing all uncertainty to a
        single boolean.
        """
        statuses = {
            source: self.evidence_statuses.get(
                source,
                EvidenceStatus.NOT_COLLECTED,
            )
            for source in EVIDENCE_SOURCES
        }

        complete = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.COMPLETE
        ]

        empty = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.EMPTY
        ]

        partial = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.PARTIAL
        ]

        sampled = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.SAMPLED
        ]

        failed = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.FAILED
        ]

        unavailable = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.UNAVAILABLE
        ]

        not_collected = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.NOT_COLLECTED
        ]

        stale = [
            source
            for source, status in statuses.items()
            if status == EvidenceStatus.STALE
        ]

        operational = complete + empty

        incomplete = [
            source
            for source in EVIDENCE_SOURCES
            if source not in operational
        ]

        errors = {
            source: self.evidence_errors[source]
            for source in self.evidence_errors
            if source in EVIDENCE_SOURCES
        }

        if not incomplete:
            status = "complete"
        elif operational:
            status = "partial"
        else:
            status = "unavailable"

        return {
            "attempted": list(EVIDENCE_SOURCES),
            "available": operational,
            "complete_sources": complete,
            "empty_sources": empty,
            "partial_sources": partial,
            "sampled_sources": sampled,
            "failed_sources": failed,
            "unavailable_sources": unavailable,
            "not_collected_sources": not_collected,
            "stale_sources": stale,
            "missing": incomplete,
            "complete": not incomplete,
            "status": status,
            "error_count": len(self.evidence_errors),
            "errors": errors,
            "statuses": {
                source: statuses[source].value
                for source in EVIDENCE_SOURCES
            },
        }

    def evidence_status(
        self,
        source: str,
    ) -> EvidenceStatus:
        """Return the explicit status for one evidence source."""
        source = str(source).strip()

        if not source:
            raise ValueError("source must be non-empty")

        return self.evidence_statuses.get(
            source,
            EvidenceStatus.NOT_COLLECTED,
        )

    def evidence_is_usable(
        self,
        source: str,
        *,
        allow_empty: bool = True,
    ) -> bool:
        """Return whether a source is safe for normal deterministic analysis.

        ``PARTIAL`` and ``SAMPLED`` are deliberately not considered usable
        for conclusions that require exhaustive evidence.
        """
        status = self.evidence_status(source)

        usable = {
            EvidenceStatus.COMPLETE,
        }

        if allow_empty:
            usable.add(EvidenceStatus.EMPTY)

        return status in usable

    def provenance_for(
        self,
        source: str,
    ) -> dict[str, Any]:
        """Return defensive provenance metadata for one source."""
        source = str(source).strip()

        if not source:
            raise ValueError("source must be non-empty")

        return deepcopy(
            self.evidence_provenance.get(
                source,
                {},
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete snapshot for replay.

        The output is intentionally independent of ``to_evidence()``.
        ``to_evidence()`` is the backwards-compatible analyzer interface;
        ``to_dict()`` is the canonical persistence/replay representation.
        """
        return _safe_json_value(
            {
                "schema_version": self.schema_version,
                "analyzer_version": self.analyzer_version,
                "pr_number": self.pr_number,
                "captured_at": self.captured_at,
                "repository": self.repository,
                "pr": deepcopy(self.pr),
                "files": deepcopy(self.files),
                "reviews": deepcopy(self.reviews),
                "review_comments": deepcopy(
                    self.review_comments
                ),
                "issue_comments": deepcopy(
                    self.issue_comments
                ),
                "timeline": deepcopy(self.timeline),
                "linked_issues": deepcopy(
                    self.linked_issues
                ),
                "base_file_contents": deepcopy(
                    self.base_file_contents
                ),
                "source_file_contents": deepcopy(
                    self.source_file_contents
                ),
                "codeowners_path": self.codeowners_path,
                "codeowners_text": self.codeowners_text,
                "check_runs": deepcopy(self.check_runs),
                "statuses": deepcopy(self.statuses),
                "head_sha": self.head_sha,
                "base_sha": self.base_sha,
                "evidence_errors": deepcopy(
                    self.evidence_errors
                ),
                "collection_stats": deepcopy(
                    self.collection_stats
                ),
                "evidence_statuses": {
                    source: status.value
                    for source, status in self.evidence_statuses.items()
                },
                "evidence_provenance": deepcopy(
                    self.evidence_provenance
                ),
                "references": deepcopy(self.references),
            }
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> ReviewSnapshot:
        """Reconstruct a snapshot from ``to_dict()`` output.

        Unknown schema versions are rejected rather than silently interpreted
        as compatible. This is important for deterministic replay: a newer
        snapshot format should not accidentally be consumed by older code.
        """
        if not isinstance(value, Mapping):
            raise TypeError("snapshot must be a mapping")

        schema_version = value.get("schema_version", 1)

        if not isinstance(schema_version, int):
            raise TypeError("schema_version must be an integer")

        if schema_version > SCHEMA_VERSION:
            raise ValueError(
                "snapshot schema version is newer than this analyzer"
            )

        return cls(
            schema_version=schema_version,
            analyzer_version=value.get("analyzer_version"),
            pr_number=value.get("pr_number"),
            captured_at=value.get("captured_at"),
            repository=value.get("repository"),
            pr=_dict_value(value, "pr"),
            files=_list_value(value, "files"),
            reviews=_list_value(value, "reviews"),
            review_comments=_list_value(
                value,
                "review_comments",
            ),
            issue_comments=_list_value(
                value,
                "issue_comments",
            ),
            timeline=_list_value(value, "timeline"),
            linked_issues=_list_value(
                value,
                "linked_issues",
            ),
            base_file_contents=_dict_value(
                value,
                "base_file_contents",
            ),
            source_file_contents=_normalise_source_file_contents(
                value.get("source_file_contents")
            ),
            codeowners_path=_optional_string(
                value.get("codeowners_path")
            ),
            codeowners_text=_optional_string(
                value.get("codeowners_text")
            ),
            check_runs=_check_runs_value(
                value.get("check_runs")
            ),
            statuses=_list_value(
                value,
                "statuses",
            ),
            head_sha=_optional_string(
                value.get("head_sha")
            ),
            base_sha=_optional_string(
                value.get("base_sha")
            ),
            evidence_errors=_normalise_errors(
                value.get("evidence_errors")
            ),
            collection_stats=_normalise_stats(
                value.get("collection_stats")
            ),
            evidence_statuses=_normalise_evidence_statuses(
                value.get("evidence_statuses")
            ),
            evidence_provenance=_normalise_provenance(
                value.get("evidence_provenance")
            ),
            references=(
                deepcopy(value.get("references"))
                if isinstance(value.get("references"), dict)
                else {}
            ),
        )

    def to_json(
        self,
        *,
        indent: int | None = 2,
    ) -> str:
        """Serialize the snapshot as deterministic JSON."""
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
            ensure_ascii=False,
        )

    @classmethod
    def from_json(
        cls,
        value: str,
    ) -> ReviewSnapshot:
        """Reconstruct a snapshot from JSON text."""
        if not isinstance(value, str):
            raise TypeError("snapshot JSON must be a string")

        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid snapshot JSON") from exc

        return cls.from_dict(decoded)

    def to_evidence(self) -> dict[str, Any]:
        """Return the existing report-compatible evidence shape.

        This method intentionally preserves the current public structure so
        downstream analyzers and reports can migrate incrementally.

        The richer status/provenance/replay metadata remains available through
        ``completeness()``, ``evidence_status()``, ``provenance_for()``, and
        ``to_dict()``.
        """
        return {
            "pr": deepcopy(self.pr),
            "files": deepcopy(self.files),
            "reviews": deepcopy(self.reviews),
            "review_comments": deepcopy(
                self.review_comments
            ),
            "issue_comments": deepcopy(
                self.issue_comments
            ),
            "timeline": deepcopy(self.timeline),
            "linked_issues": deepcopy(
                self.linked_issues
            ),
            "base_file_contents": deepcopy(
                self.base_file_contents
            ),
            "source_file_contents": deepcopy(
                self.source_file_contents
            ),
            "codeowners_path": self.codeowners_path,
            "codeowners_text": self.codeowners_text,
            "check_runs": deepcopy(self.check_runs),
            "statuses": deepcopy(self.statuses),
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "evidence_errors": deepcopy(
                self.evidence_errors
            ),
            "references": deepcopy(self.references),
            "evidence_statuses": {
                source: status.value
                for source, status in self.evidence_statuses.items()
            },
            "evidence_provenance": deepcopy(
                self.evidence_provenance
            ),
        }