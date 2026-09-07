"""
Canonical data models for the CPython PR Triager.

The central design rule is:

    evidence != inference

Every deterministic finding should retain enough provenance to answer:

    "Why did the triager say this?"

The models deliberately distinguish:
- observed evidence
- derived signals
- heuristic findings
- process signals
- evidence completeness
- optional AI synthesis

These models are data contracts. They do not perform GitHub requests,
policy decisions, or CLI presentation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

FINDING_STATUSES = {
    "review",
    "informational",
    "suppressed",
}

PROCESS_SIGNAL_LEVELS = {
    "BLOCK",
    "WARN",
    "INFO",
    "OK",
}

EVIDENCE_STATUSES = {
    "complete",
    "partial",
    "unavailable",
}


def _require_choice(
    value: Any,
    allowed: set[str] | dict[str, Any],
    field_name: str,
) -> str:
    """
    Validate a controlled vocabulary field.

    Keeping this validation in the canonical model prevents malformed
    reports from silently propagating to the CLI, JSON output, or future
    web UI.
    """

    if value not in allowed:
        choices = ", ".join(
            sorted(allowed)
        )

        raise ValueError(
            f"{field_name} must be one of "
            f"{choices}; got {value!r}"
        )

    return value


def _require_nonempty_string(
    value: Any,
    field_name: str,
) -> str:
    """Validate and return a required non-empty string."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} must be a non-empty string"
        )

    return value


def _normalise_evidence_refs(
    refs: Any,
    field_name: str,
) -> list[EvidenceRef]:
    """Normalize nested evidence references into canonical objects."""

    if refs is None:
        return []

    if not isinstance(refs, list):
        raise TypeError(
            f"{field_name} must be a list"
        )

    normalized: list[EvidenceRef] = []

    for ref in refs:
        if isinstance(ref, EvidenceRef):
            normalized.append(ref)
            continue

        if isinstance(ref, dict):
            normalized.append(
                EvidenceRef(**ref)
            )
            continue

        raise TypeError(
            f"{field_name} entries must be EvidenceRef "
            "objects or dictionaries"
        )

    return normalized


@dataclass(frozen=True)
class EvidenceRef:
    """
    A reference to evidence supporting a claim.

    kind examples:
        pr
        file
        diff
        review
        comment
        issue
        timeline
        ci
        codeowners
        repository
        history
    """

    kind: str
    description: str

    source: str | None = None
    file: str | None = None
    line: int | None = None
    url: str | None = None
    observed: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(
            self.kind,
            "EvidenceRef.kind",
        )

        _require_nonempty_string(
            self.description,
            "EvidenceRef.description",
        )

        if self.line is not None:
            try:
                normalized_line = int(self.line)
            except (TypeError, ValueError):
                raise ValueError(
                    "EvidenceRef.line must be an integer or None"
                ) from None

            if normalized_line < 1:
                raise ValueError(
                    "EvidenceRef.line must be greater than zero"
                )

            object.__setattr__(
                self,
                "line",
                normalized_line,
            )

        for value, field_name in (
            (self.source, "EvidenceRef.source"),
            (self.file, "EvidenceRef.file"),
            (self.url, "EvidenceRef.url"),
            (self.observed, "EvidenceRef.observed"),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string or None"
                )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """
    A deterministic or derived technical finding.

    A finding is a reason for human review.
    It is not automatically proof of a defect.
    """

    severity: str
    category: str
    message: str
    confidence: str

    source: str = "deterministic"

    evidence_refs: list[EvidenceRef] = field(
        default_factory=list
    )

    file: str | None = None
    rule_id: str | None = None

    # review = human review recommended
    # informational = useful context only
    # suppressed = intentionally hidden by policy
    status: str = "review"

    def __post_init__(self) -> None:
        _require_choice(
            self.severity,
            SEVERITY_ORDER,
            "Finding.severity",
        )

        _require_choice(
            self.confidence,
            CONFIDENCE_ORDER,
            "Finding.confidence",
        )

        _require_choice(
            self.status,
            FINDING_STATUSES,
            "Finding.status",
        )

        _require_nonempty_string(
            self.category,
            "Finding.category",
        )

        _require_nonempty_string(
            self.message,
            "Finding.message",
        )

        if not isinstance(self.source, str):
            raise TypeError(
                "Finding.source must be a string"
            )

        if self.file is not None and not isinstance(
            self.file,
            str,
        ):
            raise TypeError(
                "Finding.file must be a string or None"
            )

        if self.rule_id is not None and not isinstance(
            self.rule_id,
            str,
        ):
            raise TypeError(
                "Finding.rule_id must be a string or None"
            )

        self.evidence_refs = _normalise_evidence_refs(
            self.evidence_refs,
            "Finding.evidence_refs",
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessSignal:
    """
    A repository/process signal.

    This is intentionally separate from technical findings.

    Example:

        BLOCK
        WARN
        INFO
        OK
    """

    level: str
    message: str

    source: str = "policy"

    evidence_refs: list[EvidenceRef] = field(
        default_factory=list
    )

    rule_id: str | None = None

    def __post_init__(self) -> None:
        _require_choice(
            self.level,
            PROCESS_SIGNAL_LEVELS,
            "ProcessSignal.level",
        )

        _require_nonempty_string(
            self.message,
            "ProcessSignal.message",
        )

        if not isinstance(self.source, str):
            raise TypeError(
                "ProcessSignal.source must be a string"
            )

        if self.rule_id is not None and not isinstance(
            self.rule_id,
            str,
        ):
            raise TypeError(
                "ProcessSignal.rule_id must be a string or None"
            )

        self.evidence_refs = _normalise_evidence_refs(
            self.evidence_refs,
            "ProcessSignal.evidence_refs",
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceCompleteness:
    """
    Tracks which evidence sources were attempted and which were available.

    The distinction between ``attempted`` and ``available`` is deliberate:

        attempted + unavailable
            means the triager tried but could not obtain evidence.

        not attempted
            means no conclusion should be drawn from that source.

    Missing evidence must never silently become negative evidence.
    """

    attempted: list[str] = field(
        default_factory=list
    )

    available: list[str] = field(
        default_factory=list
    )

    missing: list[str] = field(
        default_factory=list
    )

    errors: dict[str, str] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        self.attempted = self._normalise_names(
            self.attempted
        )

        self.available = self._normalise_names(
            self.available
        )

        self.missing = self._normalise_names(
            self.missing
        )

        if not isinstance(self.errors, dict):
            raise TypeError(
                "EvidenceCompleteness.errors must be a dictionary"
            )

        self.errors = {
            str(name): str(error)
            for name, error in self.errors.items()
            if str(name).strip()
        }

        attempted = set(
            self.attempted
        )

        available = set(
            self.available
        )

        missing = set(
            self.missing
        )

        # Evidence that is available or missing must have been attempted.
        self.attempted = sorted(
            attempted
            | available
            | missing
            | set(self.errors)
        )

        # A source cannot simultaneously be available and missing.
        self.missing = sorted(
            missing - available
        )

        self.available = sorted(
            available
        )

    @staticmethod
    def _normalise_names(
        names: list[str] | None,
    ) -> list[str]:
        """Normalize evidence-source names deterministically."""

        if names is None:
            return []

        if not isinstance(names, list):
            raise TypeError(
                "Evidence source names must be lists"
            )

        return sorted(
            {
                str(name).strip()
                for name in names
                if str(name).strip()
            }
        )

    @property
    def score(self) -> float:
        """
        Return the fraction of attempted sources that are available.

        With no attempted sources, completeness is unknown rather than
        evidence of failure. The historical model represented this as
        1.0, so that behavior is retained for compatibility.
        """

        if not self.attempted:
            return 1.0

        return min(
            1.0,
            max(
                0.0,
                len(
                    set(self.available)
                )
                / len(
                    set(self.attempted)
                ),
            ),
        )

    @property
    def complete(self) -> bool:
        """Return whether every attempted source is available."""

        if not self.attempted:
            return True

        return not bool(
            set(self.attempted)
            - set(self.available)
        )

    @property
    def status(self) -> str:
        """Return the canonical completeness status."""

        if self.complete:
            return "complete"

        if self.available:
            return "partial"

        return "unavailable"

    def as_dict(self) -> dict[str, Any]:
        data = asdict(
            self
        )

        data["score"] = round(
            self.score,
            3,
        )

        data["complete"] = self.complete
        data["status"] = self.status

        return data


@dataclass
class FileEvidence:
    """
    Normalized evidence about a changed file.
    """

    filename: str

    status: str | None = None

    additions: int = 0
    deletions: int = 0

    patch_available: bool = False

    subsystem: str | None = None
    component: str | None = None

    expected_test_hint: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(
            self.filename,
            "FileEvidence.filename",
        )

        self.additions = self._safe_nonnegative_int(
            self.additions
        )

        self.deletions = self._safe_nonnegative_int(
            self.deletions
        )

        self.patch_available = bool(
            self.patch_available
        )

        for value, field_name in (
            (self.status, "FileEvidence.status"),
            (self.subsystem, "FileEvidence.subsystem"),
            (self.component, "FileEvidence.component"),
            (
                self.expected_test_hint,
                "FileEvidence.expected_test_hint",
            ),
        ):
            if value is not None and not isinstance(
                value,
                str,
            ):
                raise TypeError(
                    f"{field_name} must be a string or None"
                )

    @staticmethod
    def _safe_nonnegative_int(
        value: Any,
    ) -> int:
        try:
            return max(
                0,
                int(value or 0),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckSummary:
    """
    Normalized CI/check state.
    """

    available: bool

    check_runs: int = 0
    completed: int = 0
    successes: int = 0
    failures: int = 0
    pending: int = 0

    legacy_status: str | None = None

    error: str | None = None

    def __post_init__(self) -> None:
        self.available = bool(
            self.available
        )

        self.check_runs = self._safe_count(
            self.check_runs
        )

        self.completed = self._safe_count(
            self.completed
        )

        self.successes = self._safe_count(
            self.successes
        )

        self.failures = self._safe_count(
            self.failures
        )

        self.pending = self._safe_count(
            self.pending
        )

        for value, field_name in (
            (self.legacy_status, "CheckSummary.legacy_status"),
            (self.error, "CheckSummary.error"),
        ):
            if value is not None and not isinstance(
                value,
                str,
            ):
                raise TypeError(
                    f"{field_name} must be a string or None"
                )

    @staticmethod
    def _safe_count(
        value: Any,
    ) -> int:
        try:
            return max(
                0,
                int(value or 0),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OwnershipMatch:
    """
    A CODEOWNERS-derived ownership match.
    """

    owner: str
    file: str
    pattern: str
    line: int

    source: str = "CODEOWNERS"

    def __post_init__(self) -> None:
        _require_nonempty_string(
            self.owner,
            "OwnershipMatch.owner",
        )

        _require_nonempty_string(
            self.file,
            "OwnershipMatch.file",
        )

        _require_nonempty_string(
            self.pattern,
            "OwnershipMatch.pattern",
        )

        try:
            self.line = int(
                self.line
            )
        except (
            TypeError,
            ValueError,
        ):
            raise ValueError(
                "OwnershipMatch.line must be an integer"
            ) from None

        if self.line < 1:
            raise ValueError(
                "OwnershipMatch.line must be greater than zero"
            )

        if not isinstance(self.source, str):
            raise TypeError(
                "OwnershipMatch.source must be a string"
            )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriageReport:
    """
    Canonical report consumed by the CLI and eventually the web UI.

    This is the central contract of Triager V2.
    """

    schema_version: str
    repository: str
    generated_at: str

    disposition: str

    pr: dict[str, Any]

    process_signals: list[ProcessSignal] = field(
        default_factory=list
    )

    technical_findings: list[Finding] = field(
        default_factory=list
    )

    files: list[FileEvidence] = field(
        default_factory=list
    )

    experts: list[OwnershipMatch] = field(
        default_factory=list
    )

    checks: CheckSummary | None = None

    evidence_completeness: EvidenceCompleteness = field(
        default_factory=EvidenceCompleteness
    )

    linked_issues: list[dict[str, Any]] = field(
        default_factory=list
    )

    references: dict[str, Any] = field(
        default_factory=dict
    )

    backport_targets: list[str] = field(
        default_factory=list
    )

    signature_changes: list[dict[str, Any]] = field(
        default_factory=list
    )

    historical_context: dict[str, Any] | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    ai_synthesis: dict[str, Any] | None = None

    ai_error: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(
            self.schema_version,
            "TriageReport.schema_version",
        )

        _require_nonempty_string(
            self.repository,
            "TriageReport.repository",
        )

        _require_nonempty_string(
            self.generated_at,
            "TriageReport.generated_at",
        )

        _require_nonempty_string(
            self.disposition,
            "TriageReport.disposition",
        )

        if not isinstance(self.pr, dict):
            raise TypeError(
                "TriageReport.pr must be a dictionary"
            )

        if not isinstance(self.linked_issues, list):
            raise TypeError(
                "TriageReport.linked_issues must be a list"
            )

        if not isinstance(self.references, dict):
            raise TypeError(
                "TriageReport.references must be a dictionary"
            )

        if not isinstance(self.backport_targets, list):
            raise TypeError(
                "TriageReport.backport_targets must be a list"
            )

        if not isinstance(self.signature_changes, list):
            raise TypeError(
                "TriageReport.signature_changes must be a list"
            )

        if self.historical_context is not None and not isinstance(
            self.historical_context,
            dict,
        ):
            raise TypeError(
                "TriageReport.historical_context must be a dictionary or None"
            )

        if not isinstance(self.metadata, dict):
            raise TypeError(
                "TriageReport.metadata must be a dictionary"
            )

        if self.ai_synthesis is not None and not isinstance(
            self.ai_synthesis,
            dict,
        ):
            raise TypeError(
                "TriageReport.ai_synthesis must be a dictionary or None"
            )

        if self.ai_error is not None and not isinstance(
            self.ai_error,
            str,
        ):
            raise TypeError(
                "TriageReport.ai_error must be a string or None"
            )

        if not isinstance(
            self.evidence_completeness,
            EvidenceCompleteness,
        ):
            self.evidence_completeness = (
                EvidenceCompleteness(
                    **self.evidence_completeness
                )
                if isinstance(
                    self.evidence_completeness,
                    dict,
                )
                else EvidenceCompleteness()
            )

        if not isinstance(self.process_signals, list):
            raise TypeError(
                "TriageReport.process_signals must be a list"
            )

        self.process_signals = [
            signal
            if isinstance(
                signal,
                ProcessSignal,
            )
            else ProcessSignal(
                **signal
            )
            for signal in self.process_signals
        ]

        if not isinstance(self.technical_findings, list):
            raise TypeError(
                "TriageReport.technical_findings must be a list"
            )

        self.technical_findings = [
            finding
            if isinstance(
                finding,
                Finding,
            )
            else Finding(
                **finding
            )
            for finding in self.technical_findings
        ]

        if not isinstance(self.files, list):
            raise TypeError(
                "TriageReport.files must be a list"
            )

        self.files = [
            file_data
            if isinstance(
                file_data,
                FileEvidence,
            )
            else FileEvidence(
                **file_data
            )
            for file_data in self.files
        ]

        if not isinstance(self.experts, list):
            raise TypeError(
                "TriageReport.experts must be a list"
            )

        self.experts = [
            expert
            if isinstance(
                expert,
                OwnershipMatch,
            )
            else OwnershipMatch(
                **expert
            )
            for expert in self.experts
        ]

        if self.checks is not None and not isinstance(
            self.checks,
            CheckSummary,
        ):
            if isinstance(
                self.checks,
                dict,
            ):
                self.checks = CheckSummary(
                    **self.checks
                )
            else:
                raise TypeError(
                    "TriageReport.checks must be "
                    "CheckSummary, dict, or None"
                )

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the complete canonical report.

        ``dataclasses.asdict`` recursively converts all nested dataclass
        instances, including EvidenceRef, Finding, ProcessSignal,
        FileEvidence, OwnershipMatch, CheckSummary, and
        EvidenceCompleteness.
        """

        return asdict(
            self
        )