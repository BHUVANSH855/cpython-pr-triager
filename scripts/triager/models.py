"""
Canonical data models for the CPython PR Triager.

The most important design rule in this module is:

    evidence != inference

Every deterministic finding should retain enough provenance to answer:

    "Why did the triager say this?"

The models deliberately distinguish:
- observed evidence
- derived signals
- heuristic findings
- process signals
- optional AI synthesis
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


@dataclass
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

    evidence_refs: list[EvidenceRef] = field(default_factory=list)

    file: str | None = None
    rule_id: str | None = None

    # review = human review recommended
    # informational = useful context only
    # suppressed = intentionally hidden by policy
    status: str = "review"

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

    evidence_refs: list[EvidenceRef] = field(default_factory=list)

    rule_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceCompleteness:
    """
    Tracks what evidence the triager attempted to collect.

    Missing evidence must never silently become negative evidence.
    """

    attempted: list[str] = field(default_factory=list)
    available: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    errors: dict[str, str] = field(default_factory=dict)

    @property
    def score(self) -> float:
        if not self.attempted:
            return 1.0

        return len(self.available) / len(self.attempted)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["score"] = round(self.score, 3)
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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)