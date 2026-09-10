"""
Canonical data models for the CPython PR Triager.

Updated in v1.2:
  - Added ExpertContext dataclass: enriched expert routing with reviewer
    profiles, known concerns, dynamic activity, co-owner suggestions.
  - TriageReport gains expert_contexts field.
  - SCHEMA_VERSION bumped to 1.2.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
FINDING_STATUSES = {"review", "informational", "suppressed"}
PROCESS_SIGNAL_LEVELS = {"BLOCK", "WARN", "INFO", "OK"}
EVIDENCE_STATUSES = {"complete", "partial", "unavailable"}


def _require_choice(value: Any, allowed: set | dict, field_name: str) -> str:
    if value not in allowed:
        choices = ", ".join(sorted(str(k) for k in allowed))
        raise ValueError(f"{field_name} must be one of {choices}; got {value!r}")
    return value


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _normalise_evidence_refs(refs: Any, field_name: str) -> list[EvidenceRef]:
    if refs is None:
        return []
    if not isinstance(refs, list):
        raise TypeError(f"{field_name} must be a list")
    normalized: list[EvidenceRef] = []
    for ref in refs:
        if isinstance(ref, EvidenceRef):
            normalized.append(ref)
        elif isinstance(ref, dict):
            normalized.append(EvidenceRef(**ref))
        else:
            raise TypeError(f"{field_name} entries must be EvidenceRef objects or dicts")
    return normalized


@dataclass(frozen=True)
class EvidenceRef:
    kind: str
    description: str
    source: str | None = None
    file: str | None = None
    line: int | None = None
    url: str | None = None
    observed: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.kind, "EvidenceRef.kind")
        _require_nonempty_string(self.description, "EvidenceRef.description")
        if self.line is not None:
            try:
                normalized_line = int(self.line)
            except (TypeError, ValueError):
                raise ValueError("EvidenceRef.line must be an integer or None") from None
            if normalized_line < 1:
                raise ValueError("EvidenceRef.line must be greater than zero")
            object.__setattr__(self, "line", normalized_line)
        for value, fname in (
            (self.source, "EvidenceRef.source"), (self.file, "EvidenceRef.file"),
            (self.url, "EvidenceRef.url"), (self.observed, "EvidenceRef.observed"),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{fname} must be a string or None")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    confidence: str
    source: str = "deterministic"
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    file: str | None = None
    rule_id: str | None = None
    status: str = "review"

    def __post_init__(self) -> None:
        _require_choice(self.severity, SEVERITY_ORDER, "Finding.severity")
        _require_choice(self.confidence, CONFIDENCE_ORDER, "Finding.confidence")
        _require_choice(self.status, FINDING_STATUSES, "Finding.status")
        _require_nonempty_string(self.category, "Finding.category")
        _require_nonempty_string(self.message, "Finding.message")
        if not isinstance(self.source, str):
            raise TypeError("Finding.source must be a string")
        if self.file is not None and not isinstance(self.file, str):
            raise TypeError("Finding.file must be a string or None")
        if self.rule_id is not None and not isinstance(self.rule_id, str):
            raise TypeError("Finding.rule_id must be a string or None")
        self.evidence_refs = _normalise_evidence_refs(self.evidence_refs, "Finding.evidence_refs")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessSignal:
    level: str
    message: str
    source: str = "policy"
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    rule_id: str | None = None

    def __post_init__(self) -> None:
        _require_choice(self.level, PROCESS_SIGNAL_LEVELS, "ProcessSignal.level")
        _require_nonempty_string(self.message, "ProcessSignal.message")
        if not isinstance(self.source, str):
            raise TypeError("ProcessSignal.source must be a string")
        if self.rule_id is not None and not isinstance(self.rule_id, str):
            raise TypeError("ProcessSignal.rule_id must be a string or None")
        self.evidence_refs = _normalise_evidence_refs(self.evidence_refs, "ProcessSignal.evidence_refs")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceCompleteness:
    attempted: list[str] = field(default_factory=list)
    available: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.attempted = self._normalise_names(self.attempted)
        self.available = self._normalise_names(self.available)
        self.missing = self._normalise_names(self.missing)
        if not isinstance(self.errors, dict):
            raise TypeError("EvidenceCompleteness.errors must be a dictionary")
        self.errors = {str(k): str(v) for k, v in self.errors.items() if str(k).strip()}
        attempted = set(self.attempted)
        available = set(self.available)
        missing = set(self.missing)
        self.attempted = sorted(attempted | available | missing | set(self.errors))
        self.missing = sorted(missing - available)
        self.available = sorted(available)

    @staticmethod
    def _normalise_names(names: list[str] | None) -> list[str]:
        if names is None:
            return []
        if not isinstance(names, list):
            raise TypeError("Evidence source names must be lists")
        return sorted({str(n).strip() for n in names if str(n).strip()})

    @property
    def score(self) -> float:
        if not self.attempted:
            return 1.0
        return min(1.0, max(0.0, len(set(self.available)) / len(set(self.attempted))))

    @property
    def complete(self) -> bool:
        if not self.attempted:
            return True
        return not bool(set(self.attempted) - set(self.available))

    @property
    def status(self) -> str:
        if self.complete:
            return "complete"
        if self.available:
            return "partial"
        return "unavailable"

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["score"] = round(self.score, 3)
        data["complete"] = self.complete
        data["status"] = self.status
        return data


@dataclass
class FileEvidence:
    filename: str
    status: str | None = None
    additions: int = 0
    deletions: int = 0
    patch_available: bool = False
    subsystem: str | None = None
    component: str | None = None
    expected_test_hint: str | None = None

    @staticmethod
    def _safe_nonnegative_int(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def __post_init__(self) -> None:
        _require_nonempty_string(self.filename, "FileEvidence.filename")
        self.additions = self._safe_nonnegative_int(self.additions)
        self.deletions = self._safe_nonnegative_int(self.deletions)
        self.patch_available = bool(self.patch_available)
        for value, fname in (
            (self.status, "FileEvidence.status"),
            (self.subsystem, "FileEvidence.subsystem"),
            (self.component, "FileEvidence.component"),
            (self.expected_test_hint, "FileEvidence.expected_test_hint"),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{fname} must be a string or None")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckSummary:
    available: bool
    check_runs: int = 0
    completed: int = 0
    successes: int = 0
    failures: int = 0
    pending: int = 0
    legacy_status: str | None = None
    error: str | None = None

    @staticmethod
    def _safe_count(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def __post_init__(self) -> None:
        self.available = bool(self.available)
        for attr in ("check_runs", "completed", "successes", "failures", "pending"):
            setattr(self, attr, self._safe_count(getattr(self, attr)))
        for value, fname in (
            (self.legacy_status, "CheckSummary.legacy_status"),
            (self.error, "CheckSummary.error"),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{fname} must be a string or None")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OwnershipMatch:
    owner: str
    file: str
    pattern: str
    line: int
    source: str = "CODEOWNERS"

    def __post_init__(self) -> None:
        _require_nonempty_string(self.owner, "OwnershipMatch.owner")
        _require_nonempty_string(self.file, "OwnershipMatch.file")
        _require_nonempty_string(self.pattern, "OwnershipMatch.pattern")
        try:
            self.line = int(self.line)
        except (TypeError, ValueError):
            raise ValueError("OwnershipMatch.line must be an integer") from None
        if self.line < 1:
            raise ValueError("OwnershipMatch.line must be greater than zero")
        if not isinstance(self.source, str):
            raise TypeError("OwnershipMatch.source must be a string")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExpertContext:
    """
    Enriched expert routing entry combining CODEOWNERS match with
    reviewer profile knowledge and optional dynamic activity data.

    This replaces the plain OwnershipMatch in the report output,
    giving the AI synthesis layer and human readers:
      - What areas this reviewer owns
      - Who else they co-review with
      - What they typically ask about before approving
      - Keywords they focus on in technical review
      - Dynamic: their approval rate, common concern patterns,
        sample phrases from real review comments
    """

    # Core CODEOWNERS fields
    owner: str
    file: str
    pattern: str
    line: int = 0

    # Static profile fields (from reviewer_profiles.py)
    subsystems: list[str] = field(default_factory=list)
    co_owners: list[str] = field(default_factory=list)
    known_concerns: list[str] = field(default_factory=list)
    focus_keywords: list[str] = field(default_factory=list)
    typical_response_days: float | None = None

    # Dynamic activity fields (from reviewer_activity.py — optional)
    dynamic_concerns: list[str] = field(default_factory=list)
    approval_rate: float | None = None
    sample_phrases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.owner, str):
            raise TypeError("ExpertContext.owner must be a string")
        if not isinstance(self.file, str):
            raise TypeError("ExpertContext.file must be a string")
        try:
            self.line = int(self.line)
        except (TypeError, ValueError):
            self.line = 0
        for attr in ("subsystems", "co_owners", "known_concerns",
                     "focus_keywords", "dynamic_concerns", "sample_phrases"):
            val = getattr(self, attr)
            if not isinstance(val, list):
                setattr(self, attr, list(val) if val else [])
        if self.approval_rate is not None:
            self.approval_rate = max(0.0, min(1.0, float(self.approval_rate)))
        if self.typical_response_days is not None:
            self.typical_response_days = float(self.typical_response_days)

    @property
    def username(self) -> str:
        return self.owner.lstrip("@")

    @property
    def all_concerns(self) -> list[str]:
        """Combined known + dynamic concerns, deduplicated."""
        seen: set[str] = set()
        result: list[str] = []
        for concern in self.known_concerns + self.dynamic_concerns:
            if concern not in seen:
                seen.add(concern)
                result.append(concern)
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "file": self.file,
            "pattern": self.pattern,
            "line": self.line,
            "username": self.username,
            "subsystems": self.subsystems,
            "co_owners": self.co_owners,
            "known_concerns": self.known_concerns,
            "focus_keywords": self.focus_keywords,
            "typical_response_days": self.typical_response_days,
            "dynamic_concerns": self.dynamic_concerns,
            "approval_rate": self.approval_rate,
            "sample_phrases": self.sample_phrases,
            "all_concerns": self.all_concerns,
        }


@dataclass
class TriageReport:
    """Canonical report consumed by the CLI and web UI."""

    schema_version: str
    repository: str
    generated_at: str
    disposition: str
    pr: dict[str, Any]

    process_signals: list[ProcessSignal] = field(default_factory=list)
    technical_findings: list[Finding] = field(default_factory=list)
    files: list[FileEvidence] = field(default_factory=list)

    # Raw CODEOWNERS matches (backward compat)
    experts: list[OwnershipMatch] = field(default_factory=list)

    # Enriched expert contexts with reviewer profiles + activity
    expert_contexts: list[ExpertContext] = field(default_factory=list)

    checks: CheckSummary | None = None
    evidence_completeness: EvidenceCompleteness = field(default_factory=EvidenceCompleteness)
    linked_issues: list[dict[str, Any]] = field(default_factory=list)
    references: dict[str, Any] = field(default_factory=dict)
    backport_targets: list[str] = field(default_factory=list)
    signature_changes: list[dict[str, Any]] = field(default_factory=list)
    historical_context: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    ai_synthesis: dict[str, Any] | None = None
    ai_error: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.schema_version, "TriageReport.schema_version")
        _require_nonempty_string(self.repository, "TriageReport.repository")
        _require_nonempty_string(self.generated_at, "TriageReport.generated_at")
        _require_nonempty_string(self.disposition, "TriageReport.disposition")
        if not isinstance(self.pr, dict):
            raise TypeError("TriageReport.pr must be a dictionary")
        for attr in ("linked_issues", "backport_targets", "signature_changes"):
            if not isinstance(getattr(self, attr), list):
                raise TypeError(f"TriageReport.{attr} must be a list")
        for attr in ("references", "metadata"):
            if not isinstance(getattr(self, attr), dict):
                raise TypeError(f"TriageReport.{attr} must be a dictionary")
        if self.historical_context is not None and not isinstance(self.historical_context, dict):
            raise TypeError("TriageReport.historical_context must be a dict or None")
        if self.ai_synthesis is not None and not isinstance(self.ai_synthesis, dict):
            raise TypeError("TriageReport.ai_synthesis must be a dict or None")
        if self.ai_error is not None and not isinstance(self.ai_error, str):
            raise TypeError("TriageReport.ai_error must be a string or None")

        if not isinstance(self.evidence_completeness, EvidenceCompleteness):
            self.evidence_completeness = (
                EvidenceCompleteness(**self.evidence_completeness)
                if isinstance(self.evidence_completeness, dict)
                else EvidenceCompleteness()
            )

        if not isinstance(self.process_signals, list):
            raise TypeError("TriageReport.process_signals must be a list")
        self.process_signals = [
            s if isinstance(s, ProcessSignal) else ProcessSignal(**s)
            for s in self.process_signals
        ]

        if not isinstance(self.technical_findings, list):
            raise TypeError("TriageReport.technical_findings must be a list")
        self.technical_findings = [
            f if isinstance(f, Finding) else Finding(**f)
            for f in self.technical_findings
        ]

        if not isinstance(self.files, list):
            raise TypeError("TriageReport.files must be a list")
        self.files = [
            f if isinstance(f, FileEvidence) else FileEvidence(**f)
            for f in self.files
        ]

        if not isinstance(self.experts, list):
            raise TypeError("TriageReport.experts must be a list")
        self.experts = [
            e if isinstance(e, OwnershipMatch) else OwnershipMatch(**e)
            for e in self.experts
        ]

        if not isinstance(self.expert_contexts, list):
            raise TypeError("TriageReport.expert_contexts must be a list")
        self.expert_contexts = [
            e if isinstance(e, ExpertContext) else ExpertContext(**e)
            for e in self.expert_contexts
        ]

        if self.checks is not None and not isinstance(self.checks, CheckSummary):
            if isinstance(self.checks, dict):
                self.checks = CheckSummary(**self.checks)
            else:
                raise TypeError("TriageReport.checks must be CheckSummary, dict, or None")

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # expert_contexts use custom as_dict (not a plain dataclass field)
        data["expert_contexts"] = [e.as_dict() for e in self.expert_contexts]
        return data
