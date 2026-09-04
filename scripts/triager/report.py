"""
Canonical triage report construction.

This module is where evidence, findings, and process signals
become one report.

The important ordering rule is:

    collect ALL signals
        ↓
    collect ALL findings
        ↓
    calculate disposition

Never calculate the disposition before CI/process evidence
has been incorporated.
"""

from __future__ import annotations

import datetime as dt
from typing import Iterable

from .models import (
    CheckSummary,
    EvidenceCompleteness,
    FileEvidence,
    Finding,
    OwnershipMatch,
    ProcessSignal,
    TriageReport,
)


VALID_DISPOSITIONS = {
    "PROCESS_BLOCKED",
    "NEEDS_TECHNICAL_REVIEW",
    "NEEDS_MAINTAINER_ATTENTION",
    "READY_FOR_MAINTAINER_REVIEW",
}


def disposition(
    process_signals: Iterable[ProcessSignal],
    findings: Iterable[Finding],
) -> str:
    """
    Calculate the canonical deterministic disposition.

    Priority:

        process blocker
            ↓
        critical/high technical concern
            ↓
        process warning
            ↓
        medium technical concern
            ↓
        ready for maintainer review
    """

    process = list(
        process_signals
    )

    technical = list(
        findings
    )

    if any(
        signal.level.upper()
        == "BLOCK"
        for signal in process
    ):
        return "PROCESS_BLOCKED"

    if any(
        finding.severity.upper()
        in {
            "CRITICAL",
            "HIGH",
        }
        for finding in technical
    ):
        return "NEEDS_TECHNICAL_REVIEW"

    if any(
        signal.level.upper()
        == "WARN"
        for signal in process
    ):
        return "NEEDS_MAINTAINER_ATTENTION"

    if any(
        finding.severity.upper()
        == "MEDIUM"
        for finding in technical
    ):
        return "NEEDS_TECHNICAL_REVIEW"

    return "READY_FOR_MAINTAINER_REVIEW"


def build_completeness(
    attempted: Iterable[str],
    available: Iterable[str],
    errors: dict[str, str] | None = None,
) -> EvidenceCompleteness:
    """
    Build an explicit evidence-completeness object.
    """

    attempted_values = list(
        dict.fromkeys(
            attempted
        )
    )

    available_values = list(
        dict.fromkeys(
            available
        )
    )

    missing = [
        item
        for item in attempted_values
        if item not in available_values
    ]

    return EvidenceCompleteness(
        attempted=attempted_values,
        available=available_values,
        missing=missing,
        errors=errors or {},
    )


def normalize_files(
    files: list[dict],
) -> list[FileEvidence]:
    """
    Convert raw GitHub file objects into canonical file evidence.
    """

    result: list[FileEvidence] = []

    for file_data in files:
        result.append(
            FileEvidence(
                filename=file_data.get(
                    "filename",
                    "",
                ),
                status=file_data.get(
                    "status"
                ),
                additions=int(
                    file_data.get(
                        "additions",
                        0,
                    )
                    or 0
                ),
                deletions=int(
                    file_data.get(
                        "deletions",
                        0,
                    )
                    or 0
                ),
                patch_available=bool(
                    file_data.get(
                        "patch"
                    )
                ),
            )
        )

    return result


def build_report(
    repository: str,
    pr: dict,
    files: list[dict],
    process_signals: list[ProcessSignal],
    findings: list[Finding],
    experts: list[OwnershipMatch],
    checks: CheckSummary | None = None,
    evidence_completeness: EvidenceCompleteness | None = None,
    linked_issues: list[dict] | None = None,
    references: dict | None = None,
    backport_targets: list[str] | None = None,
    signature_changes: list[dict] | None = None,
    historical_context: dict | None = None,
    metadata: dict | None = None,
) -> TriageReport:
    """
    Construct the canonical report.

    Disposition is deliberately calculated LAST.
    """

    return TriageReport(
        schema_version="2.0",
        repository=repository,
        generated_at=dt.datetime.now(
            dt.timezone.utc
        ).isoformat(),
        disposition=disposition(
            process_signals,
            findings,
        ),
        pr=pr,
        process_signals=process_signals,
        technical_findings=findings,
        files=normalize_files(
            files
        ),
        experts=experts,
        checks=checks,
        evidence_completeness=(
            evidence_completeness
            or EvidenceCompleteness()
        ),
        linked_issues=(
            linked_issues
            or []
        ),
        references=(
            references
            or {}
        ),
        backport_targets=(
            backport_targets
            or []
        ),
        signature_changes=(
            signature_changes
            or []
        ),
        historical_context=(
            historical_context
        ),
        metadata=(
            metadata
            or {}
        ),
    )