"""
Canonical report construction for CPython PR triage.

This module assembles the final report from already-collected evidence
and deterministic analysis results.

It does not perform GitHub requests and does not own CLI presentation.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def build_report(
    *,
    repository: str,
    generated_at: str,
    evidence: dict[str, Any],
    linked_issues: list[dict[str, Any]],
    experts: list[dict[str, Any]],
    findings: list[Any],
    signatures: list[dict[str, Any]],
    process: list[tuple[str, str]],
    backports: list[str],
    disposition: str,
    checks: dict[str, Any],
    classify: Callable[[str], tuple[str, str, str | None]],
    summarize_labels: Callable[
        [list[str], dict[str, Any]],
        list[dict[str, Any]],
    ],
    label_metadata: Callable[
        [Any],
        dict[str, Any],
    ],
    gh: Any,
) -> dict[str, Any]:
    """
    Build the canonical triager report.

    The function intentionally receives analysis results and small
    application callbacks instead of importing orchestration logic.
    This keeps report construction independent of GitHub and CLI concerns
    while preserving the existing report schema.
    """

    pr = evidence["pr"]
    files = evidence["files"]
    timeline = evidence["timeline"]

    labels = [
        item.get("name")
        for item in pr.get("labels", [])
    ]

    adds = sum(
        int(
            file_data.get(
                "additions",
                0,
            )
            or 0
        )
        for file_data in files
    )

    dels = sum(
        int(
            file_data.get(
                "deletions",
                0,
            )
            or 0
        )
        for file_data in files
    )

    if (
        checks.get(
            "summary",
            {},
        ).get(
            "failures"
        )
    ):
        process = [
            *process,
            (
                "WARN",
                f"{checks['summary']['failures']} "
                "completed CI check(s) have failure-like conclusions.",
            ),
        ]

    return {
        "schema_version": "1.0",
        "repository": repository,
        "generated_at": generated_at,
        "pr": {
            "number": pr.get(
                "number"
            ),
            "title": pr.get(
                "title"
            ),
            "state": pr.get(
                "state"
            ),
            "merged": bool(
                pr.get(
                    "merged_at"
                )
            ),
            "draft": bool(
                pr.get(
                    "draft"
                )
            ),
            "author": (
                pr.get(
                    "user"
                )
                or {}
            ).get(
                "login"
            ),
            "base": (
                pr.get(
                    "base"
                )
                or {}
            ).get(
                "ref"
            ),
            "base_sha": (
                pr.get(
                    "base"
                )
                or {}
            ).get(
                "sha"
            ),
            "head": (
                pr.get(
                    "head"
                )
                or {}
            ).get(
                "ref"
            ),
            "head_sha": (
                pr.get(
                    "head"
                )
                or {}
            ).get(
                "sha"
            ),
            "labels": labels,
            "additions": adds,
            "deletions": dels,
            "changed_files": pr.get(
                "changed_files"
            ),
            "commits": pr.get(
                "commits"
            ),
            "created_at": pr.get(
                "created_at"
            ),
            "updated_at": pr.get(
                "updated_at"
            ),
            "closed_at": pr.get(
                "closed_at"
            ),
            "merged_at": pr.get(
                "merged_at"
            ),
            "mergeable": pr.get(
                "mergeable"
            ),
            "mergeable_state": pr.get(
                "mergeable_state"
            ),
        },
        "disposition": disposition,
        "process_signals": [
            {
                "signal": signal,
                "message": message,
            }
            for signal, message in process
        ],
        "backport_targets": backports,
        "technical_findings": [
            finding.as_dict()
            for finding in findings
        ],
        "signature_changes": signatures,
        "files": [
            {
                "filename": file_data.get(
                    "filename"
                ),
                "status": file_data.get(
                    "status"
                ),
                "additions": file_data.get(
                    "additions"
                ),
                "deletions": file_data.get(
                    "deletions"
                ),
                "subsystem": classify(
                    file_data.get(
                        "filename",
                        "",
                    )
                )[0],
                "component": classify(
                    file_data.get(
                        "filename",
                        "",
                    )
                )[1],
                "expected_test_hint": classify(
                    file_data.get(
                        "filename",
                        "",
                    )
                )[2],
            }
            for file_data in files
        ],
        "experts": experts,
        "labels": summarize_labels(
            labels,
            label_metadata(gh),
        ),
        "checks": checks,
        "linked_issues": linked_issues,
        "timeline": timeline,
        "evidence_counts": {
            "timeline_events": len(
                timeline
            ),
            "human_timeline_events": sum(
                not event.get(
                    "bot"
                )
                for event in timeline
            ),
            "reviews": len(
                evidence[
                    "reviews"
                ]
            ),
            "review_comments": len(
                evidence[
                    "review_comments"
                ]
            ),
            "issue_comments": len(
                evidence[
                    "issue_comments"
                ]
            ),
            "linked_issues": len(
                linked_issues
            ),
            "api_calls": gh.calls,
            "cache_hits": gh.cache_hits,
            "rate_limit_remaining": (
                gh.rate_remaining
            ),
            "rate_limit_reset": (
                gh.rate_reset
            ),
        },
    }