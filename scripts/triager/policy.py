"""
Deterministic policy decisions for CPython PR triage.

This module contains process-signal, backport, review, and disposition
rules. It does not perform GitHub requests or CLI presentation.

Fixes applied:
- BACKPORT_LABEL_RE now matches "needs-backport-to-X.Y" (hyphens) which
  is the actual label format used in python/cpython (was matching spaces).
- 3.10 security-only branch now explicitly flagged (point 14).
- _iso_age_days moved here (was also duplicated in analyze.py).
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

MAINTENANCE_BRANCH_RE = re.compile(r"^3\.\d+$")

# FIX (point 3): real CPython labels use hyphens: "needs-backport-to-3.13"
# The original regex matched spaces which never matched any real label.
BACKPORT_LABEL_RE = re.compile(
    r"^needs-backport-to-(\d+\.\d+)$",
    re.IGNORECASE,
)

# FIX (point 14): 3.10 is security-fix-only.
SECURITY_ONLY_BRANCHES = frozenset({"3.10"})


def _iso_age_days(value: str | None) -> float | None:
    """Calculate age in days from an ISO-8601 timestamp."""
    if not value:
        return None
    try:
        return (
            dt.datetime.now(dt.timezone.utc)
            - dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        ).total_seconds() / 86400
    except ValueError:
        return None


def file_signals(
    files: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Classify changed files into names, tests, NEWS entries, and docs."""
    names = [f.get("filename", "") for f in files]

    tests = [
        name
        for name in names
        if (
            name.startswith("Lib/test/")
            or "/test/" in name
            or Path(name).name.startswith("test_")
        )
    ]

    news = [name for name in names if name.startswith("Misc/NEWS.d/")]
    docs = [name for name in names if name.startswith("Doc/")]

    return names, tests, news, docs


def review_signals(
    pr: dict[str, Any],
    timeline: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    """Produce deterministic signals from human review activity."""
    human = [event for event in timeline if not event.get("bot")]

    approvals = [
        event
        for event in human
        if event.get("kind") == "review" and event.get("state") == "APPROVED"
    ]

    changes = [
        event
        for event in human
        if event.get("kind") == "review" and event.get("state") == "CHANGES_REQUESTED"
    ]

    signals: list[tuple[str, str]] = []

    if approvals:
        signals.append(
            ("OK", f"{len(approvals)} human approval review(s) recorded.")
        )

    if changes:
        latest = max(changes, key=lambda e: e.get("date", ""))
        later = [e for e in human if e.get("date", "") > latest.get("date", "")]

        if later:
            signals.append(
                (
                    "INFO",
                    f"Changes were requested by @{latest.get('login','?')}; "
                    "later human activity exists.",
                )
            )
        else:
            signals.append(
                (
                    "WARN",
                    f"Latest changes-requested review is by @{latest.get('login','?')} "
                    "with no later human activity.",
                )
            )

    if pr.get("state") == "open":
        dates = [e.get("date") for e in human if e.get("date")]
        if dates:
            age = _iso_age_days(max(dates))
            if age is not None:
                if age > 90:
                    signals.append(
                        (
                            "WARN",
                            f"No human activity for about {age:.0f} days; "
                            "review whether follow-up is appropriate.",
                        )
                    )
                elif age > 30:
                    signals.append(
                        (
                            "INFO",
                            f"No human activity for about {age:.0f} days; "
                            "follow-up may be appropriate.",
                        )
                    )

    return signals


def branch_and_backport_signals(
    pr: dict[str, Any],
    labels: list[str],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Produce branch-policy signals and extract requested backport targets."""
    base = (pr.get("base") or {}).get("ref", "")

    signals: list[tuple[str, str]] = []

    if MAINTENANCE_BRANCH_RE.fullmatch(base):
        # FIX (point 14): 3.10 is security-only — reject bug fixes.
        if base in SECURITY_ONLY_BRANCHES:
            type_labels = set(labels) & {
                "type-bug", "type-feature", "type-enhancement",
                "type-crash",
            }
            if type_labels:
                signals.append(
                    (
                        "BLOCK",
                        f"PR targets {base} which is a security-fix-only branch. "
                        "Only CVE-level security fixes are accepted on this branch. "
                        "Re-target to main for bug fixes.",
                    )
                )
            else:
                signals.append(
                    (
                        "WARN",
                        f"PR targets {base} (security-fix-only); verify this is "
                        "a genuine security fix before approving.",
                    )
                )
        else:
            # Stable branch: no new features.
            if {"type-feature", "type-enhancement"} & set(labels):
                signals.append(
                    (
                        "BLOCK",
                        f"Feature/enhancement-labelled PR targets maintenance branch {base}; "
                        "verify CPython branch policy.",
                    )
                )

            if "type-security" in labels:
                signals.append(
                    (
                        "INFO",
                        f"Security-labelled PR targets maintenance branch {base}; "
                        "verify security handling.",
                    )
                )

    backports: list[str] = []
    for label in labels:
        match = BACKPORT_LABEL_RE.fullmatch(label)
        if match:
            backports.append(match.group(1))

    if backports:
        signals.append(
            (
                "INFO",
                "Backport intent labels: " + ", ".join(sorted(backports)) + ".",
            )
        )

    return signals, backports


def process_signals(
    pr: dict[str, Any],
    files: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    labels: list[str],
    patterns: dict[str, Any] | None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Determine deterministic process signals and backport targets."""
    signals: list[tuple[str, str]] = []

    title = pr.get("title") or ""

    if re.match(r"^gh-\d{3,7}:\s+\S", title, re.IGNORECASE):
        signals.append(("OK", "Title uses the current gh-NNNNN issue-reference style."))
    elif re.match(r"^\[(?:3\.\d+|main)\]\s+\S", title):
        signals.append(("OK", "Title looks like a branch/backport title."))
    else:
        signals.append(
            (
                "INFO",
                "Title does not use the common gh-/backport form; style signal only.",
            )
        )

    adds = int(pr.get("additions", 0) or 0)
    dels = int(pr.get("deletions", 0) or 0)
    total = adds + dels

    stats = (patterns or {}).get("statistics") or {}
    p90 = stats.get("p90")
    p95 = stats.get("p95")

    if p95 is not None and total > p95:
        signals.append(
            ("WARN", f"PR size {total} changed lines is above sampled p95 ({p95:.0f}).")
        )
    elif p90 is not None and total > p90:
        signals.append(
            ("INFO", f"PR size {total} changed lines is above sampled p90 ({p90:.0f}).")
        )
    else:
        signals.append(
            ("OK", f"PR size is {total} changed lines across {pr.get('changed_files')} files.")
        )

    names, tests, news, docs = file_signals(files)
    labels_set = set(labels)

    if "skip news" in labels_set:
        signals.append(("OK", "skip news label is present."))
    elif news:
        signals.append(("OK", f"NEWS entry present ({len(news)} file(s))."))
    elif all(name.startswith("Doc/") for name in names):
        signals.append(("INFO", "Documentation-only change has no NEWS entry; usually not required."))
    elif all(name.startswith("Lib/test/") for name in names):
        signals.append(("INFO", "Test-only change has no NEWS entry; usually not required."))
    else:
        signals.append(
            ("WARN", "No Misc/NEWS.d entry detected; verify whether this change requires one.")
        )

    if tests:
        signals.append(("OK", f"Test-related file(s) changed ({len(tests)})."))
    elif all(name.startswith("Doc/") for name in names):
        signals.append(("INFO", "Documentation-only change has no test file; likely not applicable."))
    else:
        signals.append(
            ("WARN", "No test file changed; verify whether regression/behavior coverage is needed.")
        )

    if "DO-NOT-MERGE" in labels_set:
        signals.append(("BLOCK", "DO-NOT-MERGE is active."))

    if "awaiting changes" in labels_set:
        signals.append(("BLOCK", "awaiting changes indicates author action is expected."))

    if "awaiting merge" in labels_set:
        signals.append(("INFO", "awaiting merge is present; verify CI and current review state."))

    branch, backports = branch_and_backport_signals(pr, labels)
    signals.extend(branch)
    signals.extend(review_signals(pr, timeline))

    return signals, backports


def disposition(
    process: list[tuple[str, str]],
    findings: list[Any],
) -> str:
    """Determine the final PR disposition from deterministic signals."""
    if any(signal == "BLOCK" for signal, _ in process):
        return "PROCESS_BLOCKED"

    if any(
        finding.severity in {"CRITICAL", "HIGH"}
        for finding in findings
    ):
        return "NEEDS_TECHNICAL_REVIEW"

    if any(signal == "WARN" for signal, _ in process):
        return "NEEDS_MAINTAINER_ATTENTION"

    return "READY_FOR_MAINTAINER_REVIEW"