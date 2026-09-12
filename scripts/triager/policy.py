"""
Deterministic policy decisions for CPython PR triage.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MAINTENANCE_BRANCH_RE = re.compile(r"^3\.\d+$")

BRANCH_POLICY_FILENAME = "branch-policy.json"
BRANCH_POLICY_ENV = "CPYTHON_TRIAGER_BRANCH_POLICY"
BRANCH_POLICY_MAX_AGE_ENV = "CPYTHON_TRIAGER_BRANCH_POLICY_MAX_AGE_DAYS"
DEFAULT_BRANCH_POLICY_MAX_AGE_DAYS = 45

DEFAULT_BRANCH_POLICIES: dict[str, str] = {
    "main": "feature",
    "3.15": "prerelease",
    "3.14": "bugfix",
    "3.13": "bugfix",
    "3.12": "security",
    "3.11": "security",
    "3.10": "security",
    "3.9": "end-of-life",
    "3.8": "end-of-life",
    "3.7": "end-of-life",
    "3.6": "end-of-life",
    "3.5": "end-of-life",
    "3.4": "end-of-life",
    "3.3": "end-of-life",
    "3.2": "end-of-life",
    "3.1": "end-of-life",
    "3.0": "end-of-life",
}

VALID_BRANCH_STATUSES = frozenset(
    {
        "feature",
        "prerelease",
        "bugfix",
        "security",
        "end-of-life",
        "unknown",
    }
)

def _branch_policy_path() -> Path:
    override = os.environ.get(BRANCH_POLICY_ENV)
    if override:
        return Path(override).expanduser()

    return (
        Path(__file__).resolve().parents[2]
        / "data"
        / BRANCH_POLICY_FILENAME
    )


def _load_branch_policy_snapshot() -> tuple[dict[str, str], dict[str, Any]]:
    path = _branch_policy_path()

    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_BRANCH_POLICIES), {
            "status": "missing",
            "path": str(path),
        }

    if not isinstance(payload, Mapping):
        return dict(DEFAULT_BRANCH_POLICIES), {
            "status": "invalid",
            "path": str(path),
        }

    statuses = payload.get("statuses")
    if not isinstance(statuses, Mapping):
        return dict(DEFAULT_BRANCH_POLICIES), {
            "status": "invalid",
            "path": str(path),
        }

    policies: dict[str, str] = {}

    for branch, status in statuses.items():
        if not isinstance(branch, str) or not isinstance(status, str):
            continue

        normalized_status = status.strip().lower()

        if normalized_status in VALID_BRANCH_STATUSES:
            policies[branch.strip()] = normalized_status

    if not policies:
        return dict(DEFAULT_BRANCH_POLICIES), {
            "status": "invalid",
            "path": str(path),
        }

    metadata = {
        "status": "ok",
        "path": str(path),
        "schema_version": payload.get("schema_version"),
        "source": payload.get("source"),
        "retrieved_at": payload.get("retrieved_at"),
    }

    return policies, metadata


DEFAULT_BRANCH_POLICIES, BRANCH_POLICY_METADATA = (
    _load_branch_policy_snapshot()
)

SECURITY_ONLY_BRANCHES = frozenset(
    branch
    for branch, status in DEFAULT_BRANCH_POLICIES.items()
    if status == "security"
)

def _branch_policy_max_age_days() -> float:
    raw_value = os.environ.get(BRANCH_POLICY_MAX_AGE_ENV)

    if raw_value is None:
        return float(DEFAULT_BRANCH_POLICY_MAX_AGE_DAYS)

    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return float(DEFAULT_BRANCH_POLICY_MAX_AGE_DAYS)

    return max(0.0, value)


def _branch_policy_metadata_signals() -> list[tuple[str, str]]:
    status = BRANCH_POLICY_METADATA.get("status")

    if status == "missing":
        return [
            (
                "WARN",
                "Branch lifecycle policy snapshot could not be loaded; "
                "using the built-in fallback policy.",
            )
        ]

    if status == "invalid":
        return [
            (
                "WARN",
                "Branch lifecycle policy snapshot is invalid; using the "
                "built-in fallback policy.",
            )
        ]

    retrieved_at = BRANCH_POLICY_METADATA.get("retrieved_at")

    if not isinstance(retrieved_at, str) or not retrieved_at.strip():
        return [
            (
                "WARN",
                "Branch lifecycle policy snapshot has no retrieval "
                "timestamp; freshness could not be verified.",
            )
        ]

    age = _iso_age_days(retrieved_at)

    if age is None:
        return [
            (
                "WARN",
                "Branch lifecycle policy snapshot has an invalid retrieval "
                "timestamp; freshness could not be verified.",
            )
        ]

    max_age = _branch_policy_max_age_days()

    if age > max_age:
        return [
            (
                "WARN",
                f"Branch lifecycle policy snapshot is about {age:.0f} days "
                f"old, exceeding the configured {max_age:.0f}-day freshness "
                "window; refresh the snapshot before relying on lifecycle "
                "decisions.",
            )
        ]

    return []

BACKPORT_LABEL_RE = re.compile(
    r"^needs backport to (\d+\.\d+)$",
    re.IGNORECASE,
)

LEGACY_BACKPORT_LABEL_RE = re.compile(
    r"^needs-backport-to-(\d+\.\d+)$",
    re.IGNORECASE,
)

DO_NOT_MERGE_LABEL = "DO-NOT-MERGE"
AWAITING_ACTION_LABEL = "awaiting action"
SKIP_NEWS_LABEL = "skip news"

EVIDENCE_REVIEW_DISPOSITION = "NEEDS_EVIDENCE_REVIEW"


def _iso_age_days(value: str | None) -> float | None:
    if not value:
        return None

    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)

        return (
            dt.datetime.now(dt.timezone.utc) - parsed
        ).total_seconds() / 86400
    except (TypeError, ValueError):
        return None


def _normalise_label(label: Any) -> str:
    if label is None:
        return ""
    return str(label).strip()


def _normalise_labels(labels: list[str]) -> list[str]:
    return [
        normalized
        for label in labels
        if (normalized := _normalise_label(label))
    ]


def _casefold_labels(labels: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}

    for label in _normalise_labels(labels):
        result.setdefault(label.casefold(), label)

    return result


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _branch_status_from_mapping(
    branch: str,
    mapping: Mapping[str, Any] | None,
) -> str | None:
    if not mapping:
        return None

    value = mapping.get(branch)

    if isinstance(value, str):
        status = value.strip().lower()
        return status if status in VALID_BRANCH_STATUSES else None

    if isinstance(value, Mapping):
        status = value.get("status")
        if isinstance(status, str):
            status = status.strip().lower()
            return status if status in VALID_BRANCH_STATUSES else None

    return None


def _resolve_branch_status(
    pr: dict[str, Any],
    *,
    branch_policies: Mapping[str, Any] | None = None,
) -> str:
    base = pr.get("base") or {}
    branch = str(base.get("ref") or "").strip()

    candidates = (
        base.get("status"),
        base.get("branch_status"),
        pr.get("branch_status"),
    )

    for candidate in candidates:
        if isinstance(candidate, str):
            status = candidate.strip().lower()
            if status in VALID_BRANCH_STATUSES:
                return status

    status = _branch_status_from_mapping(branch, branch_policies)
    if status:
        return status

    return DEFAULT_BRANCH_POLICIES.get(branch, "unknown")


def _is_documentation_only(names: list[str]) -> bool:
    return bool(names) and all(name.startswith("Doc/") for name in names)


def _is_test_only(names: list[str]) -> bool:
    return bool(names) and all(
        name.startswith("Lib/test/")
        or "/test/" in name
        or Path(name).name.startswith("test_")
        for name in names
    )


def _is_news_only(names: list[str]) -> bool:
    return bool(names) and all(
        name.startswith("Misc/NEWS.d/")
        for name in names
    )


def file_signals(
    files: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str], list[str]]:
    names = [
        str(filename)
        for item in files
        if isinstance(item, dict)
        and (filename := item.get("filename"))
    ]

    tests = [
        name
        for name in names
        if (
            name.startswith("Lib/test/")
            or "/test/" in name
            or Path(name).name.startswith("test_")
        )
    ]

    news = [
        name
        for name in names
        if name.startswith("Misc/NEWS.d/")
    ]

    docs = [
        name
        for name in names
        if name.startswith("Doc/")
    ]

    return names, tests, news, docs


def review_signals(
    pr: dict[str, Any],
    timeline: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    human = [
        event
        for event in timeline
        if isinstance(event, dict) and not event.get("bot")
    ]

    approvals = [
        event
        for event in human
        if (
            event.get("kind") == "review"
            and str(event.get("state") or "").upper() == "APPROVED"
        )
    ]

    changes = [
        event
        for event in human
        if (
            event.get("kind") == "review"
            and str(event.get("state") or "").upper() == "CHANGES_REQUESTED"
        )
    ]

    signals: list[tuple[str, str]] = []

    if approvals:
        signals.append(
            (
                "OK",
                f"{len(approvals)} human approval review(s) recorded.",
            )
        )

    if changes:
        latest = max(
            changes,
            key=lambda event: str(event.get("date") or ""),
        )

        latest_date = str(latest.get("date") or "")

        later_human_activity = [
            event
            for event in human
            if str(event.get("date") or "") > latest_date
        ]

        if later_human_activity:
            signals.append(
                (
                    "INFO",
                    f"Changes were requested by "
                    f"@{latest.get('login', '?')}; later human activity "
                    "exists, but the requested changes should still be "
                    "verified as addressed.",
                )
            )
        else:
            signals.append(
                (
                    "WARN",
                    f"Latest changes-requested review is by "
                    f"@{latest.get('login', '?')} with no later human "
                    "activity.",
                )
            )

    if pr.get("state") == "open":
        dates = [
            str(event.get("date"))
            for event in human
            if event.get("date")
        ]

        if not dates and pr.get("updated_at"):
            age = _iso_age_days(str(pr["updated_at"]))

            if age is not None:
                if age > 90:
                    signals.append(
                        (
                            "WARN",
                            f"PR has not been updated for about {age:.0f} "
                            "days; review whether follow-up is appropriate.",
                        )
                    )
                elif age > 30:
                    signals.append(
                        (
                            "INFO",
                            f"PR has not been updated for about {age:.0f} "
                            "days; follow-up may be appropriate.",
                        )
                    )
        elif dates:
            latest_date = max(dates)
            age = _iso_age_days(latest_date)

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
    branch_policies: Mapping[str, Any] | None = None,
    files: list[dict[str, Any]] | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    base = str((pr.get("base") or {}).get("ref") or "").strip()
    normalized_labels = _normalise_labels(labels)

    signals: list[tuple[str, str]] = []

    branch_status = _resolve_branch_status(
        pr,
        branch_policies=branch_policies,
    )

    file_names = []
    if files:
        file_names = [
            str(filename)
            for item in files
            if isinstance(item, dict)
            and (filename := item.get("filename"))
        ]
    documentation_only = _is_documentation_only(file_names)

    type_labels = {
        label.casefold()
        for label in normalized_labels
        if label.casefold().startswith("type-")
    }

    is_feature = bool(
        {"type-feature", "type-enhancement"} & type_labels
    )
    is_security = "type-security" in type_labels
    is_bug = bool(
        {"type-bug", "type-crash"} & type_labels
    )

    if branch_status == "feature":
        signals.append(
            (
                "OK",
                f"PR targets {base}, the feature-development branch.",
            )
        )

    elif branch_status == "prerelease":
        if is_feature:
            signals.append(
                (
                    "BLOCK",
                    f"Feature/enhancement-labelled PR targets {base}, "
                    "which is in prerelease status; verify that the change "
                    "is a permitted feature fix rather than a new feature.",
                )
            )
        else:
            signals.append(
                (
                    "INFO",
                    f"PR targets {base}, which is in prerelease status; "
                    "new features are not accepted after the first beta.",
                )
            )

    elif branch_status == "bugfix":
        if is_feature:
            signals.append(
                (
                    "BLOCK",
                    f"Feature/enhancement-labelled PR targets {base}, "
                    "which is in bugfix/maintenance status; verify CPython "
                    "branch policy and whether this change should target "
                    "main instead.",
                )
            )
        else:
            signals.append(
                (
                    "OK",
                    f"PR targets {base}, which is in bugfix/maintenance status.",
                )
            )

        if is_security:
            signals.append(
                (
                    "INFO",
                    f"Security-labelled PR targets maintenance branch {base}; "
                    "verify the security handling and release context.",
                )
            )

    elif branch_status == "security":
        if is_security:
            signals.append(
                (
                    "OK",
                    f"Security-labelled PR targets {base}, which accepts "
                    "security fixes.",
                )
            )
        elif is_feature or is_bug:
            signals.append(
                (
                    "BLOCK",
                    f"PR targets {base}, which is in security-fix-only "
                    "status, but its current labels indicate a "
                    f"{'feature/enhancement' if is_feature else 'bug/crash'} "
                    "change. Verify whether this is genuinely a security "
                    "fix before proceeding.",
                )
            )
        elif documentation_only:
            signals.append(
                (
                    "INFO",
                    f"Documentation-only PR targets {base}, which is in "
                    "security-fix-only status; no runtime change is indicated, "
                    "but verify that this documentation backport is appropriate "
                    "for the branch.",
                )
            )
        else:
            signals.append(
                (
                    "WARN",
                    f"PR targets {base}, which is in security-fix-only "
                    "status; verify that the change is a genuine security "
                    "fix before approval.",
                )
            )

    elif branch_status == "end-of-life":
        signals.append(
            (
                "BLOCK",
                f"PR targets {base}, which is an end-of-life Python branch; "
                "the CPython Developer's Guide says no further changes are "
                "allowed on end-of-life branches.",
            )
        )

    elif MAINTENANCE_BRANCH_RE.fullmatch(base):
        signals.append(
            (
                "WARN",
                f"Branch {base} has no known current lifecycle status in "
                "the supplied policy data; do not infer branch eligibility "
                "from the branch number alone.",
            )
        )

    elif base:
        signals.append(
            (
                "INFO",
                f"PR targets {base}; no CPython branch lifecycle status "
                "was available.",
            )
        )

    backports: list[str] = []
    legacy_backports: list[str] = []

    for label in normalized_labels:
        match = BACKPORT_LABEL_RE.fullmatch(label)

        if match:
            backports.append(match.group(1))
            continue

        legacy_match = LEGACY_BACKPORT_LABEL_RE.fullmatch(label)

        if legacy_match:
            legacy_backports.append(legacy_match.group(1))

    if backports:
        signals.append(
            (
                "INFO",
                "Backport intent labels: "
                + ", ".join(sorted(set(backports)))
                + ".",
            )
        )

    if legacy_backports:
        signals.append(
            (
                "WARN",
                "Legacy/non-current backport label spelling detected: "
                + ", ".join(sorted(set(legacy_backports)))
                + ". Current CPython labels use "
                "\"needs backport to X.Y\".",
            )
        )

    return signals, sorted(set(backports))


def process_signals(
    pr: dict[str, Any],
    files: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    labels: list[str],
    patterns: dict[str, Any] | None,
) -> tuple[list[tuple[str, str]], list[str]]:
    signals: list[tuple[str, str]] = []

    signals.extend(_branch_policy_metadata_signals())

    normalized_labels = _normalise_labels(labels)
    labels_set = {label.casefold() for label in normalized_labels}

    title = str(pr.get("title") or "").strip()

    if re.match(r"^gh-\d{3,7}:\s+\S", title, re.IGNORECASE):
        signals.append(
            (
                "OK",
                "Title uses the expected gh-NNNNN issue-reference form.",
            )
        )
    elif re.match(r"^\[(?:3\.\d+|main)\]\s+\S", title):
        signals.append(
            (
                "INFO",
                "Title uses a branch/backport-style prefix; verify that "
                "the corresponding issue relationship and branch context "
                "are correct.",
            )
        )
    else:
        signals.append(
            (
                "INFO",
                "Title does not use the common gh-NNNNN issue-reference "
                "form; style signal only.",
            )
        )

    additions = _safe_int(pr.get("additions"))
    deletions = _safe_int(pr.get("deletions"))
    total = additions + deletions

    stats = (patterns or {}).get("statistics") or {}

    p90 = stats.get("p90")
    p95 = stats.get("p95")

    try:
        p90_value = float(p90) if p90 is not None else None
    except (TypeError, ValueError):
        p90_value = None

    try:
        p95_value = float(p95) if p95 is not None else None
    except (TypeError, ValueError):
        p95_value = None

    if p95_value is not None and total > p95_value:
        signals.append(
            (
                "WARN",
                f"PR size {total} changed lines is above sampled "
                f"p95 ({p95_value:.0f}); size is a review-complexity "
                "signal, not evidence of a defect.",
            )
        )
    elif p90_value is not None and total > p90_value:
        signals.append(
            (
                "INFO",
                f"PR size {total} changed lines is above sampled "
                f"p90 ({p90_value:.0f}); size is a review-complexity "
                "signal only.",
            )
        )
    else:
        changed_files = pr.get("changed_files")

        if changed_files is None:
            signals.append(
                (
                    "INFO",
                    f"PR size is {total} changed lines; changed-file "
                    "count was not available.",
                )
            )
        else:
            signals.append(
                (
                    "OK",
                    f"PR size is {total} changed lines across "
                    f"{changed_files} files.",
                )
            )

    names, tests, news, docs = file_signals(files)

    if not names:
        signals.append(
            (
                "WARN",
                "No changed files were available to evaluate NEWS/test "
                "requirements. Treat this as missing file evidence, not "
                "as a documentation-only or test-only change.",
            )
        )
    else:
        documentation_only = _is_documentation_only(names)
        test_only = _is_test_only(names)
        news_only = _is_news_only(names)

        if SKIP_NEWS_LABEL.casefold() in labels_set:
            signals.append(
                (
                    "OK",
                    "skip news label is present.",
                )
            )
        elif news:
            signals.append(
                (
                    "OK",
                    f"NEWS entry present ({len(news)} file(s)).",
                )
            )
        elif documentation_only:
            signals.append(
                (
                    "INFO",
                    "Documentation-only change has no NEWS entry; "
                    "CPython normally does not require NEWS for documentation.",
                )
            )
        elif test_only:
            signals.append(
                (
                    "INFO",
                    "Test-only change has no NEWS entry; CPython normally "
                    "does not require NEWS for test-only changes.",
                )
            )
        elif news_only:
            signals.append(
                (
                    "OK",
                    "NEWS-only change detected.",
                )
            )
        else:
            signals.append(
                (
                    "WARN",
                    "No Misc/NEWS.d entry detected; verify whether the "
                    "change requires one under CPython's NEWS policy.",
                )
            )

        if tests:
            signals.append(
                (
                    "OK",
                    f"Test-related file(s) changed ({len(tests)}).",
                )
            )
        elif documentation_only:
            signals.append(
                (
                    "INFO",
                    "Documentation-only change has no test file; "
                    "test coverage is likely not applicable.",
                )
            )
        elif test_only:
            signals.append(
                (
                    "OK",
                    "Test-only change contains test coverage by definition.",
                )
            )
        else:
            signals.append(
                (
                    "WARN",
                    "No test file changed; verify whether regression or "
                    "behavior coverage is needed.",
                )
            )

        if docs:
            signals.append(
                (
                    "INFO",
                    f"Documentation-related file(s) changed ({len(docs)}). "
                    "Verify that user-facing documentation is appropriate "
                    "for the behavioral/API impact.",
                )
            )

    if DO_NOT_MERGE_LABEL.casefold() in labels_set:
        signals.append(
            (
                "BLOCK",
                "DO-NOT-MERGE is active.",
            )
        )

    if AWAITING_ACTION_LABEL.casefold() in labels_set:
        signals.append(
            (
                "BLOCK",
                "awaiting action indicates that action is expected "
                "before the PR can progress.",
            )
        )

    if "awaiting changes" in labels_set:
        signals.append(
            (
                "WARN",
                "Legacy project label \"awaiting changes\" is present. "
                "Current CPython uses \"awaiting action\" for this "
                "workflow state.",
            )
        )

    if "awaiting merge" in labels_set:
        signals.append(
            (
                "INFO",
                "awaiting merge is present; verify current CI, review "
                "state, and whether the PR is otherwise ready.",
            )
        )

    branch_policies: Mapping[str, Any] | None = None

    if patterns:
        candidate = patterns.get("branch_policies")

        if isinstance(candidate, Mapping):
            branch_policies = candidate
        else:
            candidate = patterns.get("branch_status")

            if isinstance(candidate, Mapping):
                branch_policies = candidate

    branch, backports = branch_and_backport_signals(
        pr,
        normalized_labels,
        branch_policies=branch_policies,
        files=files,
    )

    signals.extend(branch)
    signals.extend(review_signals(pr, timeline))

    return signals, backports


def _evidence_is_incomplete(evidence: Any) -> bool:
    if evidence is None:
        return False

    if isinstance(evidence, Mapping):
        missing = evidence.get("missing") or []
        errors = evidence.get("errors") or []

        if missing or errors:
            return True

        complete = evidence.get("complete")
        if complete is False:
            return True

        status = str(evidence.get("status") or "").strip().lower()
        return status in {"incomplete", "error", "failed"}

    missing = getattr(evidence, "missing", None) or []
    errors = getattr(evidence, "errors", None) or []

    if missing or errors:
        return True

    complete = getattr(evidence, "complete", None)

    if complete is False:
        return True

    status = str(getattr(evidence, "status", "") or "").strip().lower()
    return status in {"incomplete", "error", "failed"}


def disposition(
    process: list[tuple[str, str]],
    findings: list[Any],
    evidence: Any = None,
) -> str:
    if any(
        str(signal).upper() == "BLOCK"
        for signal, _ in process
    ):
        return "PROCESS_BLOCKED"

    if any(
        str(getattr(finding, "severity", "")).upper()
        in {"CRITICAL", "HIGH"}
        for finding in findings
    ):
        return "NEEDS_TECHNICAL_REVIEW"

    if _evidence_is_incomplete(evidence):
        return EVIDENCE_REVIEW_DISPOSITION

    if any(
        str(signal).upper() == "WARN"
        for signal, _ in process
    ):
        return "NEEDS_MAINTAINER_ATTENTION"

    return "READY_FOR_MAINTAINER_REVIEW"