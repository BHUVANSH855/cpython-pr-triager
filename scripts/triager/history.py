"""
Historical analysis helpers.

Historical statistics are context, not proof.

The goal is to answer questions such as:

    "Is this PR unusually large compared with the supplied sample?"

rather than:

    "Large means bad."
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from statistics import median, quantiles
from typing import Any


def _as_int(value: Any, default: int = 0) -> int:
    """Convert a value to a non-negative integer when possible."""

    try:
        result = int(value or 0)
    except (TypeError, ValueError):
        return default

    return max(0, result)


def _base_ref(pr: Mapping[str, Any]) -> str | None:
    """Return a normalized base branch name."""

    base = pr.get("base")

    if not isinstance(base, Mapping):
        return None

    ref = base.get("ref")

    if ref is None:
        return None

    ref = str(ref).strip()

    return ref or None


def _label_names(pr: Mapping[str, Any]) -> tuple[str, ...]:
    """Return normalized, deterministic PR label names."""

    labels = pr.get("labels", [])

    if not isinstance(labels, Iterable) or isinstance(
        labels,
        (str, bytes, Mapping),
    ):
        return ()

    names: set[str] = set()

    for label in labels:
        if isinstance(label, Mapping):
            name = label.get("name")
        else:
            name = label

        if name is None:
            continue

        normalized = str(name).strip().lower()

        if normalized:
            names.add(normalized)

    return tuple(sorted(names))


def _normalize_pr(pr: Any) -> dict[str, Any] | None:
    """
    Normalize the fields required by historical analysis.

    Invalid records are ignored rather than allowed to poison
    the complete historical sample.
    """

    if not isinstance(pr, Mapping):
        return None

    try:
        return {
            "number": pr.get("number"),
            "additions": _as_int(
                pr.get("additions"),
            ),
            "deletions": _as_int(
                pr.get("deletions"),
            ),
            "changed_files": _as_int(
                pr.get("changed_files"),
            ),
            "base": _base_ref(pr),
            "labels": _label_names(pr),
        }
    except Exception:
        return None


def _normalized_rows(
    prs: Iterable[dict],
) -> list[dict[str, Any]]:
    """Return valid, normalized PR records."""

    rows: list[dict[str, Any]] = []

    for pr in prs:
        row = _normalize_pr(pr)

        if row is not None:
            rows.append(row)

    return rows


def summarize_sizes(
    prs: Iterable[dict],
) -> dict:
    """
    Build a reproducible size baseline.

    Invalid historical records are skipped so that one malformed
    API response does not invalidate the complete sample.
    """

    rows = _normalized_rows(prs)

    total_changes = [
        row["additions"] + row["deletions"]
        for row in rows
    ]

    changed_files = [
        row["changed_files"]
        for row in rows
    ]

    result = {
        "sample_size": len(rows),
        "rows": [
            {
                "number": row["number"],
                "additions": row["additions"],
                "deletions": row["deletions"],
                "changed_files": row["changed_files"],
                "base": row["base"],
            }
            for row in rows
        ],
        "size": {
            "median": (
                median(total_changes)
                if total_changes
                else 0
            ),
            "p95": _percentile(
                total_changes,
                0.95,
            ),
            "max": (
                max(total_changes)
                if total_changes
                else 0
            ),
        },
        "changed_files": {
            "median": (
                median(changed_files)
                if changed_files
                else 0
            ),
            "p95": _percentile(
                changed_files,
                0.95,
            ),
            "max": (
                max(changed_files)
                if changed_files
                else 0
            ),
        },
    }

    result["branches"] = dict(
        Counter(
            row["base"]
            for row in rows
            if row["base"]
        )
    )

    return result


def _percentile(
    values: list[int],
    percentile: float,
) -> float:
    """
    Calculate an interpolated percentile.

    The percentile is expected to be between 0 and 1.
    """

    if not values:
        return 0

    if len(values) == 1:
        return float(values[0])

    percentile = max(
        0.0,
        min(
            1.0,
            float(percentile),
        ),
    )

    values = sorted(values)

    data = quantiles(
        values,
        n=100,
        method="inclusive",
    )

    index = max(
        0,
        min(
            98,
            int(percentile * 100) - 1,
        ),
    )

    return float(
        data[index]
    )


def contextual_size_signal(
    additions: int,
    deletions: int,
    changed_files: int,
    baseline: dict | None,
) -> dict:
    """
    Compare a PR with a supplied historical baseline.

    Historical size is only a contextual signal. It does not
    establish that a PR is incorrect or unsafe.
    """

    total = _as_int(additions) + _as_int(deletions)
    changed_files = _as_int(changed_files)

    if not isinstance(baseline, Mapping):
        return {
            "status": "unknown",
            "reason": (
                "No historical baseline supplied."
            ),
        }

    size = baseline.get(
        "size",
        {},
    )

    files = baseline.get(
        "changed_files",
        {},
    )

    if not isinstance(size, Mapping):
        size = {}

    if not isinstance(files, Mapping):
        files = {}

    p95 = size.get(
        "p95",
        0,
    )

    file_p95 = files.get(
        "p95",
        0,
    )

    try:
        p95 = float(p95 or 0)
    except (TypeError, ValueError):
        p95 = 0

    try:
        file_p95 = float(file_p95 or 0)
    except (TypeError, ValueError):
        file_p95 = 0

    flags: list[str] = []

    if p95 and total > p95:
        flags.append(
            "total_change_size_above_p95"
        )

    if (
        file_p95
        and changed_files > file_p95
    ):
        flags.append(
            "changed_files_above_p95"
        )

    sample_size = baseline.get(
        "sample_size",
        0,
    )

    try:
        sample_size = _as_int(sample_size)
    except (TypeError, ValueError):
        sample_size = 0

    return {
        "status": (
            "unusual"
            if flags
            else "typical"
        ),
        "flags": flags,
        "sample_size": sample_size,
    }


def _stratification_key(
    pr: Mapping[str, Any],
) -> tuple[str, tuple[str, ...]]:
    """Build a stable branch/label stratification key."""

    base = _base_ref(pr) or "unknown"
    labels = _label_names(pr)

    # Keep the historical grouping bounded. A PR can have many
    # labels, but the first three sorted labels provide a stable
    # and reproducible coarse grouping.
    return base, labels[:3]


def stratify(
    prs: Iterable[dict],
) -> dict:
    """
    Produce branch/label-stratified baselines.

    Groups are deterministic and use at most the first three
    normalized labels.

    Historical statistics remain contextual and should not be
    interpreted as proof of correctness or risk.
    """

    groups: defaultdict[
        tuple[str, tuple[str, ...]],
        list[dict],
    ] = defaultdict(list)

    for pr in prs:
        if not isinstance(pr, Mapping):
            continue

        base, labels = _stratification_key(pr)

        groups[
            (
                base,
                labels,
            )
        ].append(pr)

    result: dict[str, dict] = {}

    for (
        base,
        labels,
    ), rows in sorted(
        groups.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
        ),
    ):
        label_text = ",".join(labels)

        result[
            f"{base}|{label_text}"
        ] = summarize_sizes(rows)

    return result