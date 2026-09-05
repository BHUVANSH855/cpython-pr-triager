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
from collections.abc import Iterable
from statistics import median, quantiles


def summarize_sizes(
    prs: Iterable[dict],
) -> dict:
    """
    Build a reproducible size baseline.
    """

    rows: list[dict] = []

    for pr in prs:
        try:
            rows.append(
                {
                    "number": pr.get(
                        "number"
                    ),
                    "additions": int(
                        pr.get(
                            "additions",
                            0,
                        )
                        or 0
                    ),
                    "deletions": int(
                        pr.get(
                            "deletions",
                            0,
                        )
                        or 0
                    ),
                    "changed_files": int(
                        pr.get(
                            "changed_files",
                            0,
                        )
                        or 0
                    ),
                    "base": (
                        pr.get("base")
                        or {}
                    ).get("ref"),
                }
            )

        except (
            TypeError,
            ValueError,
        ):
            continue

    total_changes = [
        row["additions"]
        + row["deletions"]
        for row in rows
    ]

    changed_files = [
        row["changed_files"]
        for row in rows
    ]

    result = {
        "sample_size": len(rows),
        "rows": rows,
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
    """

    if not values:
        return 0

    if len(values) == 1:
        return float(values[0])

    values = sorted(values)

    data = quantiles(
        values,
        n=100,
        method="inclusive",
    )

    index = max(
        0,
        min(
            99,
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
    """

    total = additions + deletions

    if not baseline:
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

    p95 = size.get(
        "p95",
        0,
    )

    file_p95 = files.get(
        "p95",
        0,
    )

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

    return {
        "status": (
            "unusual"
            if flags
            else "typical"
        ),
        "flags": flags,
        "sample_size": baseline.get(
            "sample_size",
            0,
        ),
    }


def stratify(
    prs: Iterable[dict],
) -> dict:
    """
    Produce simple branch/label-stratified baselines.

    This is an initial implementation.

    Later we will stratify by:
        branch
        component
        PR type
        time period
    """

    groups: defaultdict[
        tuple,
        list[dict],
    ] = defaultdict(list)

    for pr in prs:
        base = (
            pr.get("base")
            or {}
        ).get(
            "ref"
        ) or "unknown"

        labels = tuple(
            sorted(
                (
                    label.get("name")
                    or ""
                ).lower()
                for label in pr.get(
                    "labels",
                    [],
                )
            )
        )

        key = (
            base,
            labels[:3],
        )

        groups[key].append(pr)

    return {
        (
            f"{base}|"
            f"{','.join(labels)}"
        ): summarize_sizes(
            rows
        )
        for (
            base,
            labels,
        ), rows in groups.items()
    }