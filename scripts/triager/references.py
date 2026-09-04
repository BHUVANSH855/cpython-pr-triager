"""
Reference discovery for CPython pull-request triage.

This module performs pure reference extraction.

It does not make network requests. The resulting identifiers can be
passed to the GitHub evidence layer for retrieval.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


ISSUE_REF_RE = re.compile(
    r"\b(?:bpo|issue)[-_ ]?#?(\d+)\b",
    re.IGNORECASE,
)

GITHUB_ISSUE_RE = re.compile(
    r"https?://github\.com/[^/\s]+/[^/\s]+/"
    r"(?:issues|pull)/(\d+)\b",
    re.IGNORECASE,
)

PEP_RE = re.compile(
    r"\bPEP[- ]?(\d+)\b",
    re.IGNORECASE,
)

DISCUSS_RE = re.compile(
    r"https?://github\.com/[^/\s]+/[^/\s]+/"
    r"discussions/(\d+)\b",
    re.IGNORECASE,
)


def extract_references(
    text: str | None,
) -> tuple[list[int], list[int], list[int]]:
    """
    Extract issue, PEP, and GitHub Discussion references.

    Results are deduplicated and sorted.

    The function deliberately performs extraction only; it does not
    determine whether a reference is actually related to a PR.
    """

    text = text or ""

    issues = {
        int(number)
        for number in ISSUE_REF_RE.findall(text)
    }

    issues.update(
        int(number)
        for number in GITHUB_ISSUE_RE.findall(text)
    )

    peps = {
        int(number)
        for number in PEP_RE.findall(text)
    }

    discussions = {
        int(number)
        for number in DISCUSS_RE.findall(text)
    }

    return (
        sorted(issues),
        sorted(peps),
        sorted(discussions),
    )


def issue_refs_from_timeline(
    timeline: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Extract issue references represented by timeline
    ``cross-referenced`` events.

    The raw issue metadata is retained so callers can use the title
    without another parsing step.
    """

    refs: list[dict[str, Any]] = []

    for event in timeline or []:
        if event.get("event") != "cross-referenced":
            continue

        source = event.get("source") or {}
        issue = source.get("issue") or {}

        number = issue.get("number")

        if not isinstance(number, int):
            continue

        refs.append(
            {
                "number": number,
                "title": issue.get(
                    "title",
                    "",
                ),
            }
        )

    return refs


def collect_issue_numbers(
    *,
    pr_number: int,
    pr_body: str | None = None,
    timeline: Iterable[dict[str, Any]] | None = None,
    limit: int = 20,
) -> tuple[list[int], list[int], list[int]]:
    """
    Combine textual and timeline references into issue identifiers.

    The current PR number is removed because a self-reference is not a
    linked issue.

    ``limit`` bounds the number of issue identifiers returned, matching
    the old analyzer's behavior.
    """

    if limit < 0:
        raise ValueError(
            "limit must be non-negative"
        )

    timeline_list = list(
        timeline or []
    )

    body_text = pr_body or ""

    for event in timeline_list:
        if not event.get("bot"):
            body_text += "\n"
            body_text += event.get(
                "body",
                "",
            )

    issues, peps, discussions = (
        extract_references(body_text)
    )

    cross_refs = issue_refs_from_timeline(
        [
            event.get(
                "event",
                {},
            )
            for event in timeline_list
        ]
    )

    issues = sorted(
        set(issues)
        | {
            ref["number"]
            for ref in cross_refs
        }
    )

    issues = [
        number
        for number in issues
        if number != pr_number
    ]

    return (
        issues[:limit],
        peps,
        discussions,
    )