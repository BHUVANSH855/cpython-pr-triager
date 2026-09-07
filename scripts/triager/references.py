"""
Reference discovery for CPython pull-request triage.

This module performs pure reference extraction.

It does not make network requests. The resulting identifiers can be
passed to the GitHub evidence layer for retrieval.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

ISSUE_REF_RE = re.compile(
    r"\b(?:bpo|issue)[-_ ]?#?(\d+)\b",
    re.IGNORECASE,
)

GITHUB_ISSUE_RE = re.compile(
    r"https?://github\.com/[^/\s]+/[^/\s]+/"
    r"(?:issues|pull)/(\d+)\b",
    re.IGNORECASE,
)

GH_REF_RE = re.compile(
    r"\bgh-(\d{3,7})\b",
    re.IGNORECASE,
)

CLOSES_REF_RE = re.compile(
    r"(?:fix(?:es|ed)?|close(?:s|d)?|resolve(?:s|d)?)\s+#(\d{3,7})\b",
    re.IGNORECASE,
)

PEP_RE = re.compile(
    r"\bPEP[- ]?(\d+)\b",
    re.IGNORECASE,
)

DISCUSS_RE = re.compile(
    r"https?://discuss\.python\.org/t/[^\s)>\]]+",
    re.IGNORECASE,
)


def extract_references(
    text: str | None,
) -> tuple[list[int], list[int], list[str]]:
    """
    Extract issue numbers, PEP numbers, and discuss.python.org URLs.

    Results are deduplicated and sorted where applicable.
    Discussion URLs are returned as strings.
    """
    text = text or ""

    issues: set[int] = set()

    for pattern in (
        ISSUE_REF_RE,
        GITHUB_ISSUE_RE,
        GH_REF_RE,
        CLOSES_REF_RE,
    ):
        for match in pattern.finditer(text):
            issues.add(int(match.group(1)))

    peps = {
        int(match.group(1))
        for match in PEP_RE.finditer(text)
    }

    discussions = {
        match.group(0)
        for match in DISCUSS_RE.finditer(text)
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
        if not isinstance(event, dict):
            continue

        if event.get("event") != "cross-referenced":
            continue

        source = event.get("source")
        if not isinstance(source, dict):
            continue

        issue = source.get("issue")
        if not isinstance(issue, dict):
            continue

        number = issue.get("number")

        if not isinstance(number, int) or number <= 0:
            continue

        refs.append(
            {
                "number": number,
                "title": issue.get("title", ""),
            }
        )

    return refs


def collect_issue_numbers(
    *,
    pr_number: int,
    pr_body: str | None = None,
    timeline: Iterable[dict[str, Any]] | None = None,
    limit: int = 20,
) -> tuple[list[int], list[int], list[str]]:
    """
    Combine textual and structured timeline references into identifiers.

    The current PR number is removed because a self-reference is not a
    linked issue.

    ``limit`` bounds the number of issue identifiers returned.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")

    timeline_list = list(timeline or [])

    body_parts = [pr_body or ""]

    for event in timeline_list:
        if not isinstance(event, dict):
            continue

        if event.get("bot"):
            continue

        body = event.get("body", "")
        if isinstance(body, str) and body:
            body_parts.append(body)

    issues, peps, discussions = extract_references(
        "\n".join(body_parts)
    )

    structured_issues = {
        ref["number"]
        for ref in issue_refs_from_timeline(timeline_list)
        if isinstance(ref.get("number"), int)
    }

    issues = sorted(
        {
            number
            for number in (*issues, *structured_issues)
            if number > 0 and number != pr_number
        }
    )

    return (
        issues[:limit],
        peps,
        discussions,
    )