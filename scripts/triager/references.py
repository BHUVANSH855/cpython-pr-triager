"""
Reference discovery for CPython pull-request triage.

This module performs pure reference extraction.

It does not make network requests. The resulting identifiers can be
passed to the GitHub evidence layer for retrieval.

Fixes applied:
- DISCUSS_RE now correctly targets discuss.python.org (was matching
  GitHub Discussions, which CPython does not use for community threads).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# Legacy bpo-/issue- syntax still appears in older PRs and issue bodies.
ISSUE_REF_RE = re.compile(
    r"\b(?:bpo|issue)[-_ ]?#?(\d+)\b",
    re.IGNORECASE,
)

# GitHub issue/PR URLs.
GITHUB_ISSUE_RE = re.compile(
    r"https?://github\.com/[^/\s]+/[^/\s]+/"
    r"(?:issues|pull)/(\d+)\b",
    re.IGNORECASE,
)

# gh-NNNNN shorthand used in CPython PR titles and bodies.
GH_REF_RE = re.compile(
    r"\bgh-(\d{3,7})\b",
    re.IGNORECASE,
)

# Inline issue references: fixes #NNNNN, closes #NNNNN, etc.
CLOSES_REF_RE = re.compile(
    r"(?:fix(?:es|ed)?|close(?:s|d)?|resolve(?:s|d)?)\s+#(\d{3,7})\b",
    re.IGNORECASE,
)

PEP_RE = re.compile(
    r"\bPEP[- ]?(\d+)\b",
    re.IGNORECASE,
)

# FIX (point 4): was matching github.com/*/discussions which is not where
# CPython community discussion happens.  CPython uses discuss.python.org.
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
    Discussion URLs are returned as strings (slugs vary; numeric IDs
    are not reliable).

    The function deliberately performs extraction only; it does not
    determine whether a reference is actually related to a PR.
    """
    text = text or ""

    issues: set[int] = set()

    for m in ISSUE_REF_RE.finditer(text):
        issues.add(int(m.group(1)))

    for m in GITHUB_ISSUE_RE.finditer(text):
        issues.add(int(m.group(1)))

    for m in GH_REF_RE.finditer(text):
        issues.add(int(m.group(1)))

    for m in CLOSES_REF_RE.finditer(text):
        issues.add(int(m.group(1)))

    peps: set[int] = set()
    for m in PEP_RE.finditer(text):
        peps.add(int(m.group(1)))

    discussions: set[str] = set()
    for m in DISCUSS_RE.finditer(text):
        discussions.add(m.group(0))

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
    Combine textual and timeline references into issue identifiers.

    The current PR number is removed because a self-reference is not a
    linked issue.

    ``limit`` bounds the number of issue identifiers returned.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")

    timeline_list = list(timeline or [])

    body_text = pr_body or ""

    # Only include human (non-bot) timeline event bodies.
    for event in timeline_list:
        if not event.get("bot"):
            body_text += "\n"
            body_text += event.get("body", "")

    issues, peps, discussions = extract_references(body_text)

    # Also pull cross-referenced events from the raw event objects.
    # Note: timeline events here are the normalized triager events
    # (with "bot", "kind", "body" keys), not raw GitHub API events.
    # Cross-references are surfaced separately via issue_refs_from_timeline
    # on the raw GitHub timeline.

    issues = sorted(
        set(issues) - {pr_number}
    )

    return (
        issues[:limit],
        peps,
        discussions,
    )