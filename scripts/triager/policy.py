"""
CPython process-policy signals.

This module deliberately does not pretend to know the final
maintainer decision.

It identifies conditions that deserve process review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import ProcessSignal


MAINTENANCE_BRANCH_RE = re.compile(
    r"^3\.\d+$"
)

NEWS_PATH_RE = re.compile(
    r"^Misc/NEWS\.d/"
)


@dataclass(frozen=True)
class PolicyContext:
    """
    Evidence available to the policy engine.
    """

    base_branch: str

    labels: tuple[str, ...]

    changed_files: tuple[str, ...]

    has_news: bool

    has_tests: bool

    draft: bool = False


def evaluate_process(
    context: PolicyContext,
) -> list[ProcessSignal]:
    """
    Generate process signals.

    These are not automatically equivalent to a maintainer verdict.
    """

    signals: list[ProcessSignal] = []

    labels = {
        label.lower()
        for label in context.labels
    }

    # --------------------------------------------------------------
    # Draft state
    # --------------------------------------------------------------

    if context.draft:
        signals.append(
            ProcessSignal(
                level="INFO",
                message=(
                    "PR is marked draft; maintainer readiness "
                    "should not be inferred."
                ),
                rule_id="draft",
            )
        )

    # --------------------------------------------------------------
    # Explicit blockers
    # --------------------------------------------------------------

    if "do-not-merge" in labels:
        signals.append(
            ProcessSignal(
                level="BLOCK",
                message=(
                    "DO-NOT-MERGE label is present."
                ),
                rule_id="label-do-not-merge",
            )
        )

    if "awaiting changes" in labels:
        signals.append(
            ProcessSignal(
                level="BLOCK",
                message=(
                    "Awaiting changes label indicates "
                    "author action is expected."
                ),
                rule_id="label-awaiting-changes",
            )
        )

    # --------------------------------------------------------------
    # NEWS
    # --------------------------------------------------------------

    if "skip news" in labels:
        signals.append(
            ProcessSignal(
                level="OK",
                message=(
                    "NEWS requirement is explicitly waived."
                ),
                rule_id="skip-news",
            )
        )

    elif (
        _news_applicable(context)
        and not context.has_news
    ):
        signals.append(
            ProcessSignal(
                level="WARN",
                message=(
                    "No Misc/NEWS.d entry was detected; "
                    "verify whether this change requires NEWS."
                ),
                rule_id="missing-news",
            )
        )

    # --------------------------------------------------------------
    # Branch
    # --------------------------------------------------------------

    if MAINTENANCE_BRANCH_RE.fullmatch(
        context.base_branch
    ):
        signals.append(
            ProcessSignal(
                level="INFO",
                message=(
                    f"PR targets maintenance branch "
                    f"{context.base_branch}; verify "
                    "branch-specific eligibility."
                ),
                rule_id="maintenance-branch",
            )
        )

    # --------------------------------------------------------------
    # Tests
    # --------------------------------------------------------------

    if context.has_tests:
        signals.append(
            ProcessSignal(
                level="INFO",
                message=(
                    "Test files are part of the change set."
                ),
                rule_id="tests-present",
            )
        )

    elif _test_likely(
        context.changed_files
    ):
        signals.append(
            ProcessSignal(
                level="WARN",
                message=(
                    "Changed code suggests a test may be "
                    "appropriate, but no test file was detected."
                ),
                rule_id="possible-test-gap",
            )
        )

    return signals


def _news_applicable(
    context: PolicyContext,
) -> bool:
    """
    Conservative first-pass NEWS applicability heuristic.

    This will later become a repository-aware policy engine.
    """

    labels = {
        label.lower()
        for label in context.labels
    }

    if "skip news" in labels:
        return False

    files = context.changed_files

    if not files:
        return False

    # Documentation/release-only changes do not automatically
    # imply a NEWS entry.
    if all(
        filename.startswith(
            (
                "Doc/",
                "Misc/NEWS.d/",
                "Tools/clinic/",
            )
        )
        for filename in files
    ):
        return False

    # Pure test/support changes are less likely to need NEWS.
    if all(
        filename.startswith(
            (
                "Lib/test/",
                "Modules/_testcapi/",
            )
        )
        for filename in files
    ):
        return False

    return True


def _test_likely(
    files: tuple[str, ...],
) -> bool:
    """
    Identify source areas where tests are commonly relevant.
    """

    source_prefixes = (
        "Python/",
        "Objects/",
        "Modules/",
        "Lib/",
        "Parser/",
        "Grammar/",
    )

    return any(
        filename.startswith(
            source_prefixes
        )
        for filename in files
    )