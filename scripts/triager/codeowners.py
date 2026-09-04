"""
CODEOWNERS parsing and ownership resolution.

Ownership from the PR base revision is evidence.
Hard-coded expert knowledge is not authoritative ownership.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from .models import EvidenceRef, OwnershipMatch


@dataclass(frozen=True)
class CodeOwnerRule:
    pattern: str
    owners: tuple[str, ...]
    line: int


def parse_codeowners(
    text: str | None,
) -> list[CodeOwnerRule]:
    """
    Parse a CODEOWNERS file.

    Blank lines and comments are ignored.
    """

    if not text:
        return []

    rules: list[CodeOwnerRule] = []

    for line_number, raw in enumerate(
        text.splitlines(),
        1,
    ):
        line = raw.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        pattern = parts[0]
        owners = tuple(parts[1:])

        rules.append(
            CodeOwnerRule(
                pattern=pattern,
                owners=owners,
                line=line_number,
            )
        )

    return rules


def _normalize(
    value: str,
) -> str:
    return value.lstrip("/")


def _matches(
    pattern: str,
    filename: str,
) -> bool:
    """
    Practical CODEOWNERS-style matcher.

    This deliberately remains conservative. A pattern match is
    reported as ownership evidence, not as a claim that the owner
    will necessarily approve the PR.
    """

    pattern = _normalize(pattern)
    filename = _normalize(filename)

    if pattern.endswith("/"):
        pattern = pattern + "**"

    if "/" not in pattern:
        if fnmatch.fnmatchcase(
            filename,
            pattern,
        ):
            return True

        return any(
            fnmatch.fnmatchcase(
                part,
                pattern,
            )
            for part in filename.split("/")
        )

    return fnmatch.fnmatchcase(
        filename,
        pattern,
    )


def resolve_codeowners(
    rules: list[CodeOwnerRule],
    filenames: list[str],
) -> list[OwnershipMatch]:
    """
    Resolve owners for changed files.

    The last matching CODEOWNERS rule wins for each file.
    """

    matches: list[OwnershipMatch] = []

    for filename in filenames:
        matched_rule: CodeOwnerRule | None = None

        for rule in rules:
            if _matches(
                rule.pattern,
                filename,
            ):
                matched_rule = rule

        if matched_rule is None:
            continue

        for owner in matched_rule.owners:
            matches.append(
                OwnershipMatch(
                    owner=owner,
                    file=filename,
                    pattern=matched_rule.pattern,
                    line=matched_rule.line,
                )
            )

    return matches


def evidence_for_match(
    match: OwnershipMatch,
) -> EvidenceRef:
    return EvidenceRef(
        kind="codeowners",
        description=(
            f"{match.file} matched CODEOWNERS "
            f"pattern {match.pattern}"
        ),
        source="CODEOWNERS",
        file=match.file,
        line=match.line,
        observed=match.owner,
    )