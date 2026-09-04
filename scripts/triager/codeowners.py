"""
CODEOWNERS parsing and ownership resolution.

Ownership from the PR base revision is evidence.
Hard-coded expert knowledge is not authoritative ownership.
"""

from __future__ import annotations

import re
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
    Inline comments are stripped after whitespace followed by ``#``.
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

        line = re.split(
            r"\s+#",
            line,
            maxsplit=1,
        )[0].strip()

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


def _regex(
    pattern: str,
) -> re.Pattern[str] | None:
    """
    Build the conservative CODEOWNERS matcher used by the legacy triager.

    Unsupported character classes and negation are deliberately rejected
    rather than approximated.
    """

    if any(
        character in pattern
        for character in "[]!"
    ):
        return None

    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")

    directory = pattern.endswith("/")

    if directory:
        pattern = pattern.rstrip("/") + "/**"

    if "/" not in pattern:
        prefix = r"^(?:.*/)?"
    elif anchored:
        prefix = r"^"
    else:
        prefix = r"^(?:.*/)?"

    output: list[str] = []
    index = 0

    while index < len(pattern):
        character = pattern[index]

        if character == "*":
            if (
                index + 1 < len(pattern)
                and pattern[index + 1] == "*"
            ):
                index += 1

                if (
                    index + 1 < len(pattern)
                    and pattern[index + 1] == "/"
                ):
                    index += 1
                    output.append(
                        r"(?:.*/)?"
                    )
                else:
                    output.append(
                        r".*"
                    )
            else:
                output.append(
                    r"[^/]*"
                )

        elif character == "?":
            output.append(
                r"[^/]"
            )

        else:
            output.append(
                re.escape(character)
            )

        index += 1

    return re.compile(
        prefix
        + "".join(output)
        + r"$"
    )


def _matches(
    pattern: str,
    filename: str,
) -> bool:
    """
    Match one filename against one CODEOWNERS pattern.

    This intentionally mirrors the existing triager behavior.
    """

    normalized_pattern = _normalize(
        pattern
    )

    normalized_filename = _normalize(
        filename
    )

    matcher = _regex(
        normalized_pattern
    )

    return bool(
        matcher
        and matcher.match(
            normalized_filename
        )
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