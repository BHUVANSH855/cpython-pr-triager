"""
Diff and semantic-diff helpers.

The lightweight diff helpers operate directly on unified-diff hunks for
existing heuristics.  Complete-file semantic analysis should instead use
``reconstruct_new_text()`` followed by ``parse_python()``.

This module therefore provides:
- added-line extraction
- changed-line mapping
- conservative patch reconstruction
- Python AST parsing
- function signature comparison
- changed AST-node discovery
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class ChangedLine:
    """A changed line in the new-file coordinate space."""

    line_no: int
    text: str
    kind: str


_HUNK_RE = re.compile(
    r"\+(\d+)(?:,(\d+))?"
)

_FULL_HUNK_RE = re.compile(
    r"^@@\s+"
    r"-(\d+)(?:,(\d+))?\s+"
    r"\+(\d+)(?:,(\d+))?\s+@@"
)


def added_lines(
    patch: str | None,
) -> list[ChangedLine]:
    """
    Extract added lines and their new-file line numbers.

    This intentionally retains the permissive behavior used by the
    existing lightweight analyzers.  It should not be coupled to the
    stricter patch-reconstruction parser.
    """
    if not patch:
        return []

    result: list[ChangedLine] = []

    new_line: int | None = None

    for raw in patch.splitlines():
        if raw.startswith("@@"):
            match = _HUNK_RE.search(
                raw
            )

            new_line = (
                int(match.group(1))
                if match
                else None
            )

            continue

        if raw.startswith("+++") or raw.startswith("---"):
            continue

        if new_line is None:
            continue

        if raw.startswith("+"):
            result.append(
                ChangedLine(
                    line_no=new_line,
                    text=raw[1:],
                    kind="added",
                )
            )

            new_line += 1

        elif raw.startswith("-"):
            # Deleted lines do not consume new-file line numbers.
            continue

        else:
            new_line += 1

    return result


def changed_line_numbers(
    patch: str | None,
) -> set[int]:
    """Return added-line numbers in the new-file coordinate space."""
    return {
        item.line_no
        for item in added_lines(
            patch
        )
    }


def _parse_reconstruction_hunks(
    patch: str,
) -> list[
    tuple[
        int,
        int,
        int,
        int,
        list[str],
    ]
] | None:
    """
    Parse unified-diff hunks for reconstruction.

    This parser is deliberately separate from ``added_lines()`` so
    stricter validation cannot change the behavior of existing
    lightweight analyzers.
    """
    if not patch:
        return []

    lines = patch.splitlines()
    hunks: list[
        tuple[
            int,
            int,
            int,
            int,
            list[str],
        ]
    ] = []

    index = 0

    while index < len(lines):
        line = lines[index]

        match = _FULL_HUNK_RE.match(
            line
        )

        if not match:
            index += 1
            continue

        old_start = int(
            match.group(1)
        )

        old_count = (
            int(match.group(2))
            if match.group(2) is not None
            else 1
        )

        new_start = int(
            match.group(3)
        )

        new_count = (
            int(match.group(4))
            if match.group(4) is not None
            else 1
        )

        hunk_lines: list[str] = []

        index += 1

        while index < len(lines):
            current = lines[index]

            if _FULL_HUNK_RE.match(
                current
            ):
                break

            if current.startswith(
                "\\ No newline at end of file"
            ):
                hunk_lines.append(
                    current
                )
                index += 1
                continue

            if current.startswith(
                (
                    "diff ",
                    "--- ",
                    "+++ ",
                )
            ):
                break

            if not current.startswith(
                (
                    " ",
                    "+",
                    "-",
                )
            ):
                return None

            hunk_lines.append(
                current
            )
            index += 1

        old_consumed = sum(
            line.startswith(
                (
                    " ",
                    "-",
                )
            )
            for line in hunk_lines
        )

        new_consumed = sum(
            line.startswith(
                (
                    " ",
                    "+",
                )
            )
            for line in hunk_lines
        )

        if old_consumed != old_count:
            return None

        if new_consumed != new_count:
            return None

        hunks.append(
            (
                old_start,
                old_count,
                new_start,
                new_count,
                hunk_lines,
            )
        )

    return hunks


def _without_newline(
    line: str,
) -> str:
    """Return a source line without its line terminator."""
    if line.endswith(
        "\r\n"
    ):
        return line[:-2]

    if line.endswith(
        (
            "\n",
            "\r",
        )
    ):
        return line[:-1]

    return line


def _preferred_newline(
    old_lines: list[str],
) -> str:
    """
    Return the preferred newline for newly inserted lines.

    Existing source lines are copied unchanged.
    """
    for line in old_lines:
        if line.endswith(
            "\r\n"
        ):
            return "\r\n"

    return "\n"


def reconstruct_new_text(
    old_text: str,
    patch: str | None,
) -> str | None:
    """
    Reconstruct the complete new file from an old file and unified diff.

    The function is intentionally conservative:

    - ``None`` patch means reconstruction is unavailable.
    - an empty patch means the file is unchanged;
    - malformed hunks return ``None``;
    - context mismatches return ``None``;
    - deleted-line mismatches return ``None``;
    - hunk coordinates that move backwards return ``None``.

    The function does not attempt fuzzy matching.  A patch is either
    applied exactly to the supplied old text or reconstruction fails.

    This function is intentionally independent from ``added_lines()`` so
    stricter reconstruction semantics do not affect existing analyzers.
    """
    if patch is None:
        return None

    if patch == "":
        return old_text

    hunks = _parse_reconstruction_hunks(
        patch
    )

    if hunks is None:
        return None

    if not hunks:
        # A patch containing only metadata/file headers represents no
        # textual change.  Treat it as unchanged.
        return old_text

    old_lines = old_text.splitlines(
        keepends=True
    )

    newline = _preferred_newline(
        old_lines
    )

    output: list[str] = []

    old_index = 0
    previous_old_end = 0
    previous_new_end = 0

    for (
        old_start,
        old_count,
        new_start,
        new_count,
        hunk_lines,
    ) in hunks:
        old_position = old_start - 1

        if old_position < 0:
            return None

        if old_position < old_index:
            return None

        if old_position > len(old_lines):
            return None

        # Number of unchanged old lines between the previous hunk and
        # this hunk.
        old_gap = (
            old_position
            - previous_old_end
        )

        # The corresponding new-file coordinate must account for the
        # unchanged gap as well as the previous hunk's output.
        expected_new_start = (
            previous_new_end
            + old_gap
            + 1
        )

        if new_start != expected_new_start:
            return None

        # Copy unchanged lines between hunks.
        output.extend(
            old_lines[
                old_index:old_position
            ]
        )

        old_index = old_position

        for raw in hunk_lines:
            if raw.startswith(
                "\\ No newline at end of file"
            ):
                if not output:
                    return None

                previous = output[-1]

                if previous.endswith(
                    "\r\n"
                ):
                    output[-1] = previous[:-2]
                elif previous.endswith(
                    (
                        "\n",
                        "\r",
                    )
                ):
                    output[-1] = previous[:-1]

                continue

            prefix = raw[0]
            text = raw[1:]

            if prefix == " ":
                if old_index >= len(old_lines):
                    return None

                actual = _without_newline(
                    old_lines[old_index]
                )

                if actual != text:
                    return None

                output.append(
                    old_lines[old_index]
                )

                old_index += 1

            elif prefix == "-":
                if old_index >= len(old_lines):
                    return None

                actual = _without_newline(
                    old_lines[old_index]
                )

                if actual != text:
                    return None

                old_index += 1

            elif prefix == "+":
                output.append(
                    text + newline
                )

            else:
                return None

        previous_old_end = (
            old_position
            + old_count
        )

        previous_new_end = (
            new_start
            + new_count
            - 1
        )

    # Copy everything after the final hunk.
    output.extend(
        old_lines[
            old_index:
        ]
    )

    return "".join(
        output
    )


def parse_python(
    text: str,
) -> ast.AST | None:
    """
    Parse complete Python source.

    Returns None rather than raising on syntax errors.
    """
    try:
        return ast.parse(
            text
        )
    except (
        SyntaxError,
        ValueError,
        TypeError,
    ):
        return None


def function_signatures(
    text: str,
) -> dict[str, tuple]:
    """
    Extract function signature structure.

    This is intentionally structural rather than textual.
    """
    tree = parse_python(
        text
    )

    if tree is None:
        return {}

    result: dict[str, tuple] = {}

    for node in ast.walk(
        tree
    ):
        if not isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        ):
            continue

        args = node.args

        positional = [
            arg.arg
            for arg in (
                list(
                    args.posonlyargs
                )
                + list(
                    args.args
                )
            )
        ]

        keyword_only = [
            arg.arg
            for arg in args.kwonlyargs
        ]

        vararg = (
            args.vararg.arg
            if args.vararg
            else ""
        )

        kwarg = (
            args.kwarg.arg
            if args.kwarg
            else ""
        )

        result[node.name] = (
            tuple(positional),
            tuple(keyword_only),
            vararg,
            kwarg,
        )

    return result


def compare_function_signatures(
    old_text: str,
    new_text: str,
) -> list[dict[str, object]]:
    """
    Compare function structures between two complete files.
    """
    old = function_signatures(
        old_text
    )
    new = function_signatures(
        new_text
    )

    changes: list[dict[str, object]] = []

    for name in sorted(
        set(old) | set(new)
    ):
        if (
            name in old
            and name in new
            and old[name] != new[name]
        ):
            changes.append(
                {
                    "function": name,
                    "kind": "changed",
                    "old": old[name],
                    "new": new[name],
                }
            )

        elif name not in old:
            changes.append(
                {
                    "function": name,
                    "kind": "added",
                    "old": None,
                    "new": new[name],
                }
            )

        elif name not in new:
            changes.append(
                {
                    "function": name,
                    "kind": "removed",
                    "old": old[name],
                    "new": None,
                }
            )

    return changes


def changed_python_nodes(
    text: str,
    line_numbers: Iterable[int],
) -> list[ast.AST]:
    """
    Return AST nodes whose starting line is changed.

    ``text`` should be complete reconstructed source rather than an
    isolated diff hunk.
    """
    tree = parse_python(
        text
    )

    if tree is None:
        return []

    wanted = set(
        line_numbers
    )

    return [
        node
        for node in ast.walk(
            tree
        )
        if getattr(
            node,
            "lineno",
            None,
        ) in wanted
    ]
