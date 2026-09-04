"""
Diff and semantic-diff helpers.

The old analyzer frequently reasoned about added lines directly.

That is useful for lightweight heuristics, but Python syntax and
semantics cannot reliably be understood from added lines alone.

This module therefore provides:
- added-line extraction
- changed-line mapping
- patch reconstruction
- Python AST parsing
- function signature comparison
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ChangedLine:
    line_no: int
    text: str
    kind: str


def added_lines(
    patch: str | None,
) -> list[ChangedLine]:
    """
    Extract added lines and their new-file line numbers.
    """

    if not patch:
        return []

    result: list[ChangedLine] = []

    new_line: int | None = None

    for raw in patch.splitlines():
        if raw.startswith("@@"):
            match = re.search(
                r"\+(\d+)(?:,(\d+))?",
                raw,
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
    return {
        item.line_no
        for item in added_lines(patch)
    }


def reconstruct_new_text(
    old_text: str,
    patch: str | None,
) -> str | None:
    """
    Reconstruct the new file from an old file and a unified diff.

    Returns None if the patch cannot be safely reconstructed.

    This is intentionally conservative. We prefer "unknown" over
    manufacturing a potentially incorrect file.
    """

    if patch is None:
        return None

    old_lines = old_text.splitlines(
        keepends=True
    )

    output: list[str] = []

    old_index = 0

    patch_lines = patch.splitlines()

    index = 0

    while index < len(patch_lines):
        header = patch_lines[index]

        if not header.startswith("@@"):
            index += 1
            continue

        match = re.search(
            r"-(\d+)(?:,(\d+))? "
            r"\+(\d+)(?:,(\d+))?",
            header,
        )

        if not match:
            return None

        old_start = int(
            match.group(1)
        )

        old_position = old_start - 1

        output.extend(
            old_lines[
                old_index:old_position
            ]
        )

        old_index = old_position

        index += 1

        while (
            index < len(patch_lines)
            and not patch_lines[index].startswith("@@")
        ):
            line = patch_lines[index]

            if line.startswith(
                "\\ No newline"
            ):
                index += 1
                continue

            if line.startswith(" "):
                expected = line[1:]

                if old_index >= len(old_lines):
                    return None

                actual = old_lines[
                    old_index
                ].rstrip("\n")

                if actual != expected:
                    return None

                output.append(
                    old_lines[old_index]
                )

                old_index += 1

            elif line.startswith("-"):
                if old_index >= len(old_lines):
                    return None

                old_index += 1

            elif line.startswith("+"):
                output.append(
                    line[1:] + "\n"
                )

            index += 1

    output.extend(
        old_lines[old_index:]
    )

    return "".join(output)


def parse_python(
    text: str,
) -> ast.AST | None:
    """
    Parse complete Python source.

    Returns None rather than raising on syntax errors.
    """

    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def function_signatures(
    text: str,
) -> dict[str, tuple]:
    """
    Extract function signature structure.

    This is intentionally structural rather than textual.
    """

    tree = parse_python(text)

    if tree is None:
        return {}

    result: dict[str, tuple] = {}

    for node in ast.walk(tree):
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
                list(args.posonlyargs)
                + list(args.args)
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

    old = function_signatures(old_text)
    new = function_signatures(new_text)

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
    """

    tree = parse_python(text)

    if tree is None:
        return []

    wanted = set(line_numbers)

    return [
        node
        for node in ast.walk(tree)
        if getattr(
            node,
            "lineno",
            None,
        ) in wanted
    ]