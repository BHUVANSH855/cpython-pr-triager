from __future__ import annotations

import pytest

from scripts.triager.codeowners import (
    CodeOwnerRule,
    _matches,
    evidence_for_match,
    parse_codeowners,
    resolve_codeowners,
)


def test_parse_codeowners_ignores_blank_lines_and_comments():
    text = """
# top-level comment

*.py @python
# another comment
"""

    rules = parse_codeowners(text)

    assert len(rules) == 1
    assert rules[0].pattern == "*.py"
    assert rules[0].owners == ("@python",)
    assert rules[0].line == 4


def test_parse_codeowners_preserves_multiple_owners():
    rules = parse_codeowners(
        "*.py @python @core-team\n"
    )

    assert rules == [
        CodeOwnerRule(
            pattern="*.py",
            owners=("@python", "@core-team"),
            line=1,
        )
    ]


@pytest.mark.parametrize(
    "text",
    [
        "",
        None,
        "\n",
        "# comment\n",
        "*.py",
        "   ",
    ],
)
def test_parse_codeowners_ignores_non_rules(text):
    assert parse_codeowners(text) == []


def test_parse_codeowners_strips_inline_comment():
    rules = parse_codeowners(
        "*.py @python    # Python files\n"
    )

    assert len(rules) == 1
    assert rules[0].pattern == "*.py"
    assert rules[0].owners == ("@python",)


def test_parse_codeowners_tracks_original_line_number():
    rules = parse_codeowners(
        "# comment\n\n"
        "*.c @c-team\n"
    )

    assert rules[0].line == 3


def test_matches_extension_pattern_at_any_directory_level():
    assert _matches("*.py", "foo.py")
    assert _matches("*.py", "pkg/foo.py")
    assert _matches("*.py", "pkg/sub/foo.py")
    assert not _matches("*.py", "foo.c")


def test_matches_root_anchored_pattern_only_at_repository_root():
    assert _matches("/src/*.py", "src/main.py")
    assert not _matches("/src/*.py", "vendor/src/main.py")


def test_matches_non_anchored_directory_pattern():
    assert _matches("src/*.py", "src/main.py")
    assert _matches("src/*.py", "vendor/src/main.py")
    assert not _matches("src/*.py", "vendor/other/main.py")


def test_matches_question_mark_as_one_path_character():
    assert _matches("file?.py", "file1.py")
    assert _matches("file?.py", "filea.py")
    assert not _matches("file?.py", "file10.py")


def test_matches_double_star():
    assert _matches("src/**/*.py", "src/main.py")
    assert _matches("src/**/*.py", "src/pkg/main.py")
    assert _matches("src/**/*.py", "src/pkg/sub/main.py")


def test_matches_directory_pattern():
    assert _matches("docs/", "docs/index.html")
    assert _matches("docs/", "docs/api/index.html")
    assert not _matches("docs/", "documentation/index.html")


@pytest.mark.parametrize(
    "pattern",
    [
        "[ab].py",
        "!secret.py",
        "src/[ab]/*.py",
    ],
)
def test_unsupported_patterns_do_not_match(pattern):
    assert not _matches(pattern, "src/a.py")


def test_resolve_codeowners_uses_last_matching_rule():
    rules = parse_codeowners(
        "*.py @python\n"
        "src/*.py @src-team\n"
    )

    matches = resolve_codeowners(
        rules,
        ["src/main.py", "other.py"],
    )

    assert matches == [
        matches[0],
        matches[1],
    ]
    assert matches[0].owner == "@src-team"
    assert matches[0].file == "src/main.py"
    assert matches[0].pattern == "src/*.py"
    assert matches[1].owner == "@python"
    assert matches[1].file == "other.py"


def test_resolve_codeowners_returns_all_owners_from_last_rule():
    rules = parse_codeowners(
        "*.py @old-team\n"
        "*.py @python @core-team\n"
    )

    matches = resolve_codeowners(
        rules,
        ["main.py"],
    )

    assert [(match.owner, match.pattern) for match in matches] == [
        ("@python", "*.py"),
        ("@core-team", "*.py"),
    ]


def test_resolve_codeowners_skips_unmatched_files():
    rules = parse_codeowners(
        "*.py @python\n"
    )

    matches = resolve_codeowners(
        rules,
        ["README.md"],
    )

    assert matches == []


def test_evidence_for_match():
    rules = parse_codeowners(
        "*.py @python\n"
    )

    match = resolve_codeowners(
        rules,
        ["main.py"],
    )[0]

    evidence = evidence_for_match(match)

    assert evidence.kind == "codeowners"
    assert evidence.description == (
        "main.py matched CODEOWNERS pattern *.py"
    )
    assert evidence.source == "CODEOWNERS"
    assert evidence.file == "main.py"
    assert evidence.line == 1
    assert evidence.observed == "@python"