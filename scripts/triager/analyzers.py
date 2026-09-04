"""
Deterministic technical analyzers.

Important:

These rules are REVIEW PROMPTS.

They do not establish that a defect exists.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .diff import added_lines
from .models import EvidenceRef, Finding


RULES = {
    # --------------------------------------------------------------
    # C / memory safety
    # --------------------------------------------------------------

    "c-unsafe-gets": (
        r"\bgets\s*\(",
        "CRITICAL",
        "high",
        "security",
        "gets() was introduced; inspect the added code immediately.",
    ),

    "c-unsafe-strcpy": (
        r"\bstrcpy\s*\(",
        "HIGH",
        "medium",
        "security",
        "strcpy() was introduced; inspect bounds handling and CPython conventions.",
    ),

    "c-unsafe-strcat": (
        r"\bstrcat\s*\(",
        "HIGH",
        "medium",
        "security",
        "strcat() was introduced; inspect bounds handling.",
    ),

    "c-unsafe-sprintf": (
        r"\bsprintf\s*\(",
        "MEDIUM",
        "medium",
        "security",
        "sprintf() was introduced; verify whether a bounded alternative is appropriate.",
    ),

    # --------------------------------------------------------------
    # CPython internal API
    # --------------------------------------------------------------

    "cpython-private-api": (
        r"\b_Py_[A-Za-z]\w*",
        "MEDIUM",
        "medium",
        "api",
        "A private _Py_* API is used; verify layer, ownership, and API expectations.",
    ),

    # --------------------------------------------------------------
    # Error handling
    # --------------------------------------------------------------

    "error-clear": (
        r"\bPyErr_Clear\s*\(",
        "MEDIUM",
        "medium",
        "error-handling",
        "PyErr_Clear() discards an exception; verify that the error is intentionally handled.",
    ),

    # --------------------------------------------------------------
    # Thread/GIL boundaries
    # --------------------------------------------------------------

    "thread-boundary": (
        r"\bPy_(?:BEGIN|END)_ALLOW_THREADS\b",
        "MEDIUM",
        "medium",
        "threading",
        "Thread-state/GIL boundary changed; inspect object lifetime and error paths.",
    ),

    # --------------------------------------------------------------
    # Python
    # --------------------------------------------------------------

    "python-bare-except": (
        r"except\s*:",
        "MEDIUM",
        "medium",
        "python",
        "Bare except catches BaseException; verify this is intentional.",
    ),

    "python-assert": (
        r"\bassert\s+",
        "MEDIUM",
        "medium",
        "python",
        "assert can be disabled with -O; verify it is not enforcing runtime correctness.",
    ),

    "python-global": (
        r"\bglobal\s+\w",
        "LOW",
        "medium",
        "python",
        "Global mutable state changed; inspect concurrency/lifecycle implications.",
    ),

    # --------------------------------------------------------------
    # Security
    # --------------------------------------------------------------

    "security-eval": (
        r"\beval\s*\(",
        "HIGH",
        "medium",
        "security",
        "eval() was introduced; verify the input trust boundary.",
    ),

    "security-exec": (
        r"\bexec\s*\(",
        "HIGH",
        "medium",
        "security",
        "exec() was introduced; verify the input trust boundary.",
    ),

    "security-pickle": (
        r"\bpickle\.(?:load|loads)\s*\(",
        "HIGH",
        "medium",
        "security",
        "pickle loading was introduced; verify that serialized data is trusted.",
    ),

    "security-shell": (
        r"\bshell\s*=\s*True",
        "HIGH",
        "medium",
        "security",
        "subprocess shell=True was introduced; inspect command construction and input flow.",
    ),

    "security-mktemp": (
        r"\btempfile\.mktemp\s*\(",
        "HIGH",
        "high",
        "security",
        "mktemp() is race-prone; inspect whether a safe temporary-file API is required.",
    ),
}


def analyze_patch(
    filename: str,
    patch: str | None,
) -> list[Finding]:
    """
    Analyze only added lines in a patch.

    This is intentionally a lightweight first-stage analyzer.
    Semantic analysis will be added later.
    """

    findings: list[Finding] = []

    for changed in added_lines(patch):
        for (
            rule_id,
            (
                pattern,
                severity,
                confidence,
                category,
                message,
            ),
        ) in RULES.items():

            if not re.search(
                pattern,
                changed.text,
            ):
                continue

            evidence = EvidenceRef(
                kind="diff",
                description=(
                    f"Matched deterministic rule "
                    f"{rule_id} in added code."
                ),
                source="patch",
                file=filename,
                line=changed.line_no,
                observed=changed.text,
            )

            findings.append(
                Finding(
                    severity=severity,
                    category=category,
                    message=message,
                    confidence=confidence,
                    source="deterministic",
                    evidence_refs=[evidence],
                    file=filename,
                    rule_id=rule_id,
                )
            )

    return findings


def analyze_files(
    files: Iterable[dict],
) -> list[Finding]:
    """
    Run all deterministic rules over changed files.
    """

    findings: list[Finding] = []

    for file_data in files:
        findings.extend(
            analyze_patch(
                file_data.get(
                    "filename",
                    "",
                ),
                file_data.get(
                    "patch"
                ),
            )
        )

    return findings


def deduplicate_findings(
    findings: Iterable[Finding],
) -> list[Finding]:
    """
    Remove duplicate findings while preserving order.
    """

    seen: set[tuple] = set()

    result: list[Finding] = []

    for finding in findings:
        key = (
            finding.rule_id,
            finding.file,
            finding.message,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(finding)

    return result