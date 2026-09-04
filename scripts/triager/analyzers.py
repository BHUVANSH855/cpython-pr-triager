"""
Deterministic technical analyzers.

These analyzers produce review prompts from changed files.
They never establish that a defect exists.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from .diff import (
    added_lines,
    compare_function_signatures,
    parse_python,
)
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


def _is_c_family(filename: str) -> bool:
    return filename.endswith(
        (
            ".c",
            ".h",
            ".cc",
            ".cpp",
            ".m",
        )
    )


def _is_c_family_for_refcount(filename: str) -> bool:
    return filename.endswith(
        (
            ".c",
            ".h",
            ".cc",
            ".cpp",
        )
    )


def _is_python(filename: str) -> bool:
    return filename.endswith(".py")


def _is_test_file(filename: str) -> bool:
    return (
        filename.startswith("Lib/test/")
        or "/test/" in filename
        or filename.rsplit("/", 1)[-1].startswith("test_")
    )


def _finding_sort_key(finding: Finding) -> tuple[int, int, str, str]:
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    confidence_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    return (
        severity_order.get(
            finding.severity,
            99,
        ),
        confidence_order.get(
            finding.confidence,
            99,
        ),
        finding.file,
        finding.message,
    )


def _add_rule_findings(
    filename: str,
    patch: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    is_c = _is_c_family(filename)
    is_py = _is_python(filename)
    is_test = _is_test_file(filename)

    for changed in added_lines(patch):
        for rule_id, (
            pattern,
            severity,
            confidence,
            category,
            message,
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


def _add_ast_findings(
    filename: str,
    patch: str | None,
) -> list[Finding]:
    if not _is_python(filename):
        return []

    added_lines_data = added_lines(patch)

    if not added_lines_data:
        return []

    added_text = "\n".join(
        item.text
        for item in added_lines_data
    )

    tree = parse_python(
        added_text
    )

    if tree is None:
        return []

    findings: list[Finding] = []

    for node in ast.walk(tree):
        line = getattr(
            node,
            "lineno",
            None,
        )

        if isinstance(
            node,
            ast.Call,
        ) and isinstance(
            node.func,
            ast.Name,
        ):
            if node.func.id == "eval":
                findings.append(
                    Finding(
                        severity="HIGH",
                        category="AST",
                        message=(
                            "AST analysis confirms a newly added "
                            "eval() call; verify the trust boundary."
                        ),
                        confidence="medium",
                        source="deterministic",
                        evidence_refs=[
                            EvidenceRef(
                                kind="ast",
                                description="AST contains an eval() call.",
                                source="added-python",
                                file=filename,
                                line=line,
                                observed="eval(...)",
                            )
                        ],
                        file=filename,
                        rule_id="python-ast-eval",
                    )
                )

            elif node.func.id == "exec":
                findings.append(
                    Finding(
                        severity="HIGH",
                        category="AST",
                        message=(
                            "AST analysis confirms a newly added "
                            "exec() call; verify the trust boundary."
                        ),
                        confidence="medium",
                        source="deterministic",
                        evidence_refs=[
                            EvidenceRef(
                                kind="ast",
                                description="AST contains an exec() call.",
                                source="added-python",
                                file=filename,
                                line=line,
                                observed="exec(...)",
                            )
                        ],
                        file=filename,
                        rule_id="python-ast-exec",
                    )
                )

        elif (
            isinstance(
                node,
                ast.ExceptHandler,
            )
            and node.type is None
        ):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="AST",
                    message=(
                        "AST analysis found a bare except; "
                        "verify that catching BaseException is intentional."
                    ),
                    confidence="medium",
                    source="deterministic",
                    evidence_refs=[
                        EvidenceRef(
                            kind="ast",
                            description="AST contains a bare except handler.",
                            source="added-python",
                            file=filename,
                            line=line,
                            observed="except:",
                        )
                    ],
                    file=filename,
                    rule_id="python-ast-bare-except",
                )
            )

        elif isinstance(
            node,
            ast.Assert,
        ):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="AST",
                    message=(
                        "AST analysis found an assert; verify it is "
                        "not enforcing runtime correctness."
                    ),
                    confidence="medium",
                    source="deterministic",
                    evidence_refs=[
                        EvidenceRef(
                            kind="ast",
                            description="AST contains an assert statement.",
                            source="added-python",
                            file=filename,
                            line=line,
                            observed="assert ...",
                        )
                    ],
                    file=filename,
                    rule_id="python-ast-assert",
                )
            )

    return findings


def _add_structure_findings(
    file_data: dict,
) -> tuple[list[Finding], list[dict[str, object]]]:
    filename = file_data.get(
        "filename",
        "",
    )

    patch = file_data.get(
        "patch"
    )

    findings: list[Finding] = []
    signature_changes: list[dict[str, object]] = []

    if patch is None:
        return findings, signature_changes

    if filename.startswith(
        "Grammar/"
    ):
        findings.append(
            Finding(
                severity="HIGH",
                category="GRAMMAR",
                message=(
                    "Grammar files changed; verify generated/parser "
                    "artifacts and parser tests."
                ),
                confidence="high",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description="Changed path is under Grammar/.",
                        source="filename",
                        file=filename,
                        observed=filename,
                    )
                ],
                file=filename,
                rule_id="grammar-change",
            )
        )

    if (
        re.match(
            r"^Include/(?!internal/|cpython/)",
            filename,
        )
        and filename.endswith(".h")
    ):
        findings.append(
            Finding(
                severity="HIGH",
                category="ABI",
                message=(
                    "Public C header changed; explicitly review API/ABI "
                    "compatibility and Stable ABI impact."
                ),
                confidence="high",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description=(
                            "Changed path is a public Include/*.h header."
                        ),
                        source="filename",
                        file=filename,
                        observed=filename,
                    )
                ],
                file=filename,
                rule_id="public-header-change",
            )
        )

    added_text = "\n".join(
        line.text
        for line in added_lines(patch)
    )

    removed_lines: list[str] = []

    for raw in patch.splitlines():
        if raw.startswith(
            ("+++", "---", "@@")
        ):
            continue

        if raw.startswith("-"):
            removed_lines.append(
                raw[1:]
            )

    removed_text = "\n".join(
        removed_lines
    )

    if filename.endswith(
        ".py"
    ):
        changes = compare_function_signatures(
            removed_text,
            added_text,
        )

        for change in changes:
            if change["kind"] != "changed":
                continue

            name = str(
                change["function"]
            )

            if name.startswith("_"):
                continue

            signature_changes.append(
                {
                    "function": name,
                    "file": filename,
                    "old": change["old"],
                    "new": change["new"],
                }
            )

            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="API",
                    message=(
                        f"Public-looking Python signature changed for "
                        f"{name}(); review compatibility."
                    ),
                    confidence="medium",
                    source="deterministic",
                    evidence_refs=[
                        EvidenceRef(
                            kind="signature",
                            description=(
                                f"Function signature changed for {name}()."
                            ),
                            source="patch",
                            file=filename,
                            observed=(
                                f"Old: {change['old']} | "
                                f"New: {change['new']}"
                            ),
                        )
                    ],
                    file=filename,
                    rule_id="python-signature-change",
                )
            )

    return findings, signature_changes


def _add_refcount_finding(
    file_data: dict,
) -> list[Finding]:
    filename = file_data.get(
        "filename",
        "",
    )

    if not _is_c_family_for_refcount(
        filename
    ):
        return []

    patch = file_data.get(
        "patch"
    )

    added_text = "\n".join(
        line.text
        for line in added_lines(patch)
    )

    inc = len(
        re.findall(
            r"\bPy_INCREF\s*\(",
            added_text,
        )
    )

    dec = len(
        re.findall(
            r"\bPy_(?:X)?DECREF\s*\(",
            added_text,
        )
    )

    if inc < dec + 3:
        return []

    return [
        Finding(
            severity="LOW",
            category="REFCOUNT",
            message=(
                f"Added diff contains {inc} INCREF vs {dec} DECREF "
                "operations; inspect ownership paths manually."
            ),
            confidence="low",
            source="deterministic",
            evidence_refs=[
                EvidenceRef(
                    kind="diff",
                    description=(
                        "Local diff count suggests a possible "
                        "ownership imbalance."
                    ),
                    source="patch",
                    file=filename,
                    observed=(
                        f"Py_INCREF={inc}, "
                        f"Py_DECREF/Py_XDECREF={dec}"
                    ),
                )
            ],
            file=filename,
            rule_id="refcount-imbalance-prompt",
        )
    ]


def analyze_patch(
    filename: str,
    patch: str | None,
) -> list[Finding]:
    """Analyze one changed file."""

    findings = _add_rule_findings(
        filename,
        patch,
    )

    findings.extend(
        _add_ast_findings(
            filename,
            patch,
        )
    )

    findings.sort(
        key=_finding_sort_key
    )

    return findings


def analyze_file(
    file_data: dict,
) -> tuple[list[Finding], list[dict[str, object]]]:
    """Run complete deterministic analysis for one changed file."""

    filename = file_data.get(
        "filename",
        "",
    )

    findings = _add_rule_findings(
        filename,
        file_data.get("patch"),
    )

    findings.extend(
        _add_ast_findings(
            filename,
            file_data.get("patch"),
        )
    )

    structure_findings, signature_changes = (
        _add_structure_findings(
            file_data
        )
    )

    findings.extend(
        structure_findings
    )

    findings.extend(
        _add_refcount_finding(
            file_data
        )
    )

    return findings, signature_changes


def deduplicate_findings(
    findings: Iterable[Finding],
) -> list[Finding]:
    """Remove duplicate findings while preserving the strongest evidence."""

    result: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    for finding in findings:
        key = (
            finding.rule_id,
            finding.file,
            finding.message,
            finding.category,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(
            finding
        )

    result.sort(
        key=_finding_sort_key
    )

    return result


def analyze_files(
    files: Iterable[dict],
) -> tuple[list[Finding], list[dict[str, object]]]:
    """
    Run complete deterministic analysis over changed files.

    Returns findings plus public-looking Python signature changes.
    """

    findings: list[Finding] = []
    signature_changes: list[dict[str, object]] = []

    for file_data in files:
        file_findings, file_signatures = analyze_file(
            file_data
        )

        findings.extend(
            file_findings
        )
        signature_changes.extend(
            file_signatures
        )

    findings = deduplicate_findings(
        findings
    )

    return (
        findings,
        signature_changes,
    )
