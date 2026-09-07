from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from .diff import (
    added_lines,
    compare_function_signatures,
    parse_python,
    reconstruct_new_text,
)
from .models import EvidenceRef, Finding

FREE_THREAD_SUBSYSTEMS = re.compile(
    r"^(?:"
    r"Python/ceval\.c"
    r"|Python/gc\.c"
    r"|Python/import\.c"
    r"|Python/crossinterp"
    r"|Python/context"
    r"|Python/critical_section"
    r"|Python/ceval_gil"
    r"|Objects/dict"
    r"|Objects/list"
    r"|Objects/set"
    r"|Objects/type"
    r"|Objects/frame"
    r"|Objects/gen"
    r"|Objects/func"
    r"|Modules/_asynciomodule"
    r"|Modules/_io/"
    r"|Modules/posixmodule"
    r"|Modules/socketmodule"
    r"|Modules/_thread"
    r"|Modules/_interpreters"
    r"|Lib/asyncio/"
    r"|Lib/logging/"
    r"|Lib/importlib/"
    r"|Lib/concurrent/"
    r")"
)

FREE_THREAD_TRIGGER = re.compile(
    r"PyThread_|_Py_CRITICAL_SECTION|Py_BEGIN_ALLOW_THREADS"
    r"|threading\.|global\s+\w"
    r"|interp->|tstate->"
)


RULES: dict[str, tuple[str, str, str, str, str]] = {
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
        "CRITICAL",
        "high",
        "security",
        "sprintf() was introduced; use PyOS_snprintf() instead.",
    ),
    "c-raw-malloc": (
        r"(?<!\w)malloc\s*\(",
        "HIGH",
        "medium",
        "memory",
        "raw malloc() introduced; use PyMem_Malloc() to go through the CPython allocator.",
    ),
    "c-raw-free": (
        r"(?<!\w)free\s*\(",
        "HIGH",
        "medium",
        "memory",
        "raw free() introduced; use PyMem_Free() to match the CPython allocator.",
    ),
    "c-raw-realloc": (
        r"(?<!\w)realloc\s*\(",
        "HIGH",
        "medium",
        "memory",
        "raw realloc() introduced; use PyMem_Realloc().",
    ),
    "c-raw-calloc": (
        r"(?<!\w)calloc\s*\(",
        "HIGH",
        "medium",
        "memory",
        "raw calloc() introduced; use PyMem_Calloc().",
    ),
    "cpython-private-api": (
        r"\b_Py_[A-Za-z]\w*",
        "MEDIUM",
        "medium",
        "api",
        "A private _Py_* API is used; verify layer, ownership, and API expectations.",
    ),
    "cpython-deprecated-identifier": (
        r"_Py_IDENTIFIER\s*\(",
        "MEDIUM",
        "medium",
        "api",
        "_Py_IDENTIFIER is deprecated; use &_Py_ID() or PyUnicode_FromString.",
    ),
    "cpython-pycobject": (
        r"\bPyCObject_",
        "CRITICAL",
        "high",
        "api",
        "PyCObject was removed in Python 3.x; use PyCapsule instead.",
    ),
    "error-clear": (
        r"\bPyErr_Clear\s*\(",
        "MEDIUM",
        "medium",
        "error-handling",
        "PyErr_Clear() discards an exception; verify that the error is intentionally handled.",
    ),
    "thread-boundary": (
        r"\bPy_(?:BEGIN|END)_ALLOW_THREADS\b",
        "MEDIUM",
        "medium",
        "threading",
        "Thread-state/GIL boundary changed; inspect object lifetime and error paths.",
    ),
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
    "python-deprecation-stacklevel": (
        r"DeprecationWarning(?![\s\S]{0,120}stacklevel\s*=)",
        "MEDIUM",
        "medium",
        "python",
        "DeprecationWarning without stacklevel= shows the wrong call site to users; add stacklevel=2.",
    ),
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
        "mktemp() is race-prone (TOCTOU); use mkstemp() or NamedTemporaryFile().",
    ),
    "security-md5-sha1": (
        r"\bhashlib\.(md5|sha1)\b",
        "MEDIUM",
        "medium",
        "security",
        "MD5/SHA1 are cryptographically broken for security use; use SHA-256 or SHA-3.",
    ),
}


def _is_c_family(filename: str) -> bool:
    return filename.endswith((".c", ".h", ".cc", ".cpp", ".m"))


def _is_c_family_for_refcount(filename: str) -> bool:
    return filename.endswith((".c", ".h", ".cc", ".cpp"))


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
        severity_order.get(finding.severity, 99),
        confidence_order.get(finding.confidence, 99),
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

    c_only_rules = {
        "c-unsafe-gets",
        "c-unsafe-strcpy",
        "c-unsafe-strcat",
        "c-unsafe-sprintf",
        "c-raw-malloc",
        "c-raw-free",
        "c-raw-realloc",
        "c-raw-calloc",
        "cpython-private-api",
        "cpython-deprecated-identifier",
        "cpython-pycobject",
        "error-clear",
        "thread-boundary",
    }

    py_notest_rules = {
        "python-bare-except",
        "python-assert",
        "python-global",
        "python-deprecation-stacklevel",
    }

    for changed in added_lines(patch):
        for rule_id, (
            pattern,
            severity,
            confidence,
            category,
            message,
        ) in RULES.items():
            if rule_id in c_only_rules and not is_c:
                continue

            if rule_id in py_notest_rules and not is_py:
                continue

            if rule_id in py_notest_rules and is_test:
                continue

            if not re.search(pattern, changed.text):
                continue

            evidence = EvidenceRef(
                kind="diff",
                description=(
                    f"Matched deterministic rule {rule_id} "
                    "in added code."
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


def _parse_python_for_analysis(
    filename: str,
    patch: str | None,
    old_text: str | None = None,
) -> tuple[ast.AST | None, str]:
    if not patch:
        return None, "added-python"

    if old_text is not None:
        reconstructed = reconstruct_new_text(
            old_text,
            patch,
        )

        if reconstructed is not None:
            tree = parse_python(reconstructed)

            if tree is not None:
                return tree, "reconstructed-python"

    added = added_lines(patch)

    if not added:
        return None, "added-python"

    added_text = "\n".join(
        item.text
        for item in added
    )

    tree = parse_python(added_text)

    if tree is not None:
        return tree, "added-python"

    return None, "added-python"


def _added_line_numbers(patch: str | None) -> set[int]:
    """Return new-file line numbers represented by added lines."""
    return {item.line_no for item in added_lines(patch)}


def _node_changed(
    node: ast.AST,
    changed_lines: set[int],
) -> bool:
    """Return whether an AST node overlaps a changed source line."""
    if not changed_lines:
        return False

    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)

    if not isinstance(start, int):
        return False

    if not isinstance(end, int):
        end = start

    return any(start <= line <= end for line in changed_lines)


def _add_ast_findings(
    filename: str,
    patch: str | None,
    old_text: str | None = None,
) -> list[Finding]:
    if not _is_python(filename):
        return []

    tree, source_kind = _parse_python_for_analysis(
        filename,
        patch,
        old_text,
    )

    if tree is None:
        return []

    findings: list[Finding] = []

    if source_kind == "reconstructed-python":
        changed_lines = _added_line_numbers(patch)
    else:
        added = added_lines(patch)
        changed_lines = set(range(1, len(added) + 1))

    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)

        if not _node_changed(node, changed_lines):
            continue

        if isinstance(node, ast.Call) and isinstance(
            node.func,
            ast.Name,
        ):
            if node.func.id in ("eval", "exec"):
                findings.append(
                    Finding(
                        severity="HIGH",
                        category="AST",
                        message=(
                            f"AST analysis confirms a newly added "
                            f"{node.func.id}() call; verify the trust boundary."
                        ),
                        confidence="medium",
                        source="deterministic",
                        evidence_refs=[
                            EvidenceRef(
                                kind="ast",
                                description=(
                                    f"AST contains a {node.func.id}() call."
                                ),
                                source=source_kind,
                                file=filename,
                                line=line,
                                observed=(
                                    f"{node.func.id}(...) "
                                    f"[changed line {line}]"
                                ),
                            )
                        ],
                        file=filename,
                        rule_id=f"python-ast-{node.func.id}",
                    )
                )

        elif isinstance(node, ast.ExceptHandler) and node.type is None:
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
                            description=(
                                "AST contains a bare except handler."
                            ),
                            source=source_kind,
                            file=filename,
                            line=line,
                            observed=f"except: [changed line {line}]",

                        )
                    ],
                    file=filename,
                    rule_id="python-ast-bare-except",
                )
            )

        elif isinstance(node, ast.Assert):
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
                            description=(
                                "AST contains an assert statement."
                            ),
                            source=source_kind,
                            file=filename,
                            line=line,
                            observed=f"assert ... [changed line {line}]",

                        )
                    ],
                    file=filename,
                    rule_id="python-ast-assert",
                )
            )

    return findings


_PUBLIC_API_DECL_RE = re.compile(
    r"\bPyAPI_(?:FUNC|DATA)\s*\([^)]*\)\s*"
    r"(?P<name>[A-Za-z_]\w*)"
)
_PUBLIC_API_FUNC_RE = re.compile(
    r"\bPyAPI_FUNC\s*\([^)]*\)\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
)


def _public_header_kind(filename: str) -> str | None:
    if not filename.startswith("Include/") or not filename.endswith(".h"):
        return None

    if filename.startswith("Include/internal/"):
        return None

    if filename.startswith("Include/cpython/"):
        return "cpython"
    return "stable"


def _extract_public_api_symbols(text: str) -> set[str]:
    symbols: set[str] = set()

    for match in _PUBLIC_API_DECL_RE.finditer(text):
        symbols.add(match.group("name"))

    return symbols


def _extract_public_api_function_signatures(text: str) -> dict[str, str]:
    signatures: dict[str, str] = {}

    for line in text.splitlines():
        if "PyAPI_FUNC" not in line:
            continue
        match = _PUBLIC_API_FUNC_RE.search(line)
        if match:
            name = match.group("name")
            signatures[name] = line.strip()

    return signatures


def _add_c_api_findings(
    file_data: dict,
) -> list[Finding]:
    filename = file_data.get("filename", "")
    patch = file_data.get("patch")

    if not patch:
        return []

    header_kind = _public_header_kind(filename)
    if header_kind is None:
        return []

    added_text = "\n".join(
        line.text
        for line in added_lines(patch)
    )
    removed_lines = [
        raw[1:]
        for raw in patch.splitlines()
        if raw.startswith("-")
        and not raw.startswith(("---", "+++"))
    ]
    removed_text = "\n".join(removed_lines)

    added_symbols = _extract_public_api_symbols(added_text)
    removed_symbols = _extract_public_api_symbols(removed_text)
    added_functions = _extract_public_api_function_signatures(added_text)
    removed_functions = _extract_public_api_function_signatures(removed_text)

    findings: list[Finding] = []

    for symbol in sorted(removed_symbols - added_symbols):
        severity = "HIGH" if header_kind == "stable" else "MEDIUM"
        api_scope = (
            "Stable ABI"
            if header_kind == "stable"
            else "CPython-specific public API"
        )
        findings.append(
            Finding(
                severity=severity,
                category="ABI",
                message=(
                    f"Public API symbol {symbol} was removed from "
                    f"{api_scope} header; review downstream compatibility "
                    "and ABI impact."
                ),
                confidence="high",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="diff",
                        description=(
                            "A public PyAPI_FUNC/PyAPI_DATA declaration "
                            "was removed from a public header."
                        ),
                        source="patch",
                        file=filename,
                        observed=f"Removed: {symbol}",
                    )
                ],
                file=filename,
                rule_id="public-api-removal",
            )
        )

    for symbol in sorted(added_symbols - removed_symbols):
        severity = "MEDIUM"
        api_scope = (
            "Stable ABI"
            if header_kind == "stable"
            else "CPython-specific public API"
        )
        findings.append(
            Finding(
                severity=severity,
                category="API",
                message=(
                    f"Public API symbol {symbol} was added to {api_scope} "
                    "header; review API design, documentation, and ABI "
                    "expectations."
                ),
                confidence="high",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="diff",
                        description=(
                            "A public PyAPI_FUNC/PyAPI_DATA declaration "
                            "was added to a public header."
                        ),
                        source="patch",
                        file=filename,
                        observed=f"Added: {symbol}",
                    )
                ],
                file=filename,
                rule_id="public-api-addition",
            )
        )

    for symbol in sorted(
        set(added_functions) & set(removed_functions)
    ):
        old_signature = removed_functions[symbol]
        new_signature = added_functions[symbol]

        if old_signature == new_signature:
            continue

        findings.append(
            Finding(
                severity="HIGH" if header_kind == "stable" else "MEDIUM",
                category="ABI",
                message=(
                    f"Public API function {symbol} changed signature; "
                    "review source compatibility, ABI compatibility, and "
                    "Stable ABI expectations."
                ),
                confidence="high",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="signature",
                        description=(
                            "A PyAPI_FUNC declaration changed in a public header."
                        ),
                        source="patch",
                        file=filename,
                        observed=(
                            f"Old: {old_signature} | New: {new_signature}"
                        ),
                    )
                ],
                file=filename,
                rule_id="public-api-signature-change",
            )
        )

    return findings


_ARGUMENT_CLINIC_MARKER_RE = re.compile(
    r"\[clinic\s+(?:input|start generated code|end generated code)\]",
    re.IGNORECASE,
)


def _is_argument_clinic_generated_file(filename: str) -> bool:
    """Return whether filename is a CPython Argument Clinic output file."""
    normalized = filename.replace("\\", "/")
    parts = normalized.split("/")
    if len(parts) < 3:
        return False
    if parts[0] not in {"Python", "Modules"}:
        return False
    if "clinic" not in parts[1:-1]:
        return False
    return parts[-1].endswith(".c.h")


def _argument_clinic_source_for_generated(filename: str) -> str | None:
    normalized = filename.replace("\\", "/")
    parts = normalized.split("/")
    if len(parts) < 3:
        return None
    if parts[0] not in {"Python", "Modules"}:
        return None

    try:
        clinic_index = parts.index("clinic", 1, len(parts) - 1)
    except ValueError:
        return None

    generated_name = parts[-1]
    if not generated_name.endswith(".c.h"):
        return None

    source_name = generated_name[:-2]
    source_parts = parts[:clinic_index] + [source_name]
    return "/".join(source_parts)


def _argument_clinic_generated_for_source(filename: str) -> str | None:
    normalized = filename.replace("\\", "/")
    if not normalized.endswith(".c"):
        return None

    parts = normalized.split("/")
    if len(parts) < 2 or parts[0] not in {"Python", "Modules"}:
        return None

    directory = parts[:-1]
    source_name = parts[-1]
    return "/".join(directory + ["clinic", source_name + ".h"])


def _patch_contains_argument_clinic_marker(patch: str | None) -> bool:
    if not patch:
        return False
    return bool(_ARGUMENT_CLINIC_MARKER_RE.search(patch))


def _add_argument_clinic_file_finding(file_data: dict) -> list[Finding]:
    filename = str(file_data.get("filename", "")).replace("\\", "/")
    if not _is_argument_clinic_generated_file(filename):
        return []

    source_file = _argument_clinic_source_for_generated(filename)
    message = (
        f"Generated Argument Clinic file {filename} changed; verify the "
        "corresponding source and regenerate it with Argument Clinic."
    )
    if source_file:
        message += f" Expected source: {source_file}."

    return [
        Finding(
            severity="MEDIUM",
            category="GENERATED",
            message=message,
            confidence="high",
            source="deterministic",
            evidence_refs=[
                EvidenceRef(
                    kind="path",
                    description=(
                        "Changed path matches CPython's Argument Clinic "
                        "generated-file pattern."
                    ),
                    source="filename",
                    file=filename,
                    observed=filename,
                )
            ],
            file=filename,
            rule_id="argument-clinic-generated-file",
        )
    ]


def _add_argument_clinic_consistency_findings(
    files: list[dict],
) -> list[Finding]:
    changed_paths = {
        str(file_data.get("filename", "")).replace("\\", "/")
        for file_data in files
        if file_data.get("filename")
    }
    findings: list[Finding] = []

    for file_data in files:
        filename = str(file_data.get("filename", "")).replace("\\", "/")
        patch = file_data.get("patch")

        if _is_argument_clinic_generated_file(filename):
            source_file = _argument_clinic_source_for_generated(filename)
            if source_file and source_file not in changed_paths:
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="GENERATED",
                        message=(
                            f"Argument Clinic generated file {filename} changed "
                            f"without a change to its expected source file "
                            f"{source_file}; verify whether the generated "
                            "artifact was regenerated correctly."
                        ),
                        confidence="medium",
                        source="deterministic",
                        evidence_refs=[
                            EvidenceRef(
                                kind="path",
                                description=(
                                    "Generated Clinic output has no corresponding "
                                    "source-file change in the PR."
                                ),
                                source="file-set",
                                file=filename,
                                observed=(
                                    f"generated={filename}; source={source_file}"
                                ),
                            )
                        ],
                        file=filename,
                        rule_id="argument-clinic-source-missing",
                    )
                )
            continue

        if not filename.endswith(".c") or not _patch_contains_argument_clinic_marker(
            patch
        ):
            continue

        generated_file = _argument_clinic_generated_for_source(filename)
        if generated_file and generated_file not in changed_paths:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="GENERATED",
                    message=(
                        f"Argument Clinic input changed in {filename}, but expected "
                        f"generated output {generated_file} is not part of the "
                        "change; verify regeneration."
                    ),
                    confidence="medium",
                    source="deterministic",
                    evidence_refs=[
                        EvidenceRef(
                            kind="diff",
                            description=(
                                "Changed C source contains an Argument Clinic marker."
                            ),
                            source="patch",
                            file=filename,
                            observed="Argument Clinic marker detected",
                        )
                    ],
                    file=filename,
                    rule_id="argument-clinic-generated-missing",
                )
            )

    return findings


def _add_structure_findings(
    file_data: dict,
) -> tuple[list[Finding], list[dict]]:
    filename = file_data.get("filename", "")
    patch = file_data.get("patch")

    findings: list[Finding] = []
    signature_changes: list[dict] = []

    if patch is None:
        return findings, signature_changes

    if filename.startswith("Grammar/"):
        findings.append(
            Finding(
                severity="HIGH",
                category="GRAMMAR",
                message=(
                    "Grammar files changed; run: "
                    "make regen-pegen && make regen-all && make regen-clinic. "
                    "Also verify generated parser artifacts and parser tests."
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
                    "compatibility and Stable ABI impact. "
                    "Run: python Tools/build/stable_abi.py."
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

    removed_lines_list: list[str] = []

    for raw in patch.splitlines():
        if raw.startswith(("+++", "---", "@@")):
            continue

        if raw.startswith("-"):
            removed_lines_list.append(raw[1:])

    removed_text = "\n".join(removed_lines_list)

    if filename.endswith(".py"):
        changes = compare_function_signatures(
            removed_text,
            added_text,
        )

        for change in changes:
            if change["kind"] != "changed":
                continue

            name = str(change["function"])

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


def _extract_decref_variable(text: str) -> str | None:
    match = re.search(
        r"\bPy_(?:X)?DECREF\s*\(\s*([A-Za-z_]\w*)\s*\)",
        text,
    )
    return match.group(1) if match else None


def _add_refcount_safety_findings(file_data: dict) -> list[Finding]:
    filename = file_data.get("filename", "")

    if not _is_c_family_for_refcount(filename):
        return []

    patch = file_data.get("patch")
    changed = list(added_lines(patch))
    if not changed:
        return []

    findings: list[Finding] = []

    for index, changed_line in enumerate(changed):
        variable = _extract_decref_variable(changed_line.text)
        if variable is None or index + 1 >= len(changed):
            continue

        next_line = changed[index + 1]

        if re.search(
            rf"\breturn\s+{re.escape(variable)}\s*;",
            next_line.text,
        ):
            findings.append(
                Finding(
                    severity="HIGH",
                    category="REFCOUNT",
                    message=(
                        f"Py_DECREF({variable}) is followed by returning "
                        f"{variable}; inspect for a use-after-decref."
                    ),
                    confidence="high",
                    source="deterministic",
                    evidence_refs=[
                        EvidenceRef(
                            kind="diff",
                            description=(
                                "A changed DECREF is immediately followed "
                                "by returning the same pointer."
                            ),
                            source="patch",
                            file=filename,
                            line=changed_line.line_no,
                            observed=(
                                f"{changed_line.text} -> {next_line.text}"
                            ),
                        )
                    ],
                    file=filename,
                    rule_id="refcount-decref-before-return",
                )
            )

        next_variable = _extract_decref_variable(next_line.text)
        if next_variable == variable:
            findings.append(
                Finding(
                    severity="HIGH",
                    category="REFCOUNT",
                    message=(
                        f"{variable} is decremented twice consecutively; "
                        "inspect for a double DECREF."
                    ),
                    confidence="high",
                    source="deterministic",
                    evidence_refs=[
                        EvidenceRef(
                            kind="diff",
                            description=(
                                "Consecutive changed lines DECREF "
                                "the same pointer."
                            ),
                            source="patch",
                            file=filename,
                            line=changed_line.line_no,
                            observed=(
                                f"{changed_line.text} -> {next_line.text}"
                            ),
                        )
                    ],
                    file=filename,
                    rule_id="refcount-double-decref",
                )
            )

    return findings


def _add_refcount_finding(
    file_data: dict,
) -> list[Finding]:
    filename = file_data.get("filename", "")

    if not _is_c_family_for_refcount(filename):
        return []

    patch = file_data.get("patch")

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

    findings: list[Finding] = []

    if inc > dec + 1:
        findings.append(
            Finding(
                severity="LOW",
                category="REFCOUNT",
                message=(
                    f"Added diff contains {inc} INCREF vs {dec} DECREF "
                    "operations; inspect ownership paths for potential leak."
                ),
                confidence="low",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="diff",
                        description=(
                            "Local diff count suggests possible reference leak."
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
                rule_id="refcount-possible-leak",
            )
        )

    if dec > inc + 2:
        findings.append(
            Finding(
                severity="LOW",
                category="REFCOUNT",
                message=(
                    f"Added diff contains {dec} DECREF vs {inc} INCREF "
                    "operations; inspect for potential over-decrement or double-free."
                ),
                confidence="low",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="diff",
                        description=(
                            "Local diff count suggests possible over-decrement."
                        ),
                        source="patch",
                        file=filename,
                        observed=(
                            f"Py_DECREF/Py_XDECREF={dec}, "
                            f"Py_INCREF={inc}"
                        ),
                    )
                ],
                file=filename,
                rule_id="refcount-possible-overdecref",
            )
        )

    return findings



_FREE_THREAD_GIL_DISABLED_RE = re.compile(r"\bPy_GIL_DISABLED\b")
_FREE_THREAD_CRITICAL_SECTION_RE = re.compile(
    r"\bPy_(?:BEGIN|END)_CRITICAL_SECTION(?:_FAST)?\b"
)
_FREE_THREAD_LOCK_RE = re.compile(
    r"\b(?:PyMutex_(?:Lock|Unlock)|PyThread_(?:acquire|release)_lock)\b"
)
_FREE_THREAD_BORROWED_REF_RE = re.compile(
    r"\b(?:PyList_GET_ITEM|PyTuple_GET_ITEM|PyDict_Next)\s*\("
)


def _free_thread_evidence(
    filename: str,
    description: str,
    observed: str,
    *,
    severity: str = "MEDIUM",
    confidence: str = "medium",
    rule_id: str,
    message: str,
) -> Finding:
    return Finding(
        severity=severity,
        category="FREE-THREADING",
        message=message,
        confidence=confidence,
        source="deterministic",
        evidence_refs=[
            EvidenceRef(
                kind="diff",
                description=description,
                source="patch",
                file=filename,
                observed=observed,
            )
        ],
        file=filename,
        rule_id=rule_id,
    )


def _add_free_threading_safety_findings(
    file_data: dict,
) -> list[Finding]:
    filename = str(file_data.get("filename", ""))
    normalized = filename.replace("\\", "/")
    if not FREE_THREAD_SUBSYSTEMS.match(normalized):
        return []

    patch = file_data.get("patch")
    changed = list(added_lines(patch))
    if not changed:
        return []

    added_text = "\n".join(line.text for line in changed)
    findings: list[Finding] = []

    if _FREE_THREAD_GIL_DISABLED_RE.search(added_text):
        findings.append(
            _free_thread_evidence(
                normalized,
                "Changed code explicitly references the free-threaded build condition.",
                "Py_GIL_DISABLED",
                severity="HIGH",
                confidence="high",
                rule_id="free-thread-gil-disabled-path",
                message=(
                    f"{normalized} changes a Py_GIL_DISABLED path; verify that "
                    "both GIL-enabled and free-threaded builds preserve the same "
                    "ownership, locking, and lifetime invariants."
                ),
            )
        )

    if _FREE_THREAD_CRITICAL_SECTION_RE.search(added_text):
        findings.append(
            _free_thread_evidence(
                normalized,
                "Changed code adds or removes a CPython critical-section macro.",
                "critical-section macro detected",
                severity="HIGH",
                confidence="high",
                rule_id="free-thread-critical-section",
                message=(
                    f"{normalized} changes a Py_CRITICAL_SECTION boundary; "
                    "review the protected region and lock ordering for free-threaded correctness."
                ),
            )
        )

    if _is_c_family_for_refcount(normalized) and _FREE_THREAD_LOCK_RE.search(added_text):
        findings.append(
            _free_thread_evidence(
                normalized,
                "Changed C code uses a CPython mutex or thread-lock API.",
                "mutex/thread-lock API detected",
                rule_id="free-thread-lock-scope",
                message=(
                    f"{normalized} changes lock usage in a free-threading-sensitive "
                    "C subsystem; verify lock scope, ordering, and error paths."
                ),
            )
        )

    if _is_c_family_for_refcount(normalized) and _FREE_THREAD_BORROWED_REF_RE.search(
        added_text
    ):
        findings.append(
            _free_thread_evidence(
                normalized,
                "Changed C code uses an API that exposes or traverses borrowed references.",
                "borrowed-reference API detected",
                rule_id="free-thread-borrowed-reference",
                message=(
                    f"{normalized} uses a borrowed-reference API in a "
                    "free-threading-sensitive C subsystem; verify object lifetime "
                    "and concurrent mutation assumptions."
                ),
            )
        )

    return findings

def _add_free_thread_finding(
    file_data: dict,
) -> list[Finding]:
    filename = file_data.get("filename", "")

    if not FREE_THREAD_SUBSYSTEMS.match(filename):
        return []

    patch = file_data.get("patch")

    added_text = "\n".join(
        line.text
        for line in added_lines(patch)
    )

    if not FREE_THREAD_TRIGGER.search(added_text):
        return []

    return [
        Finding(
            severity="HIGH",
            category="FREE-THREADING",
            message=(
                f"{filename} is a free-threading-sensitive subsystem; "
                "verify correctness with --disable-gil and add coverage "
                "under Lib/test/test_free_threading/ if not already present."
            ),
            confidence="medium",
            source="deterministic",
            evidence_refs=[
                EvidenceRef(
                    kind="diff",
                    description=(
                        "Free-threading-sensitive pattern in "
                        "GIL-sensitive subsystem."
                    ),
                    source="patch",
                    file=filename,
                )
            ],
            file=filename,
            rule_id="free-threading-risk",
        )
    ]


def analyze_patch(
    filename: str,
    patch: str | None,
) -> list[Finding]:
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
    findings.sort(key=_finding_sort_key)
    return findings



_GENERATED_ARTIFACT_PATHS = {
    "Parser/parser.c",
    "Python/graminit.c",
    "Python/graminit.h",
}

_NEWS_ROOT = "Misc/NEWS.d/next/"
_TEST_ROOTS = ("Lib/test/", "Tools/test/", "Modules/_testcapi/")
_PRODUCTION_ROOTS = (
    "Include/",
    "Lib/",
    "Modules/",
    "Objects/",
    "Python/",
    "Parser/",
)
_EXCLUDED_PRODUCTION_PREFIXES = (
    "Include/internal/",
    "Include/cpython/",
)


def _is_test_path(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    return normalized.startswith(_TEST_ROOTS)


def _is_news_path(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    return normalized.startswith(_NEWS_ROOT)


def _is_production_path(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    if not normalized.startswith(_PRODUCTION_ROOTS):
        return False
    return not normalized.startswith(_EXCLUDED_PRODUCTION_PREFIXES)


def _is_documentation_path(filename: str) -> bool:
    return filename.replace("\\", "/").startswith("Doc/")


def _add_generated_artifact_findings(files: list[dict]) -> list[Finding]:
    changed_paths = {
        str(file_data.get("filename", "")).replace("\\", "/")
        for file_data in files
        if file_data.get("filename")
    }
    findings: list[Finding] = []

    for filename in sorted(changed_paths):
        if filename not in _GENERATED_ARTIFACT_PATHS:
            continue
        findings.append(
            Finding(
                severity="MEDIUM",
                category="GENERATED",
                message=(
                    f"Generated parser artifact {filename} changed; verify that "
                    "the grammar/source generator was updated or run as required."
                ),
                confidence="medium",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description=(
                            "Changed path matches a known CPython generated parser artifact."
                        ),
                        source="filename",
                        file=filename,
                        observed=filename,
                    )
                ],
                file=filename,
                rule_id="generated-parser-artifact",
            )
        )

    if "Grammar/python.gram" in changed_paths and "Parser/parser.c" not in changed_paths:
        findings.append(
            Finding(
                severity="MEDIUM",
                category="GENERATED",
                message=(
                    "Grammar/python.gram changed without Parser/parser.c; "
                    "verify that the parser was regenerated when required."
                ),
                confidence="medium",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description=(
                            "Grammar source changed but the expected parser artifact "
                            "is absent from the changed-file set."
                        ),
                        source="file-set",
                        file="Grammar/python.gram",
                        observed="expected=Parser/parser.c",
                    )
                ],
                file="Grammar/python.gram",
                rule_id="generated-parser-artifact-missing",
            )
        )

    return findings


def _add_change_impact_findings(
    files: list[dict],
    findings: Iterable[Finding],
) -> list[Finding]:
    paths = [
        str(file_data.get("filename", "")).replace("\\", "/")
        for file_data in files
        if file_data.get("filename")
    ]
    production_files = [path for path in paths if _is_production_path(path)]
    if not production_files:
        return []

    has_tests = any(_is_test_path(path) for path in paths)
    has_news = any(_is_news_path(path) for path in paths)
    has_docs = any(_is_documentation_path(path) for path in paths)

    existing_findings = list(findings)
    public_api_change = any(
        finding.rule_id in {
            "public-api-addition",
            "public-api-removal",
            "public-api-signature-change",
        }
        for finding in existing_findings
    )
    user_visible_signal = any(
        finding.category in {"SECURITY", "ABI", "DEPRECATION"}
        or finding.rule_id in {
            "public-api-addition",
            "public-api-removal",
            "public-api-signature-change",
        }
        for finding in existing_findings
    )

    results: list[Finding] = []

    if not has_tests:
        results.append(
            Finding(
                severity="LOW",
                category="TESTS",
                message=(
                    "Production CPython code changed without a test-file change; "
                    "verify that regression or behavioral coverage is present."
                ),
                confidence="low",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description=(
                            "Changed-file set contains production code but no "
                            "recognized CPython test path."
                        ),
                        source="file-set",
                        observed=", ".join(production_files[:8]),
                    )
                ],
                file=production_files[0],
                rule_id="production-change-without-tests",
            )
        )

    if user_visible_signal and not has_news:
        results.append(
            Finding(
                severity="LOW",
                category="NEWS",
                message=(
                    "The change has a user-visible/API/security signal but no "
                    "Misc/NEWS.d/next entry; verify whether a NEWS entry is required."
                ),
                confidence="low",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description=(
                            "A user-visible/API/security signal was detected while "
                            "no NEWS.d/next file is changed."
                        ),
                        source="file-set",
                        observed=", ".join(production_files[:8]),
                    )
                ],
                file=production_files[0],
                rule_id="user-visible-change-without-news",
            )
        )

    if public_api_change and not has_docs:
        results.append(
            Finding(
                severity="LOW",
                category="DOCS",
                message=(
                    "A public API declaration changed without a documentation-file "
                    "change; verify whether the public API documentation needs updating."
                ),
                confidence="low",
                source="deterministic",
                evidence_refs=[
                    EvidenceRef(
                        kind="path",
                        description=(
                            "A public API finding exists but no Doc/ path is present "
                            "in the changed-file set."
                        ),
                        source="file-set",
                        observed=", ".join(production_files[:8]),
                    )
                ],
                file=production_files[0],
                rule_id="public-api-change-without-docs",
            )
        )

    return results


_HISTORY_COMPONENTS = (
    ("free-threading", (
        "free-thread",
        "gil",
        "nogil",
        "thread",
        "mutex",
        "critical section",
        "race",
    )),
    ("refcount", (
        "refcount",
        "reference",
        "decref",
        "incref",
        "borrowed",
        "immortal",
    )),
    ("parser", (
        "parser",
        "grammar",
        "peg",
        "syntax",
    )),
    ("import", (
        "import",
        "module state",
        "subinterpreter",
    )),
    ("asyncio", (
        "asyncio",
        "event loop",
        "coroutine",
        "task",
    )),
    ("abi", (
        "stable abi",
        "abi",
        "public api",
        "api change",
    )),
)


def _component_for_path(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    if normalized.startswith(("Objects/", "Include/")):
        return "objects"
    if normalized.startswith(("Python/", "Parser/", "Grammar/")):
        return "runtime"
    if normalized.startswith("Modules/"):
        return "modules"
    if normalized.startswith("Lib/asyncio/"):
        return "asyncio"
    if normalized.startswith("Lib/"):
        return "stdlib"
    if normalized.startswith("Tools/"):
        return "tools"
    if normalized.startswith("Doc/"):
        return "docs"
    if normalized.startswith("Lib/test/"):
        return "tests"
    return "other"


def _history_text(entry: object) -> str:
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return ""
    values = [
        entry.get("message"),
        entry.get("title"),
        entry.get("subject"),
        entry.get("body"),
        entry.get("sha"),
    ]
    return " ".join(str(value) for value in values if value)


def _history_entries(file_data: dict) -> list[object]:
    history = file_data.get("history")
    if not isinstance(history, list):
        return []
    return history


def _history_components(entries: list[object]) -> set[str]:
    components: set[str] = set()
    for entry in entries:
        text = _history_text(entry).lower()
        for component, keywords in _HISTORY_COMPONENTS:
            if any(keyword in text for keyword in keywords):
                components.add(component)
    return components


def _current_risk_components(
    file_data: dict,
    findings: Iterable[Finding],
) -> set[str]:
    filename = str(file_data.get("filename", "")).replace("\\", "/")
    components: set[str] = set()

    normalized = filename.lower()

    if normalized.startswith("lib/asyncio/"):
        components.add("asyncio")
    if normalized.startswith(("parser/", "grammar/")):
        components.add("parser")
    if normalized.startswith("include/"):
        components.add("abi")
    if FREE_THREAD_SUBSYSTEMS.match(filename):
        components.add("free-threading")

    category_components = {
        "FREE-THREADING": "free-threading",
        "REFCOUNT": "refcount",
        "ABI": "abi",
        "API": "abi",
        "GRAMMAR": "parser",
    }
    for finding in findings:
        component = category_components.get(finding.category)
        if component:
            components.add(component)

    return components


def _add_history_findings(
    file_data: dict,
    findings: Iterable[Finding] = (),
) -> list[Finding]:
    filename = str(file_data.get("filename", ""))
    entries = _history_entries(file_data)
    if not entries:
        return []

    historical_components = _history_components(entries)
    if not historical_components:
        return []

    current_components = _current_risk_components(file_data, findings)
    relevant = historical_components & current_components

    recent = []
    for entry in entries[:3]:
        text = _history_text(entry).strip()
        if text:
            recent.append(text[:160])
    observed = " | ".join(recent)

    if relevant:
        component_text = ", ".join(sorted(relevant))
        message = (
            f"{filename} has historical precedent for the current "
            f"{component_text} risk; review prior changes for precedent, "
            "ownership, and backport expectations. Historical context is "
            "supporting evidence, not proof of a defect."
        )
        description = (
            "Recent commit history for the changed file overlaps "
            "with a risk component detected in the current change."
        )
    else:
        component_text = ", ".join(sorted(historical_components))
        message = (
            f"{filename} has recent repository-history signals associated "
            f"with {component_text}; review prior changes for precedent, "
            "ownership, and backport expectations. Historical context is "
            "supporting evidence, not proof of a defect."
        )
        description = (
            "Recent commit history for the changed file contains "
            "component-specific maintenance signals."
        )

    return [
        Finding(
            severity="LOW",
            category="HISTORY",
            message=message,
            confidence="medium",
            source="repository-history",
            evidence_refs=[
                EvidenceRef(
                    kind="history",
                    description=description,
                    source="git-history",
                    file=filename,
                    observed=observed,
                )
            ],
            file=filename,
            rule_id="component-history-signal",
        )
    ]

def analyze_file(
    file_data: dict,
) -> tuple[list[Finding], list[dict]]:
    filename = file_data.get("filename", "")
    patch = file_data.get("patch")
    old_text = file_data.get("base_text")

    findings = _add_rule_findings(
        filename,
        patch,
    )
    findings.extend(
        _add_ast_findings(
            filename,
            patch,
            old_text,
        )
    )

    structure_findings, signature_changes = _add_structure_findings(
        file_data
    )
    findings.extend(structure_findings)
    findings.extend(_add_c_api_findings(file_data))
    findings.extend(_add_argument_clinic_file_finding(file_data))

    findings.extend(
        _add_refcount_finding(file_data)
    )
    findings.extend(
        _add_refcount_safety_findings(file_data)
    )
    findings.extend(
        _add_free_thread_finding(file_data)
    )
    findings.extend(
        _add_free_threading_safety_findings(file_data)
    )
    findings.extend(_add_history_findings(file_data, findings))

    findings.sort(key=_finding_sort_key)

    return findings, signature_changes


def deduplicate_findings(
    findings: Iterable[Finding],
) -> list[Finding]:
    result: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    for finding in findings:
        key = (
            finding.rule_id or "",
            finding.file or "",
            finding.message,
            finding.category,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(finding)

    result.sort(key=_finding_sort_key)
    return result


def analyze_files(
    files: Iterable[dict],
) -> tuple[list[Finding], list[dict]]:
    file_list = list(files)
    findings: list[Finding] = []
    signature_changes: list[dict] = []

    for file_data in file_list:
        file_findings, file_signatures = analyze_file(
            file_data
        )
        findings.extend(file_findings)
        signature_changes.extend(file_signatures)

    findings.extend(_add_argument_clinic_consistency_findings(file_list))
    findings.extend(_add_generated_artifact_findings(file_list))
    findings.extend(_add_change_impact_findings(file_list, findings))

    findings = deduplicate_findings(findings)

    return findings, signature_changes
