from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from statistics import median

# Support direct execution: python scripts/analyze.py
if __package__ in {None, ""}:
    REPO_ROOT = Path(__file__).resolve().parents[1]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

# Import analyzers as a MODULE object, not via "from X import Y".
# This avoids a circular import when test_analyzers.py imports
# scripts.triager.analyzers directly while unittest simultaneously
# loads analyze.py (which would try to import from a partially
# initialised analyzers module).
import scripts.triager.analyzers as _analyzers_module
from scripts.triager.ai import AISynthesisError

# FIX (point 20): import AI synthesis from the module — no local duplicate.
from scripts.triager.ai import synthesize as ai_synthesize
from scripts.triager.codeowners import (
    parse_codeowners as parse_codeowners_rules,
)
from scripts.triager.codeowners import (
    resolve_codeowners as resolve_codeowners_matches,
)
from scripts.triager.github import GitHub as TriagerGitHub
from scripts.triager.policy import (
    branch_and_backport_signals as policy_branch_signals,
)

# FIX (point 6): import all policy functions from policy.py — no local copies.
from scripts.triager.policy import (
    disposition as policy_disposition,
)
from scripts.triager.policy import (
    file_signals as policy_file_signals,
)
from scripts.triager.policy import (
    process_signals as policy_process_signals,
)
from scripts.triager.policy import (
    review_signals as policy_review_signals,
)
from scripts.triager.references import (
    collect_issue_numbers,
)
from scripts.triager.references import (
    issue_refs_from_timeline as extract_timeline_issue_refs,
)
from scripts.triager.report import build_report

REPO = os.environ.get("CPYTHON_REPO", "python/cpython")
CACHE_DIR = Path(os.environ.get("CPYTHON_TRIAGER_CACHE", ".triager-cache"))
CACHE_TTL = int(os.environ.get("CPYTHON_TRIAGER_CACHE_TTL", "900"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

BOT_LOGINS = frozenset({
    "miss-islington",
    "bedevere-bot",
    "github-actions[bot]",
    "dependabot[bot]",
    "codecov[bot]",
    "python-security-bot",
    "python-triage-bot",
    "CLAassistant",
    "python-cla-bot",
})

LABEL_HINTS = {
    "DO-NOT-MERGE": ("BLOCK", "Explicit repository process blocker."),
    "awaiting changes": ("BLOCK", "Author action is expected."),
    "awaiting merge": ("INFO", "Merge-process signal; verify CI and review state."),
    "skip news": ("OK", "NEWS requirement is explicitly waived."),
    "skip issue": ("OK", "Issue requirement is explicitly waived."),
    "type-security": (
        "INFO",
        "Security handling and branch policy deserve explicit review.",
    ),
    "type-crash": (
        "INFO",
        "Crash fix; prioritize impact and appropriate backports.",
    ),
}

MAINTENANCE_BRANCH_RE = re.compile(r"^3\.\d+$")

# FIX (point 3): hyphens not spaces — matches real CPython label format.
BACKPORT_LABEL_RE = re.compile(r"^needs-backport-to-(\d+\.\d+)$", re.IGNORECASE)

# Legacy reference syntax kept for compatibility with test_triager.py.
LEGACY_ISSUE_REF_RE = re.compile(
    r"(?:\bgh-|#|fix(?:es|ed)?\s+#|close(?:s|d)?\s+#|resolve(?:s|d)?\s+#)(\d{3,7})",
    re.IGNORECASE,
)

PEP_RE = re.compile(r"\bpep[- ]?(\d{3,4})\b", re.IGNORECASE)
# FIX (point 4) applied in references.py; keep legacy regex here for
# backward-compat with the test_triager.py extract_refs test only.
DISCUSS_RE = re.compile(r"https?://(?:www\.)?discuss\.python\.org/t/[^\s)>]+", re.IGNORECASE)

# FIX (point 8): expanded LAYOUT table with missing subsystems.
LAYOUT = [
    # ── Core interpreter ────────────────────────────────────────────────
    (r"^Python/ceval\.c$",          "interpreter-core", "core/eval-loop",     "Lib/test/test_ceval.py"),
    (r"^Python/bytecodes\.c$",      "interpreter-core", "core/bytecodes",     None),
    (r"^Python/compile\.c$",        "interpreter-core", "core/compiler",      "Lib/test/test_compile.py"),
    (r"^Python/ast",                "interpreter-core", "core/ast",           "Lib/test/test_ast/"),
    (r"^Python/symtable",           "interpreter-core", "core/symtable",      "Lib/test/test_symtable.py"),
    (r"^Python/gc\.c$",             "interpreter-core", "core/gc",            "Lib/test/test_gc.py"),
    (r"^Python/import\.c$",         "interpreter-core", "core/import",        "Lib/test/test_import/"),
    (r"^Python/bltinmodule",        "interpreter-core", "core/builtins",      "Lib/test/test_builtin.py"),
    (r"^Python/sysmodule",          "interpreter-core", "core/sys",           "Lib/test/test_sys.py"),
    (r"^Python/marshal",            "interpreter-core", "core/marshal",       "Lib/test/test_marshal.py"),
    (r"^Python/crossinterp",        "interpreter-core", "core/subinterp",     "Lib/test/test_interpreters/"),
    (r"^Python/context",            "interpreter-core", "core/contextvars",   "Lib/test/test_contextvars.py"),
    (r"^Python/critical_section",   "interpreter-core", "core/critical-sec",  None),
    (r"^Python/ceval_gil",          "interpreter-core", "core/gil",           None),
    (r"^Python/errors",             "interpreter-core", "core/errors",        "Lib/test/test_exceptions.py"),
    (r"^Python/flowgraph",          "interpreter-core", "core/flowgraph",     None),
    (r"^Python/codegen",            "interpreter-core", "core/codegen",       None),
    (r"^Python/assemble",           "interpreter-core", "core/assembler",     None),
    (r"^Python/jit",                "interpreter-core", "core/jit",           None),
    (r"^Python/",                   "interpreter-core", "core/python",        None),
    # ── Builtin objects ─────────────────────────────────────────────────
    (r"^Objects/longobject",        "interpreter-core", "objects/int",        "Lib/test/test_int.py"),
    (r"^Objects/unicodeobject",     "interpreter-core", "objects/unicode",    "Lib/test/test_unicode.py"),
    (r"^Objects/listobject",        "interpreter-core", "objects/list",       "Lib/test/test_list.py"),
    (r"^Objects/dictobject",        "interpreter-core", "objects/dict",       "Lib/test/test_dict.py"),
    (r"^Objects/odictobject",       "interpreter-core", "objects/ordered-dict","Lib/test/test_ordered_dict.py"),
    (r"^Objects/typeobject",        "interpreter-core", "objects/type",       "Lib/test/test_type.py"),
    (r"^Objects/exceptions",        "interpreter-core", "objects/exceptions", "Lib/test/test_exceptions.py"),
    (r"^Objects/frameobject",       "interpreter-core", "objects/frame",      "Lib/test/test_frame.py"),
    (r"^Objects/genobject",         "interpreter-core", "objects/generator",  "Lib/test/test_generators.py"),
    (r"^Objects/funcobject",        "interpreter-core", "objects/function",   None),
    (r"^Objects/bytesobject",       "interpreter-core", "objects/bytes",      "Lib/test/test_bytes.py"),
    (r"^Objects/setobject",         "interpreter-core", "objects/set",        "Lib/test/test_set.py"),
    (r"^Objects/tupleobject",       "interpreter-core", "objects/tuple",      "Lib/test/test_tuple.py"),
    (r"^Objects/typevarobject",     "interpreter-core", "objects/typevar",    "Lib/test/test_type_params.py"),
    (r"^Objects/codeobject",        "interpreter-core", "objects/code",       "Lib/test/test_code.py"),
    (r"^Objects/call",              "interpreter-core", "objects/call",       "Lib/test/test_call.py"),
    (r"^Objects/interpolation",     "interpreter-core", "objects/interpolation", None),
    (r"^Objects/lazyimport",        "interpreter-core", "objects/lazy-import",None),
    (r"^Objects/",                  "interpreter-core", "objects",            None),
    # ── C extension modules ─────────────────────────────────────────────
    (r"^Modules/_asynciomodule",    "extension-modules","modules/asyncio",    "Lib/test/test_asyncio/"),
    (r"^Modules/_io/",              "extension-modules","modules/io",         "Lib/test/test_io/"),
    (r"^Modules/_ssl",              "extension-modules","modules/ssl",        "Lib/test/test_ssl.py"),
    (r"^Modules/_json",             "extension-modules","modules/json",       "Lib/test/test_json/"),
    (r"^Modules/_pickle",           "extension-modules","modules/pickle",     "Lib/test/test_pickle.py"),
    (r"^Modules/_ctypes/",          "extension-modules","modules/ctypes",     "Lib/test/test_ctypes/"),
    (r"^Modules/_decimal/",         "extension-modules","modules/decimal",    "Lib/test/test_decimal.py"),
    (r"^Modules/_sqlite/",          "extension-modules","modules/sqlite",     "Lib/test/test_sqlite3/"),
    (r"^Modules/posixmodule",       "extension-modules","modules/os",         "Lib/test/test_os/"),
    (r"^Modules/socketmodule",      "extension-modules","modules/socket",     "Lib/test/test_socket.py"),
    (r"^Modules/signalmodule",      "extension-modules","modules/signal",     "Lib/test/test_signal.py"),
    (r"^Modules/timemodule",        "extension-modules","modules/time",       "Lib/test/test_time.py"),
    (r"^Modules/_threadmodule",     "extension-modules","modules/_thread",    "Lib/test/test_thread.py"),
    (r"^Modules/_collectionsmodule","extension-modules","modules/collections","Lib/test/test_collections.py"),
    (r"^Modules/_functoolsmodule",  "extension-modules","modules/functools",  "Lib/test/test_functools.py"),
    (r"^Modules/_interpreters",     "extension-modules","modules/interpreters","Lib/test/test_interpreters/"),
    (r"^Modules/mathmodule",        "extension-modules","modules/math",       "Lib/test/test_math.py"),
    (r"^Modules/_hashopenssl",      "extension-modules","modules/hashlib",    "Lib/test/test_hashlib.py"),
    (r"^Modules/_zstd/",            "extension-modules","modules/zstd",       "Lib/test/test_zstd.py"),
    (r"^Modules/_remote_debugging/","extension-modules","modules/remote-debug",None),
    (r"^Modules/",                  "extension-modules","modules",            None),
    # ── Python stdlib ────────────────────────────────────────────────────
    (r"^Lib/asyncio/",              "stdlib",           "asyncio",            "Lib/test/test_asyncio/"),
    (r"^Lib/typing\.py$",           "stdlib",           "typing",             "Lib/test/test_typing.py"),
    (r"^Lib/annotationlib",         "stdlib",           "annotationlib",      "Lib/test/test_annotationlib.py"),
    (r"^Lib/dataclasses",           "stdlib",           "dataclasses",        "Lib/test/test_dataclasses/"),
    (r"^Lib/pathlib/",              "stdlib",           "pathlib",            "Lib/test/test_pathlib/"),
    (r"^Lib/functools",             "stdlib",           "functools",          "Lib/test/test_functools.py"),
    (r"^Lib/contextlib",            "stdlib",           "contextlib",         "Lib/test/test_contextlib.py"),
    (r"^Lib/collections/",          "stdlib",           "collections",        "Lib/test/test_collections.py"),
    (r"^Lib/importlib/",            "stdlib",           "importlib",          "Lib/test/test_importlib/"),
    (r"^Lib/concurrent/",           "stdlib",           "concurrent.futures", "Lib/test/test_concurrent_futures/"),
    (r"^Lib/multiprocessing/",      "stdlib",           "multiprocessing",    "Lib/test/test_multiprocessing_spawn/"),
    (r"^Lib/unittest/",             "stdlib",           "unittest",           "Lib/test/test_unittest/"),
    (r"^Lib/logging/",              "stdlib",           "logging",            "Lib/test/test_logging.py"),
    (r"^Lib/http/",                 "stdlib",           "http",               "Lib/test/test_httplib.py"),
    (r"^Lib/urllib/",               "stdlib",           "urllib",             "Lib/test/test_urllib.py"),
    (r"^Lib/email/",                "stdlib",           "email",              "Lib/test/test_email/"),
    (r"^Lib/xml/",                  "stdlib",           "xml",                "Lib/test/test_xml_etree.py"),
    (r"^Lib/compression/",          "stdlib",           "compression",        "Lib/test/test_bz2.py"),
    (r"^Lib/sqlite3/",              "stdlib",           "sqlite3",            "Lib/test/test_sqlite3/"),
    (r"^Lib/idlelib/",              "idle",             "idle",               "Lib/idlelib/idle_test/"),
    (r"^Lib/test/",                 "tests",            "tests",              None),
    (r"^Lib/",                      "stdlib",           "stdlib",             None),
    # ── C API ────────────────────────────────────────────────────────────
    (r"^Include/internal/",         "c-api",            "internal",           None),
    (r"^Include/cpython/",          "c-api",            "cpython",            None),
    (r"^Include/",                  "c-api",            "public",             None),
    (r"^Misc/stable_abi",           "c-api",            "stable-abi",         None),
    # ── Release / Changelog ─────────────────────────────────────────────
    (r"^Misc/NEWS\.d/",             "release",          "news",               None),
    # ── Grammar / Parser ────────────────────────────────────────────────
    (r"^Grammar/",                  "interpreter-core", "grammar",            None),
    (r"^Parser/",                   "interpreter-core", "parser",             None),
    # ── Documentation ───────────────────────────────────────────────────
    (r"^Doc/",                      "documentation",    "docs",               None),
    # ── Tools ───────────────────────────────────────────────────────────
    (r"^Tools/clinic/",             "tools",            "clinic",             "Lib/test/test_clinic.py"),
    (r"^Tools/cases_generator/",    "tools",            "cases-gen",          "Lib/test/test_generated_cases.py"),
    (r"^Tools/jit/",                "tools",            "jit",                None),
    (r"^Tools/peg_generator/",      "tools",            "peg-generator",      "Lib/test/test_peg_generator/"),
    # ── Platform ─────────────────────────────────────────────────────────
    (r"^PC/|^PCbuild/",             "platform",         "windows",            None),
    (r"^Mac/|^Platforms/Apple/",    "platform",         "macos",              None),
    (r"^Platforms/Android/",        "platform",         "android",            None),
    (r"^Platforms/",                "platform",         "platform",           None),
    # ── Build ────────────────────────────────────────────────────────────
    (r"^configure",                 "build",            "configure",          None),
    (r"^Makefile",                  "build",            "makefile",           None),
]


# ---------------------------------------------------------------------------
# GitHub client wrapper
# ---------------------------------------------------------------------------

class GitHub(TriagerGitHub):
    """Compatibility wrapper around the modular GitHub client."""

    def __init__(self, token=GITHUB_TOKEN):
        super().__init__(
            token=token,
            cache_dir=CACHE_DIR,
            cache_ttl=CACHE_TTL,
        )

    def checks(self, ref):
        return super().check_runs(ref).get("check_runs", [])


# ---------------------------------------------------------------------------
# CODEOWNERS helpers (compatibility wrappers)
# ---------------------------------------------------------------------------

def classify(path):
    for pattern, component, subsystem, expected_test in LAYOUT:
        if re.search(pattern, path):
            return component, subsystem, expected_test
    return (
        path.split("/")[0] if "/" in path else "root",
        "unknown",
        None,
    )


def parse_codeowners(text):
    rules = parse_codeowners_rules(text or "")
    return [
        {"line": rule.line, "pattern": rule.pattern, "owners": list(rule.owners)}
        for rule in rules
    ]


def codeowners_match(pattern, path):
    from scripts.triager.codeowners import _matches
    return _matches(pattern, path)


def resolve_codeowners(rules, filenames):
    parsed_rules = [
        rule
        if hasattr(rule, "pattern")
        else type(
            "CompatCodeOwnerRule", (),
            {"pattern": rule["pattern"], "owners": tuple(rule["owners"]), "line": rule["line"]},
        )()
        for rule in rules
    ]
    return [
        {
            "owner": match.owner,
            "file": match.file,
            "pattern": match.pattern,
            "line": match.line,
        }
        for match in resolve_codeowners_matches(parsed_rules, filenames)
    ]


# ---------------------------------------------------------------------------
# Reference extraction (legacy wrapper — tests depend on this signature)
# ---------------------------------------------------------------------------

def extract_refs(text):
    """
    Compatibility wrapper preserving legacy reference semantics.
    Returns (issues, peps, discussions) where discussions is a list of URLs.
    """
    text = text or ""

    issues = sorted({
        int(m.group(1))
        for m in LEGACY_ISSUE_REF_RE.finditer(text)
    })
    peps = sorted({
        int(m.group(1))
        for m in PEP_RE.finditer(text)
    })
    discussions = sorted(set(DISCUSS_RE.findall(text)))

    return issues, peps, discussions


def issue_refs_from_timeline(timeline):
    return extract_timeline_issue_refs(timeline)


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------

def fetch_pr_evidence(gh, number):
    """Compatibility wrapper around the modular PR evidence collector."""
    result = gh.pull_request_evidence(number)
    evidence = result["evidence"]

    evidence.setdefault("files", [])
    evidence.setdefault("reviews", [])
    evidence.setdefault("review_comments", [])
    evidence.setdefault("issue_comments", [])
    evidence.setdefault("timeline", [])
    evidence.setdefault("linked_issues", [])
    evidence.setdefault("check_runs", {"total_count": 0, "check_runs": []})
    evidence.setdefault("statuses", [])
    evidence.setdefault("codeowners_path", None)
    evidence.setdefault("codeowners_text", None)
    evidence["evidence_errors"] = dict(result.get("errors") or {})

    return evidence


def fetch_linked_issues(gh, pr_number, pr_body, timeline, limit=20):
    """
    Discover referenced GitHub issues and fetch their evidence.

    Reference extraction is delegated to references.py so textual and
    structured timeline references use the same canonical rules.
    """
    issues, peps, discussions = collect_issue_numbers(
        pr_number=pr_number,
        pr_body=pr_body,
        timeline=timeline,
        limit=limit,
    )

    if not issues:
        return [], peps, discussions

    linked_issues = gh.linked_issue_evidence_batch(
        issues,
        bot_logins=BOT_LOGINS,
    )
    return linked_issues, peps, discussions


# ---------------------------------------------------------------------------
# Diff helpers (kept for test compatibility)
# ---------------------------------------------------------------------------

def added_removed(patch):
    added, removed = [], []
    for line in (patch or "").splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    return "\n".join(added), "\n".join(removed)


def ast_findings(path, added):
    """Legacy AST analysis wrapper (used by test_triager.py)."""
    import ast as _ast
    if not path.endswith(".py") or not added.strip():
        return []
    try:
        tree = _ast.parse(added)
    except SyntaxError:
        return []
    findings = []
    for node in _ast.walk(tree):
        if (
            isinstance(node, _ast.Call)
            and isinstance(node.func, _ast.Name)
            and node.func.id in {"eval", "exec"}
        ):
            findings.append((node.func.id, getattr(node, "lineno", "?")))
        if isinstance(node, _ast.ExceptHandler) and node.type is None:
            findings.append(("bare-except", getattr(node, "lineno", "?")))
        if isinstance(node, _ast.Assert):
            findings.append(("assert", getattr(node, "lineno", "?")))
    return findings


def analyze_diff(files, base_file_contents=None):
    """Run deterministic analysis with optional base-file reconstruction."""
    enriched_files = []
    base_file_contents = base_file_contents or {}

    for file_data in files:
        enriched = dict(file_data)
        filename = enriched.get("filename")
        if isinstance(filename, str):
            base_text = base_file_contents.get(filename)
            if base_text is not None:
                enriched["base_text"] = base_text
        enriched_files.append(enriched)

    return _analyzers_module.analyze_files(enriched_files)


def file_signals(files):
    """Compatibility wrapper — delegates to policy.py."""
    return policy_file_signals(files)


# ---------------------------------------------------------------------------
# File / line statistics
# ---------------------------------------------------------------------------

def changed_lines(files):
    return (
        sum(int(f.get("additions", 0) or 0) for f in files),
        sum(int(f.get("deletions", 0) or 0) for f in files),
    )


# ---------------------------------------------------------------------------
# Historical statistics
# ---------------------------------------------------------------------------

def percentile(values, p):
    if not values:
        return None
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    k = (len(values) - 1) * p
    lo = int(k)
    hi = min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def historical_statistics(records):
    sizes = [r["additions"] + r["deletions"] for r in records]
    merged = [r for r in records if r["merged"]]
    return {
        "n": len(sizes),
        "p50": percentile(sizes, 0.50),
        "p75": percentile(sizes, 0.75),
        "p90": percentile(sizes, 0.90),
        "p95": percentile(sizes, 0.95),
        "median": median(sizes) if sizes else None,
        "merged": (
            historical_statistics(merged)
            if merged and len(merged) != len(records)
            else None
        ),
    }


def collect_historical_sample(gh, count, seed=0):
    """
    FIX (point 1): was calling gh.pull_sample() which didn't exist.
    Now correctly calls gh.pull_sample() which is implemented in github.py.
    """
    candidates = gh.pull_sample(max(count * 2, count))
    candidates = sorted(candidates, key=lambda x: int(x.get("number", 0)))

    if len(candidates) > count:
        step = len(candidates) / count
        selected = [
            candidates[min(int(i * step), len(candidates) - 1)]
            for i in range(count)
        ]
    else:
        selected = candidates

    records = []
    for idx, summary in enumerate(selected, 1):
        number = int(summary["number"])
        try:
            pr = gh.pr(number)
            records.append({
                "number": number,
                "state": pr.get("state"),
                "merged": bool(pr.get("merged_at")),
                "base": (pr.get("base") or {}).get("ref"),
                "additions": int(pr.get("additions", 0) or 0),
                "deletions": int(pr.get("deletions", 0) or 0),
                "changed_files": int(pr.get("changed_files", 0) or 0),
                "created_at": pr.get("created_at"),
                "merged_at": pr.get("merged_at"),
                "closed_at": pr.get("closed_at"),
                "labels": [
                    label.get("name")
                    for label in pr.get("labels", [])
                ],
                "title": pr.get("title", ""),
            })
        except Exception as exc:
            print(
                f"sample {idx}/{len(selected)}: PR #{number} skipped: {exc}",
                file=sys.stderr,
            )

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repo": REPO,
        "requested": count,
        "candidate_population": len(candidates),
        "collected": len(records),
        "sampling": {
            "endpoint": "/pulls?state=all&sort=created&direction=desc",
            "selection": (
                "deterministic systematic sample over PR numbers "
                "from the collected candidate population"
            ),
            "seed": seed,
            "note": (
                "Descriptive statistics only; not causal and not a "
                "complete representation of every CPython PR."
            ),
        },
        "statistics": historical_statistics(records),
        "label_frequency": Counter(
            label for record in records for label in record["labels"]
        ).most_common(),
        "base_branch_frequency": Counter(
            record["base"] for record in records
        ).most_common(),
        "records": records,
    }


# ---------------------------------------------------------------------------
# Label metadata
# ---------------------------------------------------------------------------

def label_metadata(gh):
    try:
        return {item.get("name"): item for item in gh.labels()}
    except Exception:
        return {}


def summarize_labels(labels, metadata):
    result = []
    for label in labels:
        hint = LABEL_HINTS.get(label)
        result.append({
            "name": label,
            "description": (metadata.get(label) or {}).get("description"),
            "triager_hint": hint[1] if hint else None,
            "hint_class": hint[0] if hint else None,
        })
    return result


# ---------------------------------------------------------------------------
# Compatibility wrappers for policy functions
# FIX (point 6): no longer defined here — imported from policy.py above.
# These thin wrappers exist only so test_triager.py can call
# triager.review_signals() without changes.
# ---------------------------------------------------------------------------

def review_signals(pr, timeline):
    return policy_review_signals(pr, timeline)


def branch_and_backport_signals(pr, labels):
    return policy_branch_signals(pr, labels)


def process_signals(pr, files, timeline, labels, patterns):
    return policy_process_signals(pr, files, timeline, labels, patterns)


def disposition(process, findings):
    return policy_disposition(process, findings)


# ---------------------------------------------------------------------------
# CI check summary
# ---------------------------------------------------------------------------

def build_checks(gh, pr, evidence=None):
    """
    Build a CI summary from the collected evidence when available.

    The optional ``evidence`` argument preserves the legacy two-argument
    API while allowing report assembly to reuse the original evidence
    snapshot without issuing duplicate GitHub requests.
    """
    head_sha = (pr.get("head") or {}).get("sha")
    if not head_sha:
        return {"available": False, "reason": "No PR head SHA."}

    evidence = evidence if isinstance(evidence, dict) else {}

    existing_check_runs = evidence.get("check_runs")
    existing_statuses = evidence.get("statuses")

    has_check_evidence = (
        isinstance(existing_check_runs, dict)
        and isinstance(existing_check_runs.get("check_runs"), list)
    )
    has_status_evidence = isinstance(existing_statuses, list)

    result = {
        "available": True,
        "head_sha": head_sha,
        "check_runs": (
            existing_check_runs.get("check_runs", [])
            if has_check_evidence
            else []
        ),
        "status": existing_statuses if has_status_evidence else None,
    }

    if not has_check_evidence:
        try:
            result["check_runs"] = gh.checks(head_sha)
        except Exception as exc:
            result["checks_error"] = str(exc)

    if not has_status_evidence:
        try:
            result["status"] = gh.statuses(head_sha)
        except Exception as exc:
            result["status_error"] = str(exc)

    conclusions = [
        item.get("conclusion")
        for item in result["check_runs"]
        if isinstance(item, dict) and item.get("status") == "completed"
    ]

    result["summary"] = {
        "check_runs": len(result["check_runs"]),
        "completed": sum(
            run.get("status") == "completed"
            for run in result["check_runs"]
            if isinstance(run, dict)
        ),
        "failures": sum(
            conclusion in {
                "failure",
                "timed_out",
                "cancelled",
                "action_required",
            }
            for conclusion in conclusions
        ),
        "successes": sum(
            conclusion in {"success", "neutral", "skipped"}
            for conclusion in conclusions
        ),
    }

    if isinstance(result["status"], dict):
        result["summary"]["legacy_status"] = result["status"].get("state")

    return result


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def make_report(gh, evidence, linked_issues, experts, patterns):
    files = evidence["files"]
    timeline = evidence["timeline"]
    labels = [
        item.get("name")
        for item in evidence["pr"].get("labels", [])
    ]

    findings, signatures = analyze_diff(
        files,
        evidence.get("base_file_contents"),
    )

    process, backports = policy_process_signals(
        evidence["pr"],
        files,
        timeline,
        labels,
        patterns,
    )

    evidence_errors = evidence.get("evidence_errors") or {}

    required_evidence = (
        "pr",
        "files",
        "timeline",
        "reviews",
        "review_comments",
        "issue_comments",
    )

    missing_evidence = [
        source
        for source in required_evidence
        if source != "pr"
        and (
            source in evidence_errors
            or evidence.get(source) is None
        )
    ]

    evidence_completeness = {
        "attempted": list(required_evidence),
        "available": [
            source
            for source in required_evidence
            if source not in missing_evidence
        ],
        "missing": missing_evidence,
        "errors": {
            source: str(evidence_errors[source])
            for source in evidence_errors
            if source in required_evidence
        },
    }

    report_disposition = policy_disposition(
        process,
        findings,
        evidence_completeness,
    )

    checks = build_checks(gh, evidence["pr"], evidence)

    return build_report(
        repository=REPO,
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        evidence=evidence,
        linked_issues=linked_issues,
        experts=experts,
        findings=findings,
        signatures=signatures,
        process=process,
        backports=backports,
        disposition=report_disposition,
        checks=checks,
        classify=classify,
        summarize_labels=summarize_labels,
        label_metadata=label_metadata,
        gh=gh,
    )


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

def print_report(report, quiet=False):
    pr = report["pr"]

    print("=" * 78)
    print(f"CPython PR Triager — #{pr['number']}")
    print("=" * 78)
    print(f"Title:       {pr['title']}")
    print(f"State:       {pr['state']}{' (merged)' if pr['merged'] else ''}")
    print(f"Author:      @{pr['author']}")
    print(f"Base:        {pr['base']}")
    print(f"Size:        +{pr['additions']} -{pr['deletions']} / {pr['changed_files']} files")
    print(f"Disposition: {report['disposition']}")

    print("\nProcess / Evidence Signals")
    for item in report["process_signals"]:
        print(f"  [{item['signal']}] {item['message']}")

    print("\nTechnical Findings")
    if report["technical_findings"]:
        for finding in report["technical_findings"]:
            print(
                f"  [{finding['severity']}] [{finding['confidence']}] "
                f"{finding['file']}: {finding['message']}"
            )
            refs = finding.get("evidence_refs") or []
            if refs:
                first = refs[0]
                observed = first.get("observed") or ""
                if observed:
                    print(f"      {observed[:120]}")
    else:
        print("  No heuristic findings triggered.")

    if report["experts"]:
        print("\nCODEOWNERS Routing")
        for expert in report["experts"]:
            print(f"  {expert['owner']} <- {expert['file']} ({expert['pattern']})")

    checks = report.get("checks", {})
    if checks.get("available"):
        summary = checks.get("summary", {})
        print("\nCI / Checks")
        print(f"  Check runs: {summary.get('check_runs', 0)}")
        print(f"  Completed:  {summary.get('completed', 0)}")
        print(f"  Successes:  {summary.get('successes', 0)}")
        print(f"  Failures:   {summary.get('failures', 0)}")
        if summary.get("legacy_status"):
            print(f"  Commit status: {summary['legacy_status']}")

    if not quiet:
        ec = report["evidence_counts"]
        print("\nEvidence Counts")
        print(f"  Timeline: {ec['timeline_events']} ({ec['human_timeline_events']} human)")
        print(f"  Reviews: {ec['reviews']} | inline: {ec['review_comments']}")
        print(f"  Issue comments: {ec['issue_comments']} | linked issues: {ec['linked_issues']}")
        print(f"  API calls: {ec['api_calls']} | cache hits: {ec['cache_hits']}")

    print("\nHeuristic findings are review prompts, not proof of defects.")
    print("Final decisions remain with CPython maintainers.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evidence-first CPython pull-request triager"
    )
    parser.add_argument("pr_number", nargs="?", type=int)
    parser.add_argument("--ai", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--patterns", help="Historical statistics JSON")
    parser.add_argument("--learn-patterns", type=int, metavar="N")
    parser.add_argument("--output-patterns")
    parser.add_argument(
        "--no-linked-issues",
        action="store_true",
        help="Skip fetching linked issue history (faster but less evidence)",
    )
    parser.add_argument("--no-cache", action="store_true")

    args = parser.parse_args()

    global CACHE_TTL
    if args.no_cache:
        CACHE_TTL = 0

    gh = GitHub()

    if args.learn_patterns is not None:
        if args.learn_patterns < 1:
            parser.error("--learn-patterns must be >= 1")

        print(f"Collecting a reproducible sample of {args.learn_patterns} PRs...")
        data = collect_historical_sample(gh, args.learn_patterns)

        if args.output_patterns:
            Path(args.output_patterns).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output_patterns).write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            print(f"Wrote {args.output_patterns}")
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))

        return

    if args.pr_number is None:
        parser.error("pr_number is required unless --learn-patterns is used")

    evidence = fetch_pr_evidence(gh, args.pr_number)
    pr = evidence["pr"]

    if args.no_linked_issues:
        # FIX (point 16): print an explicit warning instead of silently skipping.
        print(
            "Warning: --no-linked-issues is set. Issue history, PEP references, "
            "and discussion links will not be collected. The report may lack "
            "important context (e.g. security reasoning, DO-NOT-MERGE explanation).",
            file=sys.stderr,
        )
        linked, peps, discussions = [], [], []
    else:
        linked, peps, discussions = fetch_linked_issues(
            gh,
            args.pr_number,
            (pr.get("title") or "") + "\n" + (pr.get("body") or ""),
            evidence["timeline"],
        )

    base_sha = (pr.get("base") or {}).get("sha")
    codeowners_path = evidence.get("codeowners_path")
    codeowners_text = evidence.get("codeowners_text")

    rules = parse_codeowners(codeowners_text)
    experts = resolve_codeowners(
        rules,
        [f.get("filename", "") for f in evidence["files"]],
    )

    patterns = None
    if args.patterns:
        try:
            patterns = json.loads(
                Path(args.patterns).read_text(encoding="utf-8")
            )
        except Exception as exc:
            print(f"Warning: unable to read patterns: {exc}", file=sys.stderr)

    report = make_report(gh, evidence, linked, experts, patterns)

    report["references"] = {"peps": peps, "discussions": discussions}
    report["repository_metadata"] = {
        "codeowners_path": codeowners_path,
        "codeowners_rules": len(rules),
        "base_sha": base_sha,
    }

    if args.ai:
        # FIX (point 20): use the modular ai.synthesize() — not a local copy.
        try:
            report["ai_synthesis"] = ai_synthesize(
                report,
                api_key=ANTHROPIC_API_KEY or None,
            )
        except AISynthesisError as exc:
            report["ai_error"] = str(exc)

    if args.as_json:
        output = json.dumps(report, indent=2, ensure_ascii=False)
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        try:
            print(output)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(output.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
    else:
        print_report(report, quiet=args.quiet)

        if report.get("ai_synthesis"):
            ai = report["ai_synthesis"]
            print(
                f"\nAI synthesis: {ai.get('triage')} "
                f"(confidence {ai.get('confidence')}/5)"
            )
            print(ai.get("summary", ""))
            for question in ai.get("review_questions", []):
                print(f"  - {question}")


if __name__ == "__main__":
    main()