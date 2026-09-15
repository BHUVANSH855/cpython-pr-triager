from __future__ import annotations

import argparse
import copy
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
    build_review_state as policy_build_review_state,
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
from scripts.triager.report import (
    _build_evidence_completeness,
    build_report,
)
from scripts.triager.reviewer_activity import ReviewerActivityCache
from scripts.triager.snapshot import ReviewSnapshot

REPO = os.environ.get("CPYTHON_REPO", "python/cpython")
CACHE_DIR = Path(os.environ.get("CPYTHON_TRIAGER_CACHE", ".triager-cache"))
CACHE_TTL = int(os.environ.get("CPYTHON_TRIAGER_CACHE_TTL", "900"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

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
    """Compatibility wrapper around the canonical review snapshot."""
    snapshot = ReviewSnapshot.collect(gh, number)
    return snapshot.to_evidence()


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
        offset = seed % len(candidates)
        selected = [
            candidates[min((offset + int(i * step)) % len(candidates), len(candidates) - 1)]
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
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
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

def review_signals(pr, timeline, reviews=None, review_threads=None):
    return policy_review_signals(
        pr, timeline, reviews=reviews, review_threads=review_threads
    )


def branch_and_backport_signals(pr, labels):
    return policy_branch_signals(pr, labels)


def process_signals(pr, files, timeline, labels, patterns):
    return policy_process_signals(pr, files, timeline, labels, patterns)


def disposition(process, findings, evidence=None):
    return policy_disposition(process, findings, evidence)


# ---------------------------------------------------------------------------
# CI check summary
# ---------------------------------------------------------------------------

def _normalise_commit_status(value, head_sha=None):
    """Normalize /statuses output into combined-state evidence."""
    if isinstance(value, dict):
        state=value.get("state"); state=state.strip().lower() if isinstance(state,str) else None
        sha=value.get("sha") or value.get("head_sha")
        statuses=value.get("statuses") if isinstance(value.get("statuses"),list) else []
        return {"state": state or None, "sha": sha if isinstance(sha,str) and sha else None, "statuses": statuses}
    if not isinstance(value, list): return None
    statuses=[item for item in value if isinstance(item,dict)]
    shas={item.get("sha") for item in statuses if isinstance(item.get("sha"),str) and item.get("sha")}
    if not statuses: state=None
    else:
        states={str(item.get("state") or "").strip().lower() for item in statuses}
        if "failure" in states or "error" in states: state="failure"
        elif "pending" in states: state="pending"
        elif states <= {"success"}: state="success"
        else: state="unknown"
    sha=(next(iter(shas)) if len(shas)==1 else None)
    return {"state": state, "sha": sha, "statuses": statuses}


def _check_freshness(run, head_sha):
    run_sha=run.get("head_sha") or run.get("sha") if isinstance(run,dict) else None
    if not isinstance(run_sha,str) or not run_sha or not head_sha: return "unknown"
    return "fresh" if run_sha == head_sha else "stale"


def _normalise_requiredness(run, required_checks=None):
    """Classify a check run without allowing run metadata to override policy.

    When authoritative branch-protection/ruleset evidence is complete, that
    policy is the source of truth. A check-run's own ``required`` or
    ``requiredness`` field is not authoritative and must not be allowed to
    contradict it.

    When authoritative policy is unavailable or incomplete, explicit
    run-level metadata may still be preserved as a lower-confidence
    classification.
    """
    name = (
        (run.get("name") or run.get("check_run_name"))
        if isinstance(run, dict)
        else None
    )

    if not isinstance(name, str) or not name.strip():
        return "unknown"

    if isinstance(required_checks, dict):
        policy_status = str(
            required_checks.get("status") or ""
        ).strip().lower()

        policies = required_checks.get("required_checks")
        if policy_status == "complete" and isinstance(policies, list):
            for policy in policies:
                if not isinstance(policy, dict):
                    continue

                policy_name = policy.get("name")
                if (
                    isinstance(policy_name, str)
                    and policy_name == name
                ):
                    return "required"

            # Complete authoritative policy establishes that this named
            # check is not required if it is absent from the policy.
            return "optional"

    elif isinstance(required_checks, (set, frozenset, list, tuple)):
        for policy in required_checks:
            policy_name = (
                policy.get("name")
                if isinstance(policy, dict)
                else policy
            )
            if (
                isinstance(policy_name, str)
                and policy_name == name
            ):
                return "required"

        return "optional"

    # No complete authoritative policy is available. Preserve explicit
    # run-level metadata, but do not present it as authoritative policy.
    if isinstance(run, dict):
        raw = run.get("required")
        if isinstance(raw, bool):
            return "required" if raw else "optional"

        raw = run.get("requiredness")
        if isinstance(raw, str):
            raw = raw.strip().lower()
            if raw in {"required", "optional"}:
                return raw
            if raw in {"info", "informational"}:
                return "optional"

    return "unknown"


def _check_run_recency_key(run):
    """Return a deterministic ordering key for duplicate check runs.

    GitHub check-run responses contain timestamps and stable numeric IDs.
    Never rely on the order in which an API response happens to list runs.

    ``started_at`` is the primary signal because a newer rerun may still be
    pending. ``completed_at`` is a fallback for records without a start time,
    and the numeric check-run ID is the final deterministic tiebreaker.
    """
    if not isinstance(run, dict):
        return ("", "", -1)

    started_at = run.get("started_at")
    completed_at = run.get("completed_at")

    def normalise_timestamp(value):
        if not isinstance(value, str) or not value.strip():
            return ""

        try:
            parsed = dt.datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            return value

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)

        return parsed.astimezone(dt.timezone.utc).isoformat()

    run_id = run.get("id")
    if isinstance(run_id, bool):
        run_id = -1
    elif isinstance(run_id, int):
        pass
    elif isinstance(run_id, str):
        try:
            run_id = int(run_id)
        except ValueError:
            run_id = -1
    else:
        run_id = -1

    return (
        normalise_timestamp(started_at),
        normalise_timestamp(completed_at),
        run_id,
    )


def _latest_check_run(runs):
    """Select the newest check run deterministically.

    This intentionally does not prefer completed runs. A newer queued or
    in-progress rerun supersedes an older successful run for the purpose of
    determining the current CI state.
    """
    candidates = [
        run for run in runs
        if isinstance(run, dict)
    ]

    if not candidates:
        return None

    return max(candidates, key=_check_run_recency_key)


def _run_app_id(run):
    """Extract the check-run integration/app id when GitHub supplied it."""
    if not isinstance(run, dict):
        return None
    direct = run.get("app_id")
    if direct is not None:
        return direct
    app = run.get("app")
    if isinstance(app, dict):
        return app.get("id")
    return None


def _required_policy_records(required_checks):
    if not isinstance(required_checks, dict):
        return []
    values = required_checks.get("required_checks")
    if not isinstance(values, list):
        return []
    return [
        item for item in values
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and item.get("name").strip()
    ]


def _required_check_match(run, policy):
    """Return true/false/unknown for one run against one required rule."""
    if not isinstance(run, dict) or not isinstance(policy, dict):
        return False
    if run.get("name") != policy.get("name"):
        return False
    required_app = policy.get("integration_id")
    if required_app is None:
        return True
    actual_app = _run_app_id(run)
    if actual_app is None:
        return None
    return actual_app == required_app


def _legacy_status_matches(status, policy, head_sha):
    """Find a current-head legacy status matching a required context."""
    if not isinstance(status, dict) or not isinstance(policy, dict):
        return False
    statuses = status.get("statuses")
    if not isinstance(statuses, list):
        return False
    required_app = policy.get("integration_id")
    for item in statuses:
        if not isinstance(item, dict):
            continue
        if item.get("context") != policy.get("name"):
            continue
        sha = item.get("sha") or status.get("sha")
        if sha != head_sha:
            continue
        if required_app is not None:
            # Legacy commit statuses do not carry a check-run app identity.
            continue
        return True
    return False


def _evaluate_required_checks(runs, status, required_checks, head_sha):
    """Evaluate every authoritative required check without guessing absence."""
    policies = _required_policy_records(required_checks)
    policy_status = (
        str(required_checks.get("status") or "").lower()
        if isinstance(required_checks, dict) else ""
    )
    if not policies or policy_status != "complete":
        totals = Counter()
        for run in runs:
            if run.get("requiredness") != "required":
                continue
            freshness = run.get("freshness")
            if freshness == "stale":
                totals["required_stale"] += 1
                continue
            if freshness != "fresh":
                totals["required_unknown"] += 1
                continue
            if run.get("status") != "completed":
                totals["required_pending"] += 1
                continue
            conclusion = str(run.get("conclusion") or "").lower()
            if conclusion in {"success", "skipped", "neutral"}:
                totals["required_satisfied"] += 1
            elif conclusion == "failure":
                totals["required_failed"] += 1
            elif conclusion == "cancelled":
                totals["required_cancelled"] += 1
            elif conclusion == "action_required":
                totals["required_action_required"] += 1
            elif conclusion == "timed_out":
                totals["required_timed_out"] += 1
            elif conclusion == "stale":
                totals["required_stale"] += 1
            else:
                totals["required_unknown"] += 1
        totals["required_policy_complete"] = policy_status == "complete"
        return dict(totals)

    totals = Counter()
    for policy in policies:
        candidates = []
        unknown_match = False
        for run in runs:
            match = _required_check_match(run, policy)
            if match is True:
                candidates.append(run)
            elif match is None:
                unknown_match = True

        # A current-head legacy status can satisfy a context-only requirement.
        if _legacy_status_matches(status, policy, head_sha):
            candidates.append({
                "status": "completed",
                "conclusion": "success",
                "freshness": "fresh",
                "name": policy["name"],
                "source": "legacy_status",
            })

        current = [r for r in candidates if r.get("freshness") == "fresh"]
        stale = [r for r in candidates if r.get("freshness") == "stale"]

        if not current:
            unknown_freshness = any(
                r.get("freshness") == "unknown" for r in candidates
            )
            if unknown_match or unknown_freshness:
                totals["required_unknown"] += 1
            elif stale:
                totals["required_stale"] += 1
            else:
                totals["required_missing"] += 1
            continue

        # Select the newest current-head run deterministically.
        #
        # Do not prefer an older completed success over a newer pending
        # rerun. A rerun changes the effective CI state even when the older
        # run succeeded.
        selected = _latest_check_run(current)
        if selected.get("status") != "completed":
            totals["required_pending"] += 1
            continue

        conclusion = str(selected.get("conclusion") or "").lower()
        if conclusion in {"success", "skipped", "neutral"}:
            totals["required_satisfied"] += 1
        elif conclusion == "failure":
            totals["required_failed"] += 1
        elif conclusion == "cancelled":
            totals["required_cancelled"] += 1
        elif conclusion == "action_required":
            totals["required_action_required"] += 1
        elif conclusion == "timed_out":
            totals["required_timed_out"] += 1
        elif conclusion == "stale":
            totals["required_stale"] += 1
        else:
            totals["required_unknown"] += 1

    totals["required_policy_complete"] = True
    return dict(totals)


def build_checks(gh, pr, evidence=None):
    """Build CI evidence while preserving current-head and policy uncertainty."""
    head_sha = (pr.get("head") or {}).get("sha") if isinstance(pr, dict) else None
    if not head_sha:
        return {"available": False, "reason": "No PR head SHA."}

    evidence = evidence if isinstance(evidence, dict) else {}
    raw_container = evidence.get("check_runs")
    raw_status = evidence.get("statuses")
    required_checks = evidence.get("required_checks")
    have_runs = (
        isinstance(raw_container, dict)
        and isinstance(raw_container.get("check_runs"), list)
    )
    have_status = isinstance(raw_status, (dict, list))
    raw_runs = raw_container.get("check_runs", []) if have_runs else []

    def normalise(items):
        out = []
        for raw in items if isinstance(items, list) else []:
            if isinstance(raw, dict):
                run = dict(raw)
                run["freshness"] = _check_freshness(run, head_sha)
                run["requiredness"] = _normalise_requiredness(
                    run, required_checks
                )
                out.append(run)
        return out

    result = {
        "available": True,
        "head_sha": head_sha,
        "pr_head_sha": head_sha,
        "check_runs": normalise(raw_runs),
        "status": None,
    }
    if isinstance(raw_status, (dict, list)):
        result["status"] = _normalise_commit_status(raw_status, head_sha)
    if not have_runs:
        try:
            result["check_runs"] = normalise(gh.checks(head_sha))
        except Exception as exc:
            result["checks_error"] = str(exc)
    if not have_status:
        try:
            result["status"] = _normalise_commit_status(gh.statuses(head_sha), head_sha)
        except Exception as exc:
            result["status_error"] = str(exc)

    runs = result["check_runs"]
    values = [r["freshness"] for r in runs]
    freshness = (
        "unknown" if not runs
        else "stale" if "stale" in values
        else "fresh" if all(v == "fresh" for v in values)
        else "unknown"
    )
    result["ci_freshness"] = freshness
    result["ci_fresh"] = (
        True if freshness == "fresh"
        else False if runs
        else None
    )
    stale_shas = sorted({
        (r.get("head_sha") or r.get("sha"))
        for r in runs
        if r.get("freshness") == "stale"
        and (r.get("head_sha") or r.get("sha"))
    })
    if stale_shas:
        result["stale_check_shas"] = stale_shas

    completed = [r for r in runs if r.get("status") == "completed"]
    conclusions = [r.get("conclusion") for r in completed]
    failures = sum(c == "failure" for c in conclusions)
    timed_out = sum(c == "timed_out" for c in conclusions)
    cancelled = sum(c == "cancelled" for c in conclusions)
    action_required = sum(c == "action_required" for c in conclusions)
    successes = sum(c in {"success", "neutral", "skipped"} for c in conclusions)

    required_eval = _evaluate_required_checks(
        runs, result.get("status"), required_checks, head_sha
    )

    status = result.get("status")
    legacy = status.get("state") if isinstance(status, dict) else None
    status_sha = status.get("sha") if isinstance(status, dict) else None
    legacy_freshness = (
        "fresh" if status_sha == head_sha
        else "stale" if status_sha
        else "unknown"
    )
    result["legacy_status_freshness"] = legacy_freshness
    result["required_checks"] = required_checks
    result["summary"] = {
        "check_runs": len(runs),
        "completed": len(completed),
        "successes": successes,
        "failures": failures,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "action_required": action_required,
        "pending": len(runs) - len(completed),
        "required_failures": (
            required_eval.get("required_failed", 0)
            + required_eval.get("required_timed_out", 0)
            + required_eval.get("required_action_required", 0)
        ),
        "required_cancelled": required_eval.get("required_cancelled", 0),
        "required_pending": required_eval.get("required_pending", 0),
        "required_missing": required_eval.get("required_missing", 0),
        "required_stale": required_eval.get("required_stale", 0),
        "required_satisfied": required_eval.get("required_satisfied", 0),
        "required_unknown": required_eval.get("required_unknown", 0),
        "required_policy_complete": required_eval.get("required_policy_complete", False),
        "unknown_outcomes": sum(
            c not in {
                "success", "neutral", "skipped", "failure", "timed_out",
                "cancelled", "action_required", "stale",
            }
            for c in conclusions
        ),
        "unknown_requiredness": sum(
            r.get("requiredness") == "unknown" for r in runs
        ),
        "pr_head_sha": head_sha,
        "ci_fresh": result["ci_fresh"],
        "ci_freshness": freshness,
        "legacy_status": legacy,
        "legacy_status_freshness": legacy_freshness,
    }
    return result

def mergeability_signals(pr, checks):
    """Convert CI evidence to conservative mergeability signals."""
    if not isinstance(checks, dict):
        return [("WARN", "CI/check evidence is unavailable; mergeability could not be determined.")]
    if not checks.get("available"):
        return [("WARN", f"Mergeability could not be determined: {checks.get('reason') or 'CI/check evidence is unavailable.'}")]

    signals = []
    summary = checks.get("summary") or {}
    freshness = checks.get("ci_freshness")
    if freshness is None and checks.get("ci_fresh") is False:
        freshness = "stale"
    if freshness == "stale":
        signals.append(("WARN", "STALE CI: some check runs belong to a different commit than the current PR head; re-verify before trusting CI."))
    elif freshness == "unknown":
        signals.append(("WARN", "CI freshness is unverified: no returned check run set or at least one run lacks a verifiable head SHA."))
    if checks.get("checks_error"):
        signals.append(("WARN", f"CI check-run evidence could not be collected: {checks['checks_error']}"))
    if checks.get("status_error"):
        signals.append(("WARN", f"Legacy commit-status evidence could not be collected: {checks['status_error']}"))

    required_missing = int(summary.get("required_missing", 0) or 0)
    required_stale = int(summary.get("required_stale", 0) or 0)
    required_failures = int(summary.get("required_failures", 0) or 0)
    required_cancelled = int(summary.get("required_cancelled", 0) or 0)
    required_pending = int(summary.get("required_pending", 0) or 0)
    required_unknown = int(summary.get("required_unknown", 0) or 0)
    failures = int(summary.get("failures", 0) or 0)
    pending = int(summary.get("pending", 0) or 0)
    unknown = int(summary.get("unknown_requiredness", 0) or 0)

    if required_missing:
        signals.append(("BLOCK", f"{required_missing} required CI check(s) have no current-head result; required checks must run and pass before merge."))
    if required_stale:
        signals.append(("BLOCK", f"{required_stale} required CI check(s) have only stale results; a current-head result is required."))
    if required_failures:
        signals.append(("BLOCK", f"{required_failures} required CI check(s) failed or timed out; resolve or explicitly explain them before merge."))
    if required_cancelled:
        signals.append(("BLOCK", f"{required_cancelled} required CI check(s) were cancelled; a successful current-head result is required."))
    if required_pending:
        signals.append(("WARN", f"{required_pending} required CI check(s) are incomplete; mergeability is not settled."))
    if required_unknown:
        signals.append(("WARN", f"{required_unknown} required CI check(s) could not be classified from the available evidence."))
    if failures > required_failures:
        signals.append(("INFO", f"{failures - required_failures} CI failure(s) are not established as required; they are not treated as merge blockers."))
    if unknown and failures:
        signals.append(("WARN", f"{unknown} check(s) have unknown requiredness; failures are not promoted to BLOCK without authoritative branch-policy evidence."))
    if pending and not required_pending:
        signals.append(("WARN", f"{pending} CI check(s) are incomplete; verify requiredness before treating mergeability as settled."))

    legacy = summary.get("legacy_status")
    if isinstance(legacy, str) and legacy.lower() in {"failure", "error"}:
        signals.append(("WARN", f"Legacy commit status is {legacy.lower()}; verify current-head association and requiredness before treating it as a merge blocker."))
    elif isinstance(legacy, str) and legacy.lower() == "pending":
        signals.append(("WARN", "Legacy commit status is pending; mergeability is not settled."))

    if not signals:
        if not summary.get("check_runs") and not legacy:
            signals.append(("WARN", "No CI check runs or legacy commit status were available; mergeability could not be established from the supplied evidence."))
        else:
            signals.append(("OK", "Available CI/check evidence contains no established required failure."))
    return signals


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def make_report(gh, evidence, linked_issues, experts, patterns, reviewer_activity_cache=None):
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
        reviews=evidence.get("reviews"),
        review_threads=evidence.get("review_threads"),
    )

    review_state = policy_build_review_state(
        evidence["pr"],
        reviews=evidence.get("reviews"),
        timeline=timeline,
        review_threads=evidence.get("review_threads"),
    )

    # Build CI evidence before disposition so readiness decisions are based
    # on the same collected evidence that is exposed in the final report.
    #
    # ``build_checks`` reuses the existing snapshot and therefore must not
    # issue duplicate GitHub requests when the evidence already contains
    # check-runs/status data.
    checks = build_checks(
        gh,
        evidence["pr"],
        evidence,
    )

    # CI/mergeability signals are part of the deterministic process evidence
    # used by disposition. A blocker must remain a blocker; missing evidence
    # must never be silently converted into READY.
    process.extend(
        mergeability_signals(
            evidence["pr"],
            checks,
        )
    )

    evidence_completeness = _build_evidence_completeness(
        evidence
    )

    report_disposition = policy_disposition(
        process,
        findings,
        evidence_completeness,
    )

    report = build_report(
        repository=REPO,
        generated_at=dt.datetime.now(dt.UTC).isoformat(),
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
        reviewer_activity_cache=reviewer_activity_cache,
    )
    report["review_state"] = review_state
    return report


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
        print(f"  [{item['level']}] {item['message']}")

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

    expert_contexts = report.get("expert_contexts") or []
    experts_plain = report.get("experts") or []
    if expert_contexts or experts_plain:
        print("\nCODEOWNERS Routing & Reviewer Profiles")
        display = expert_contexts if expert_contexts else experts_plain
        for expert in display:
            owner = expert.get("owner", "?")
            file_ = expert.get("file", "?")
            pattern = expert.get("pattern", "?")
            subsystems = expert.get("subsystems") or []
            sub_str = f" [{', '.join(subsystems[:3])}]" if subsystems else ""
            print(f"  {owner} <- {file_} ({pattern}){sub_str}")
            # Generic subsystem review checklist. NOT a record of anything
            # this person has actually said — see reviewer_profiles.py.
            checklist = (expert.get("known_concerns") or [])[:3]
            if checklist:
                print("    Subsystem review checklist (generic, not attributed quotes):")
                for item in checklist:
                    print(f"      - {item}")
            # Co-owners suggestion
            co = expert.get("co_owners") or []
            if co:
                print(f"    Co-owners: {', '.join('@' + c for c in co[:4])}")
            # Dynamic, evidence-based activity for THIS specific person,
            # computed live from their real recent GitHub review comments.
            dynamic_concerns = expert.get("dynamic_concerns") or []
            if dynamic_concerns:
                print(f"    Observed in their recent reviews: {', '.join(dynamic_concerns[:3])}")
            rate = expert.get("approval_rate")
            n = expert.get("approval_rate_sample_size") or 0
            resp = expert.get("typical_response_days")
            if expert.get("activity_unavailable"):
                reason = expert.get("activity_error") or "unknown error"
                print(f"    Activity: UNAVAILABLE (collection failed: {reason}) — this is NOT evidence of zero activity.")
            elif rate is not None or resp is not None or n:
                parts = []
                if rate is not None:
                    parts.append(f"approval rate {rate:.0%} (n={n}, from recent live activity)")
                elif n:
                    parts.append(f"approval rate: insufficient sample (n={n})")
                if resp is not None:
                    parts.append(f"~{resp:.0f}d median response (from recent live activity)")
                print(f"    Activity: {' | '.join(parts)}")

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
        ci_fresh = summary.get("ci_fresh")
        pr_head = summary.get("pr_head_sha")
        if ci_fresh is True:
            print(f"  Freshness:  FRESH — all returned checks match PR head {pr_head}")
        elif ci_fresh is False:
            print(f"  Freshness:  STALE — some checks do NOT match PR head {pr_head}; re-verify before trusting this CI result")
        elif pr_head:
            print(f"  Freshness:  unknown (no check runs returned for head {pr_head})")

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
    parser.add_argument(
        "--ai-provider",
        choices=("anthropic", "gemini", "mock"),
        default=os.environ.get("AI_PROVIDER", "anthropic"),
        help=(
            "AI provider to use when --ai is enabled "
            "(default: AI_PROVIDER or anthropic)"
        ),
    )
    parser.add_argument(
        "--ai-model",
        default=None,
        help=(
            "AI model to use when --ai is enabled "
            "(default: AI_MODEL or the selected provider's default)"
        ),
    )
    parser.add_argument(
        "--ai-timeout",
        type=float,
        default=None,
        help=(
            "AI request timeout in seconds "
            "(default: AI_TIMEOUT or the selected provider's default)"
        ),
    )
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

    if args.ai_timeout is not None and args.ai_timeout <= 0:
        parser.error("--ai-timeout must be greater than 0")

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

    # Build reviewer activity cache — fetches from GitHub, falls back gracefully
    reviewer_activity_cache = ReviewerActivityCache(gh)

    evidence["linked_issue_collection"] = {"status": "NOT_COLLECTED" if args.no_linked_issues else "COLLECTED", "reason": "--no-linked-issues" if args.no_linked_issues else None}
    report = make_report(gh, evidence, linked, experts, patterns, reviewer_activity_cache)

    report["references"] = {"peps": peps, "discussions": discussions}
    report["repository_metadata"] = {
        "codeowners_path": codeowners_path,
        "codeowners_rules": len(rules),
        "base_sha": base_sha,
        "codeowners_provenance": {
            "revision": base_sha,
            "path": codeowners_path,
            "status": "available" if codeowners_path and codeowners_text is not None else "unavailable",
        },
    }

    if args.ai:
        # AI remains downstream of deterministic evidence and disposition.
        # Configuration is explicit CLI input when supplied; otherwise ai.py
        # resolves the corresponding environment/provider defaults.
        try:
            ai_input = copy.deepcopy(report)
            ai_input.pop("ai_synthesis", None)
            ai_input.pop("ai_error", None)
            report["ai_synthesis"] = ai_synthesize(
                ai_input,
                provider=args.ai_provider,
                model=args.ai_model,
                timeout=args.ai_timeout,
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
        elif report.get("ai_error"):
            print("\nAI synthesis: unavailable")
            print(f"Reason: {report['ai_error']}")


if __name__ == "__main__":
    main()
