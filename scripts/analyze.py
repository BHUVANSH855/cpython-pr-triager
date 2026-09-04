from __future__ import annotations

import argparse
import ast
import base64
import datetime as dt
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median

from scripts.triager.github import GitHub as TriagerGitHub
from scripts.triager.references import (
    collect_issue_numbers,
    issue_refs_from_timeline as extract_timeline_issue_refs,
)

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
BACKPORT_LABEL_RE = re.compile(
    r"^needs backport to (\d+\.\d+)$",
    re.I,
)

# Legacy issue-reference syntax retained for compatibility with the existing
# analyzer and tests. The modular references layer is used for the actual
# linked-reference workflow.
LEGACY_ISSUE_REF_RE = re.compile(
    r"(?:\bgh-|#|fix(?:es|ed)?\s+#|close(?:s|d)?\s+#|resolve(?:s|d)?\s+#)(\d{3,7})",
    re.I,
)

PEP_RE = re.compile(
    r"\bpep[- ]?(\d{3,4})\b",
    re.I,
)

DISCUSS_RE = re.compile(
    r"https?://(?:www\.)?discuss\.python\.org/t/[^\s)>]+",
    re.I,
)

LAYOUT = [
    (r"^Python/ceval\.c$", "interpreter-core", "core/eval-loop", "Lib/test/test_ceval.py"),
    (r"^Python/bytecodes\.c$", "interpreter-core", "core/bytecodes", None),
    (r"^Python/compile\.c$", "interpreter-core", "core/compiler", "Lib/test/test_compile.py"),
    (r"^Python/ast", "interpreter-core", "core/ast", "Lib/test/test_ast/"),
    (r"^Python/gc\.c$", "interpreter-core", "core/gc", "Lib/test/test_gc.py"),
    (r"^Python/import\.c$", "interpreter-core", "core/import", "Lib/test/test_import/"),
    (r"^Python/", "interpreter-core", "core/python", None),
    (r"^Objects/dictobject", "interpreter-core", "objects/dict", "Lib/test/test_dict.py"),
    (r"^Objects/typeobject", "interpreter-core", "objects/type", "Lib/test/test_type.py"),
    (r"^Objects/unicodeobject", "interpreter-core", "objects/unicode", "Lib/test/test_unicode.py"),
    (r"^Objects/listobject", "interpreter-core", "objects/list", "Lib/test/test_list.py"),
    (r"^Objects/", "interpreter-core", "objects", None),
    (r"^Modules/_ssl", "extension-modules", "modules/ssl", "Lib/test/test_ssl.py"),
    (r"^Modules/_sqlite/", "extension-modules", "modules/sqlite", "Lib/test/test_sqlite3/"),
    (r"^Modules/", "extension-modules", "modules", None),
    (r"^Lib/asyncio/", "stdlib", "asyncio", "Lib/test/test_asyncio/"),
    (r"^Lib/typing\.py$", "stdlib", "typing", "Lib/test/test_typing.py"),
    (r"^Lib/dataclasses", "stdlib", "dataclasses", "Lib/test/test_dataclasses/"),
    (r"^Lib/pathlib/", "stdlib", "pathlib", "Lib/test/test_pathlib/"),
    (r"^Lib/importlib/", "stdlib", "importlib", "Lib/test/test_importlib/"),
    (r"^Lib/", "stdlib", "stdlib", None),
    (r"^Include/internal/", "c-api", "internal", None),
    (r"^Include/cpython/", "c-api", "cpython", None),
    (r"^Include/", "c-api", "public", None),
    (r"^Misc/stable_abi", "c-api", "stable-abi", None),
    (r"^Misc/NEWS\.d/", "release", "news", None),
    (r"^Grammar/", "interpreter-core", "grammar", None),
    (r"^Parser/", "interpreter-core", "parser", None),
    (r"^Doc/", "documentation", "docs", None),
    (r"^Tools/clinic/", "tools", "clinic", None),
    (r"^PC/|^PCbuild/", "platform", "windows", None),
    (r"^Mac/|^Platforms/Apple/", "platform", "macos", None),
    (r"^configure", "build", "configure", None),
]

C_CHECKS = [
    (
        r"\bgets\s*\(",
        "CRITICAL",
        "high",
        "gets() is unsafe; inspect the added code immediately.",
    ),
    (
        r"\bstrcpy\s*\(",
        "HIGH",
        "medium",
        "strcpy() was introduced; inspect bounds handling and CPython conventions.",
    ),
    (
        r"\bstrcat\s*\(",
        "HIGH",
        "medium",
        "strcat() was introduced; inspect bounds handling.",
    ),
    (
        r"\bsprintf\s*\(",
        "MEDIUM",
        "medium",
        "sprintf() was introduced; verify whether a bounded CPython/API alternative is appropriate.",
    ),
    (
        r"\b_Py_[A-Za-z]\w*",
        "MEDIUM",
        "medium",
        "A private _Py_* API is used; verify layer/ownership/API expectations.",
    ),
    (
        r"\bPyErr_Clear\s*\(",
        "MEDIUM",
        "medium",
        "PyErr_Clear() discards an exception; verify that the error is intentionally handled.",
    ),
    (
        r"\bPy_BEGIN_ALLOW_THREADS\b",
        "MEDIUM",
        "medium",
        "Thread-state/GIL boundary changed; inspect object lifetime and error paths.",
    ),
    (
        r"\bPy_END_ALLOW_THREADS\b",
        "MEDIUM",
        "medium",
        "Thread-state/GIL boundary changed; inspect object lifetime and error paths.",
    ),
]

PY_CHECKS = [
    (
        r"except\s*:",
        "MEDIUM",
        "medium",
        "Bare except catches BaseException; verify this is intentional.",
    ),
    (
        r"\bassert\s+",
        "MEDIUM",
        "medium",
        "assert can be disabled with -O; verify it is not enforcing runtime correctness.",
    ),
    (
        r"\bglobal\s+\w",
        "LOW",
        "medium",
        "Global mutable state changed; inspect concurrency/lifecycle implications.",
    ),
]

SEC_CHECKS = [
    (
        r"\beval\s*\(",
        "HIGH",
        "medium",
        "eval() was introduced; verify the input trust boundary.",
    ),
    (
        r"\bexec\s*\(",
        "HIGH",
        "medium",
        "exec() was introduced; verify the input trust boundary.",
    ),
    (
        r"\bpickle\.(?:load|loads)\s*\(",
        "HIGH",
        "medium",
        "pickle loading was introduced; verify that the serialized data is trusted.",
    ),
    (
        r"\bshell\s*=\s*True",
        "HIGH",
        "medium",
        "subprocess shell=True was introduced; inspect command construction and input flow.",
    ),
    (
        r"\btempfile\.mktemp\s*\(",
        "HIGH",
        "high",
        "mktemp() is race-prone; inspect whether a safe temporary-file API is required.",
    ),
]


@dataclass
class Finding:
    severity: str
    category: str
    file: str
    message: str
    confidence: str
    evidence: str
    source: str = "deterministic"

    def as_dict(self):
        return asdict(self)


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso_age_days(value):
    if not value:
        return None

    try:
        return (
            now_utc()
            - dt.datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        ).total_seconds() / 86400
    except ValueError:
        return None


def is_bot(login):
    return login in BOT_LOGINS or login.endswith("[bot]")


class GitHub(TriagerGitHub):
    """Compatibility wrapper around the modular GitHub client."""

    def __init__(self, token=GITHUB_TOKEN):
        super().__init__(
            token=token,
            cache_dir=CACHE_DIR,
            cache_ttl=CACHE_TTL,
        )

    def checks(self, ref):
        return super().check_runs(ref).get(
            "check_runs",
            [],
        )


def classify(path):
    for pattern, component, subsystem, expected_test in LAYOUT:
        if re.search(pattern, path):
            return (
                component,
                subsystem,
                expected_test,
            )

    return (
        path.split("/")[0]
        if "/" in path
        else "root",
        "unknown",
        None,
    )


def parse_codeowners(text):
    rules = []

    for lineno, raw in enumerate(
        (text or "").splitlines(),
        1,
    ):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        line = re.split(
            r"\s+#",
            line,
            maxsplit=1,
        )[0].strip()

        parts = line.split()

        if len(parts) < 2:
            continue

        pattern, owners = parts[0], parts[1:]

        rules.append(
            {
                "line": lineno,
                "pattern": pattern,
                "owners": owners,
            }
        )

    return rules


def codeowners_regex(pattern):
    if any(
        ch in pattern
        for ch in "[]!"
    ):
        return None

    anchored = pattern.startswith("/")
    p = pattern.lstrip("/")
    directory = p.endswith("/")

    if directory:
        p = p.rstrip("/") + "/**"

    if "/" not in p:
        prefix = r"^(?:.*/)?"
    elif anchored:
        prefix = r"^"
    else:
        prefix = r"^(?:.*/)?"

    i = 0
    out = []

    while i < len(p):
        ch = p[i]

        if ch == "*":
            if (
                i + 1 < len(p)
                and p[i + 1] == "*"
            ):
                i += 1

                if (
                    i + 1 < len(p)
                    and p[i + 1] == "/"
                ):
                    i += 1
                    out.append(
                        r"(?:.*/)?"
                    )
                else:
                    out.append(
                        r".*"
                    )
            else:
                out.append(
                    r"[^/]*"
                )

        elif ch == "?":
            out.append(
                r"[^/]"
            )
        else:
            out.append(
                re.escape(ch)
            )

        i += 1

    return re.compile(
        prefix
        + "".join(out)
        + r"$"
    )


def codeowners_match(pattern, path):
    rx = codeowners_regex(
        pattern
    )

    return bool(
        rx
        and rx.match(
            path.lstrip("/")
        )
    )


def resolve_codeowners(
    rules,
    filenames,
):
    results = []

    for fname in filenames:
        matched = None

        for rule in rules:
            if codeowners_match(
                rule["pattern"],
                fname,
            ):
                matched = rule

        if matched:
            for owner in matched["owners"]:
                results.append(
                    {
                        "owner": owner,
                        "file": fname,
                        "pattern": matched["pattern"],
                        "line": matched["line"],
                    }
                )

    return results


def extract_refs(text):
    """Compatibility wrapper preserving legacy reference semantics."""

    text = text or ""

    issues = sorted(
        {
            int(number)
            for number in LEGACY_ISSUE_REF_RE.findall(
                text
            )
        }
    )

    peps = sorted(
        {
            int(number)
            for number in PEP_RE.findall(
                text
            )
        }
    )

    discussions = sorted(
        set(
            DISCUSS_RE.findall(
                text
            )
        )
    )

    return (
        issues,
        peps,
        discussions,
    )


def issue_refs_from_timeline(timeline):
    return extract_timeline_issue_refs(
        timeline
    )


def fetch_pr_evidence(
    gh,
    number,
):
    pr = gh.pr(number)
    files = gh.files(number)
    reviews = gh.reviews(number)
    review_comments = gh.review_comments(number)
    issue_comments = gh.issue_comments(number)
    timeline_raw = gh.timeline(number)

    events = []

    for ev in timeline_raw:
        actor = (
            ev.get("actor") or {}
        ).get(
            "login",
            "?",
        )

        kind = ev.get(
            "event",
            "",
        )

        if kind in {
            "labeled",
            "unlabeled",
            "milestoned",
            "demilestoned",
            "closed",
            "reopened",
            "merged",
            "cross-referenced",
            "review_requested",
            "review_request_removed",
            "assigned",
            "unassigned",
            "head_ref_deleted",
            "committed",
            "base_ref_changed",
        }:
            events.append(
                {
                    "kind": kind,
                    "login": actor,
                    "date": ev.get(
                        "created_at",
                        "",
                    ),
                    "bot": is_bot(
                        actor
                    ),
                    "event": ev,
                }
            )

    for comment in issue_comments:
        login = (
            comment.get("user") or {}
        ).get(
            "login",
            "?",
        )

        events.append(
            {
                "kind": "comment",
                "login": login,
                "date": comment.get(
                    "created_at",
                    "",
                ),
                "bot": is_bot(
                    login
                ),
                "body": comment.get(
                    "body"
                ) or "",
            }
        )

    for review in reviews:
        login = (
            review.get("user") or {}
        ).get(
            "login",
            "?",
        )

        events.append(
            {
                "kind": "review",
                "login": login,
                "date": (
                    review.get(
                        "submitted_at"
                    )
                    or review.get(
                        "updated_at"
                    )
                    or ""
                ),
                "bot": is_bot(
                    login
                ),
                "body": review.get(
                    "body"
                ) or "",
                "state": review.get(
                    "state",
                    "",
                ),
            }
        )

    for comment in review_comments:
        login = (
            comment.get("user") or {}
        ).get(
            "login",
            "?",
        )

        events.append(
            {
                "kind": "inline",
                "login": login,
                "date": comment.get(
                    "created_at",
                    "",
                ),
                "bot": is_bot(
                    login
                ),
                "body": comment.get(
                    "body"
                ) or "",
                "path": comment.get(
                    "path",
                    "",
                ),
                "line": comment.get(
                    "line"
                ),
            }
        )

    events.sort(
        key=lambda item: item.get(
            "date",
            "",
        )
    )

    return {
        "pr": pr,
        "files": files,
        "reviews": reviews,
        "review_comments": review_comments,
        "issue_comments": issue_comments,
        "timeline": events,
    }


def fetch_linked_issues(
    gh,
    pr_number,
    pr_body,
    timeline,
    limit=20,
):
    """Use modular reference discovery and GitHub evidence retrieval."""

    text_parts = [
        pr_body or ""
    ]

    for event in timeline:
        if not event.get("bot"):
            text_parts.append(
                event.get(
                    "body",
                    "",
                )
            )

    combined_text = "\n".join(
        text_parts
    )

    nums, peps, discussions = (
        collect_issue_numbers(
            pr_number=pr_number,
            pr_body=combined_text,
            timeline=timeline,
            limit=limit,
        )
    )

    if not nums:
        return (
            [],
            peps,
            discussions,
        )

    issues = (
        gh.linked_issue_evidence_batch(
            nums,
            bot_logins=BOT_LOGINS,
        )
    )

    return (
        issues,
        peps,
        discussions,
    )


def added_removed(patch):
    added = []
    removed = []

    for line in (patch or "").splitlines():
        if line.startswith(
            ("+++", "---")
        ):
            continue

        if line.startswith("+"):
            added.append(
                line[1:]
            )
        elif line.startswith("-"):
            removed.append(
                line[1:]
            )

    return (
        "\n".join(added),
        "\n".join(removed),
    )


def ast_findings(
    path,
    added,
):
    if (
        not path.endswith(".py")
        or not added.strip()
    ):
        return []

    try:
        tree = ast.parse(
            added
        )
    except SyntaxError:
        return []

    findings = []

    for node in ast.walk(tree):
        if (
            isinstance(
                node,
                ast.Call,
            )
            and isinstance(
                node.func,
                ast.Name,
            )
        ):
            if node.func.id in {
                "eval",
                "exec",
            }:
                findings.append(
                    (
                        node.func.id,
                        getattr(
                            node,
                            "lineno",
                            "?",
                        ),
                    )
                )

        if (
            isinstance(
                node,
                ast.ExceptHandler,
            )
            and node.type is None
        ):
            findings.append(
                (
                    "bare-except",
                    getattr(
                        node,
                        "lineno",
                        "?",
                    ),
                )
            )

        if isinstance(
            node,
            ast.Assert,
        ):
            findings.append(
                (
                    "assert",
                    getattr(
                        node,
                        "lineno",
                        "?",
                    ),
                )
            )

    return findings


def analyze_diff(files):
    findings = []
    signature_changes = []

    for file_data in files:
        path = file_data.get(
            "filename",
            "",
        )

        patch = file_data.get(
            "patch"
        ) or ""

        if not patch:
            continue

        added, removed = added_removed(
            patch
        )

        is_c = path.endswith(
            (
                ".c",
                ".h",
                ".cc",
                ".cpp",
                ".m",
            )
        )

        is_py = path.endswith(
            ".py"
        )

        is_test = (
            path.startswith(
                "Lib/test/"
            )
            or "/test/" in path
            or Path(path).name.startswith(
                "test_"
            )
        )

        checks = []

        if is_c:
            checks.extend(
                C_CHECKS
            )

        if (
            is_py
            and not is_test
        ):
            checks.extend(
                PY_CHECKS
            )

        checks.extend(
            SEC_CHECKS
        )

        for (
            pattern,
            severity,
            confidence,
            message,
        ) in checks:
            match = re.search(
                pattern,
                added,
                re.MULTILINE,
            )

            if match:
                findings.append(
                    Finding(
                        severity,
                        "STATIC",
                        path,
                        message,
                        confidence,
                        f"Added diff line matched {pattern!r}.",
                    )
                )

        if is_py:
            for kind, line in ast_findings(
                path,
                added,
            ):
                if kind == "eval":
                    findings.append(
                        Finding(
                            "HIGH",
                            "AST",
                            path,
                            "AST analysis confirms a newly added eval() call; verify the trust boundary.",
                            "medium",
                            f"Added Python syntax contains eval() near line {line}.",
                        )
                    )

                elif kind == "exec":
                    findings.append(
                        Finding(
                            "HIGH",
                            "AST",
                            path,
                            "AST analysis confirms a newly added exec() call; verify the trust boundary.",
                            "medium",
                            f"Added Python syntax contains exec() near line {line}.",
                        )
                    )

        if path.startswith(
            "Grammar/"
        ):
            findings.append(
                Finding(
                    "HIGH",
                    "GRAMMAR",
                    path,
                    "Grammar files changed; verify generated/parser artifacts and parser tests.",
                    "high",
                    "Changed path is under Grammar/.",
                )
            )

        if (
            re.match(
                r"^Include/(?!internal/|cpython/)",
                path,
            )
            and path.endswith(".h")
        ):
            findings.append(
                Finding(
                    "HIGH",
                    "ABI",
                    path,
                    "Public C header changed; explicitly review API/ABI compatibility and Stable ABI impact.",
                    "high",
                    "Changed path is a public Include/*.h header.",
                )
            )

        old = {
            match.group(1): match.group(2).strip()
            for match in re.finditer(
                r"^\s*def\s+(\w+)\s*\(([^)]*)\)",
                removed,
                re.M,
            )
        }

        new = {
            match.group(1): match.group(2).strip()
            for match in re.finditer(
                r"^\s*def\s+(\w+)\s*\(([^)]*)\)",
                added,
                re.M,
            )
        }

        for name in sorted(
            set(old)
            & set(new)
        ):
            if (
                old[name] != new[name]
                and not name.startswith("_")
            ):
                signature_changes.append(
                    {
                        "function": name,
                        "file": path,
                        "old": old[name],
                        "new": new[name],
                    }
                )

                findings.append(
                    Finding(
                        "MEDIUM",
                        "API",
                        path,
                        f"Public-looking Python signature changed for {name}(); review compatibility.",
                        "medium",
                        f"Old: {old[name]} | New: {new[name]}",
                    )
                )

    for file_data in files:
        path = file_data.get(
            "filename",
            "",
        )

        if not path.endswith(
            (
                ".c",
                ".h",
                ".cc",
                ".cpp",
            )
        ):
            continue

        added, _ = added_removed(
            file_data.get(
                "patch"
            ) or ""
        )

        inc = len(
            re.findall(
                r"\bPy_INCREF\s*\(",
                added,
            )
        )

        dec = len(
            re.findall(
                r"\bPy_(?:X)?DECREF\s*\(",
                added,
            )
        )

        if inc >= dec + 3:
            findings.append(
                Finding(
                    "LOW",
                    "REFCOUNT",
                    path,
                    f"Added diff contains {inc} INCREF vs {dec} DECREF operations; inspect ownership paths manually.",
                    "low",
                    "Local diff counts cannot prove a leak or missing DECREF.",
                )
            )

    unique = {}

    for finding in findings:
        unique[
            (
                finding.severity,
                finding.category,
                finding.file,
                finding.message,
            )
        ] = finding

    findings = list(
        unique.values()
    )

    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(
                finding.severity,
                99,
            ),
            CONFIDENCE_ORDER.get(
                finding.confidence,
                99,
            ),
            finding.file,
        )
    )

    return (
        findings,
        signature_changes,
    )


def file_signals(files):
    names = [
        f.get(
            "filename",
            "",
        )
        for f in files
    ]

    tests = [
        name
        for name in names
        if (
            name.startswith(
                "Lib/test/"
            )
            or "/test/" in name
            or Path(name).name.startswith(
                "test_"
            )
        )
    ]

    news = [
        name
        for name in names
        if name.startswith(
            "Misc/NEWS.d/"
        )
    ]

    docs = [
        name
        for name in names
        if name.startswith(
            "Doc/"
        )
    ]

    return (
        names,
        tests,
        news,
        docs,
    )


def changed_lines(files):
    return (
        sum(
            int(
                file_data.get(
                    "additions",
                    0,
                )
                or 0
            )
            for file_data in files
        ),
        sum(
            int(
                file_data.get(
                    "deletions",
                    0,
                )
                or 0
            )
            for file_data in files
        ),
    )


def percentile(
    values,
    p,
):
    if not values:
        return None

    values = sorted(
        values
    )

    if len(values) == 1:
        return values[0]

    k = (
        len(values) - 1
    ) * p

    lo = int(k)
    hi = min(
        int(k) + 1,
        len(values) - 1,
    )

    return (
        values[lo]
        + (
            values[hi]
            - values[lo]
        )
        * (
            k
            - lo
        )
    )


def historical_statistics(records):
    sizes = [
        record["additions"]
        + record["deletions"]
        for record in records
    ]

    merged = [
        record
        for record in records
        if record["merged"]
    ]

    return {
        "n": len(sizes),
        "p50": percentile(
            sizes,
            0.50,
        ),
        "p75": percentile(
            sizes,
            0.75,
        ),
        "p90": percentile(
            sizes,
            0.90,
        ),
        "p95": percentile(
            sizes,
            0.95,
        ),
        "median": (
            median(sizes)
            if sizes
            else None
        ),
        "merged": (
            historical_statistics(
                merged
            )
            if merged
            and len(merged)
            != len(records)
            else None
        ),
    }


def collect_historical_sample(
    gh,
    count,
    seed=0,
):
    candidates = gh.pull_sample(
        max(
            count * 2,
            count,
        )
    )

    candidates = sorted(
        candidates,
        key=lambda item: int(
            item.get(
                "number",
                0,
            )
        ),
    )

    if len(candidates) > count:
        step = (
            len(candidates)
            / count
        )

        selected = [
            candidates[
                min(
                    int(i * step),
                    len(candidates) - 1,
                )
            ]
            for i in range(count)
        ]
    else:
        selected = candidates

    records = []

    for idx, summary in enumerate(
        selected,
        1,
    ):
        number = int(
            summary["number"]
        )

        try:
            pr = gh.pr(
                number
            )

            records.append(
                {
                    "number": number,
                    "state": pr.get(
                        "state"
                    ),
                    "merged": bool(
                        pr.get(
                            "merged_at"
                        )
                    ),
                    "base": (
                        pr.get(
                            "base"
                        )
                        or {}
                    ).get(
                        "ref"
                    ),
                    "additions": int(
                        pr.get(
                            "additions",
                            0,
                        )
                        or 0
                    ),
                    "deletions": int(
                        pr.get(
                            "deletions",
                            0,
                        )
                        or 0
                    ),
                    "changed_files": int(
                        pr.get(
                            "changed_files",
                            0,
                        )
                        or 0
                    ),
                    "created_at": pr.get(
                        "created_at"
                    ),
                    "merged_at": pr.get(
                        "merged_at"
                    ),
                    "closed_at": pr.get(
                        "closed_at"
                    ),
                    "labels": [
                        label.get(
                            "name"
                        )
                        for label in pr.get(
                            "labels",
                            [],
                        )
                    ],
                    "title": pr.get(
                        "title",
                        "",
                    ),
                }
            )

        except Exception as exc:
            print(
                f"sample {idx}/{len(selected)}: "
                f"PR #{number} skipped: {exc}",
                file=sys.stderr,
            )

    return {
        "generated_at": now_utc().isoformat(),
        "repo": REPO,
        "requested": count,
        "candidate_population": len(
            candidates
        ),
        "collected": len(records),
        "sampling": {
            "endpoint": (
                "/pulls?state=all&sort=created"
                "&direction=desc"
            ),
            "selection": (
                "deterministic systematic sample "
                "over PR numbers from the collected "
                "candidate population"
            ),
            "seed": seed,
            "note": (
                "Descriptive statistics only; not causal "
                "and not a complete representation of "
                "every CPython PR."
            ),
        },
        "statistics": historical_statistics(
            records
        ),
        "label_frequency": Counter(
            label
            for record in records
            for label in record[
                "labels"
            ]
        ).most_common(),
        "base_branch_frequency": Counter(
            record["base"]
            for record in records
        ).most_common(),
        "records": records,
    }


def label_metadata(gh):
    try:
        return {
            item.get(
                "name"
            ): item
            for item in gh.labels()
        }
    except Exception:
        return {}


def summarize_labels(
    labels,
    metadata,
):
    result = []

    for label in labels:
        hint = LABEL_HINTS.get(
            label
        )

        result.append(
            {
                "name": label,
                "description": (
                    metadata.get(
                        label
                    )
                    or {}
                ).get(
                    "description"
                ),
                "triager_hint": (
                    hint[1]
                    if hint
                    else None
                ),
                "hint_class": (
                    hint[0]
                    if hint
                    else None
                ),
            }
        )

    return result


def review_signals(
    pr,
    timeline,
):
    human = [
        event
        for event in timeline
        if not event.get(
            "bot"
        )
    ]

    approvals = [
        event
        for event in human
        if (
            event.get(
                "kind"
            )
            == "review"
            and event.get(
                "state"
            )
            == "APPROVED"
        )
    ]

    changes = [
        event
        for event in human
        if (
            event.get(
                "kind"
            )
            == "review"
            and event.get(
                "state"
            )
            == "CHANGES_REQUESTED"
        )
    ]

    signals = []

    if approvals:
        signals.append(
            (
                "OK",
                f"{len(approvals)} human approval review(s) recorded.",
            )
        )

    if changes:
        latest = max(
            changes,
            key=lambda event: event.get(
                "date",
                "",
            ),
        )

        later = [
            event
            for event in human
            if event.get(
                "date",
                "",
            )
            > latest.get(
                "date",
                "",
            )
        ]

        if later:
            signals.append(
                (
                    "INFO",
                    "Changes were requested by "
                    f"@{latest.get('login','?')}; "
                    "later human activity exists.",
                )
            )
        else:
            signals.append(
                (
                    "WARN",
                    "Latest changes-requested review is by "
                    f"@{latest.get('login','?')} "
                    "with no later human activity.",
                )
            )

    if pr.get(
        "state"
    ) == "open":
        dates = [
            event.get(
                "date"
            )
            for event in human
            if event.get(
                "date"
            )
        ]

        if dates:
            age = iso_age_days(
                max(dates)
            )

            if age is not None:
                if age > 90:
                    signals.append(
                        (
                            "WARN",
                            f"No human activity for about {age:.0f} days; "
                            "review whether follow-up is appropriate.",
                        )
                    )
                elif age > 30:
                    signals.append(
                        (
                            "INFO",
                            f"No human activity for about {age:.0f} days; "
                            "follow-up may be appropriate.",
                        )
                    )

    return signals


def branch_and_backport_signals(
    pr,
    labels,
):
    base = (
        pr.get(
            "base"
        )
        or {}
    ).get(
        "ref",
        "",
    )

    signals = []

    if MAINTENANCE_BRANCH_RE.fullmatch(
        base
    ):
        if {
            "type-feature",
            "type-enhancement",
        } & set(labels):
            signals.append(
                (
                    "BLOCK",
                    "Feature/enhancement-labelled PR "
                    f"targets maintenance branch {base}; "
                    "verify CPython branch policy.",
                )
            )

        if "type-security" in labels:
            signals.append(
                (
                    "INFO",
                    "Security-labelled PR targets maintenance "
                    f"branch {base}; verify security handling.",
                )
            )

    backports = []

    for label in labels:
        match = BACKPORT_LABEL_RE.fullmatch(
            label
        )

        if match:
            backports.append(
                match.group(1)
            )

    if backports:
        signals.append(
            (
                "INFO",
                "Backport intent labels: "
                + ", ".join(
                    sorted(
                        backports
                    )
                )
                + ".",
            )
        )

    return (
        signals,
        backports,
    )


def process_signals(
    pr,
    files,
    timeline,
    labels,
    patterns,
):
    signals = []
    title = pr.get(
        "title"
    ) or ""

    if re.match(
        r"^gh-\d{3,7}:\s+\S",
        title,
        re.I,
    ):
        signals.append(
            (
                "OK",
                "Title uses the current "
                "gh-NNNNN issue-reference style.",
            )
        )
    elif re.match(
        r"^\[(?:3\.\d+|main)\]\s+\S",
        title,
    ):
        signals.append(
            (
                "OK",
                "Title looks like a branch/backport title.",
            )
        )
    else:
        signals.append(
            (
                "INFO",
                "Title does not use the common gh-/backport "
                "form; style signal only.",
            )
        )

    adds = int(
        pr.get(
            "additions",
            0,
        )
        or 0
    )

    dels = int(
        pr.get(
            "deletions",
            0,
        )
        or 0
    )

    total = adds + dels

    stats = (
        patterns
        or {}
    ).get(
        "statistics"
    ) or {}

    p90 = stats.get(
        "p90"
    )

    p95 = stats.get(
        "p95"
    )

    if (
        p95 is not None
        and total > p95
    ):
        signals.append(
            (
                "WARN",
                f"PR size {total} changed lines is above sampled p95 ({p95:.0f}).",
            )
        )
    elif (
        p90 is not None
        and total > p90
    ):
        signals.append(
            (
                "INFO",
                f"PR size {total} changed lines is above sampled p90 ({p90:.0f}).",
            )
        )
    else:
        signals.append(
            (
                "OK",
                f"PR size is {total} changed lines across "
                f"{pr.get('changed_files')} files.",
            )
        )

    names, tests, news, docs = file_signals(
        files
    )

    labels_set = set(
        labels
    )

    if "skip news" in labels_set:
        signals.append(
            (
                "OK",
                "skip news label is present.",
            )
        )
    elif news:
        signals.append(
            (
                "OK",
                f"NEWS entry present ({len(news)} file(s)).",
            )
        )
    elif all(
        name.startswith(
            "Doc/"
        )
        for name in names
    ):
        signals.append(
            (
                "INFO",
                "Documentation-only change has no NEWS entry; usually not required.",
            )
        )
    elif all(
        name.startswith(
            "Lib/test/"
        )
        for name in names
    ):
        signals.append(
            (
                "INFO",
                "Test-only change has no NEWS entry; usually not required.",
            )
        )
    else:
        signals.append(
            (
                "WARN",
                "No Misc/NEWS.d entry detected; verify whether this change requires one.",
            )
        )

    if tests:
        signals.append(
            (
                "OK",
                f"Test-related file(s) changed ({len(tests)}).",
            )
        )
    elif all(
        name.startswith(
            "Doc/"
        )
        for name in names
    ):
        signals.append(
            (
                "INFO",
                "Documentation-only change has no test file; likely not applicable.",
            )
        )
    else:
        signals.append(
            (
                "WARN",
                "No test file changed; verify whether regression/behavior coverage is needed.",
            )
        )

    if "DO-NOT-MERGE" in labels_set:
        signals.append(
            (
                "BLOCK",
                "DO-NOT-MERGE is active.",
            )
        )

    if "awaiting changes" in labels_set:
        signals.append(
            (
                "BLOCK",
                "awaiting changes indicates author action is expected.",
            )
        )

    if "awaiting merge" in labels_set:
        signals.append(
            (
                "INFO",
                "awaiting merge is present; verify CI and current review state.",
            )
        )

    branch, backports = branch_and_backport_signals(
        pr,
        labels,
    )

    signals.extend(
        branch
    )

    signals.extend(
        review_signals(
            pr,
            timeline,
        )
    )

    return (
        signals,
        backports,
    )


def disposition(
    process,
    findings,
):
    if any(
        signal == "BLOCK"
        for signal, _ in process
    ):
        return "PROCESS_BLOCKED"

    if any(
        finding.severity
        in {
            "CRITICAL",
            "HIGH",
        }
        for finding in findings
    ):
        return "NEEDS_TECHNICAL_REVIEW"

    if any(
        signal == "WARN"
        for signal, _ in process
    ):
        return "NEEDS_MAINTAINER_ATTENTION"

    return "READY_FOR_MAINTAINER_REVIEW"


def build_checks(
    gh,
    pr,
):
    head_sha = (
        pr.get(
            "head"
        )
        or {}
    ).get(
        "sha"
    )

    if not head_sha:
        return {
            "available": False,
            "reason": "No PR head SHA.",
        }

    result = {
        "available": True,
        "head_sha": head_sha,
        "check_runs": [],
        "status": None,
    }

    try:
        result["check_runs"] = gh.checks(
            head_sha
        )
    except Exception as exc:
        result["checks_error"] = str(
            exc
        )

    try:
        result["status"] = gh.statuses(
            head_sha
        )
    except Exception as exc:
        result["status_error"] = str(
            exc
        )

    conclusions = [
        item.get(
            "conclusion"
        )
        for item in result[
            "check_runs"
        ]
        if item.get(
            "status"
        ) == "completed"
    ]

    result["summary"] = {
        "check_runs": len(
            result[
                "check_runs"
            ]
        ),
        "completed": sum(
            item == "completed"
            for item in [
                run.get(
                    "status"
                )
                for run in result[
                    "check_runs"
                ]
            ]
        ),
        "failures": sum(
            conclusion
            in {
                "failure",
                "timed_out",
                "cancelled",
                "action_required",
            }
            for conclusion in conclusions
        ),
        "successes": sum(
            conclusion
            in {
                "success",
                "neutral",
                "skipped",
            }
            for conclusion in conclusions
        ),
    }

    if isinstance(
        result["status"],
        dict,
    ):
        result["summary"][
            "legacy_status"
        ] = result["status"].get(
            "state"
        )

    return result


def make_report(
    gh,
    evidence,
    linked_issues,
    experts,
    patterns,
):
    pr = evidence[
        "pr"
    ]

    files = evidence[
        "files"
    ]

    timeline = evidence[
        "timeline"
    ]

    labels = [
        item.get(
            "name"
        )
        for item in pr.get(
            "labels",
            [],
        )
    ]

    findings, signatures = analyze_diff(
        files
    )

    process, backports = process_signals(
        pr,
        files,
        timeline,
        labels,
        patterns,
    )

    report_disposition = disposition(
        process,
        findings,
    )

    adds, dels = changed_lines(
        files
    )

    checks = build_checks(
        gh,
        pr,
    )

    if (
        checks.get(
            "summary",
            {},
        ).get(
            "failures"
        )
    ):
        process.append(
            (
                "WARN",
                f"{checks['summary']['failures']} completed CI check(s) have failure-like conclusions.",
            )
        )

    return {
        "schema_version": "1.0",
        "repository": REPO,
        "generated_at": now_utc().isoformat(),
        "pr": {
            "number": pr.get(
                "number"
            ),
            "title": pr.get(
                "title"
            ),
            "state": pr.get(
                "state"
            ),
            "merged": bool(
                pr.get(
                    "merged_at"
                )
            ),
            "draft": bool(
                pr.get(
                    "draft"
                )
            ),
            "author": (
                pr.get(
                    "user"
                )
                or {}
            ).get(
                "login"
            ),
            "base": (
                pr.get(
                    "base"
                )
                or {}
            ).get(
                "ref"
            ),
            "base_sha": (
                pr.get(
                    "base"
                )
                or {}
            ).get(
                "sha"
            ),
            "head": (
                pr.get(
                    "head"
                )
                or {}
            ).get(
                "ref"
            ),
            "head_sha": (
                pr.get(
                    "head"
                )
                or {}
            ).get(
                "sha"
            ),
            "labels": labels,
            "additions": adds,
            "deletions": dels,
            "changed_files": pr.get(
                "changed_files"
            ),
            "commits": pr.get(
                "commits"
            ),
            "created_at": pr.get(
                "created_at"
            ),
            "updated_at": pr.get(
                "updated_at"
            ),
            "closed_at": pr.get(
                "closed_at"
            ),
            "merged_at": pr.get(
                "merged_at"
            ),
            "mergeable": pr.get(
                "mergeable"
            ),
            "mergeable_state": pr.get(
                "mergeable_state"
            ),
        },
        "disposition": report_disposition,
        "process_signals": [
            {
                "signal": signal,
                "message": message,
            }
            for signal, message in process
        ],
        "backport_targets": backports,
        "technical_findings": [
            finding.as_dict()
            for finding in findings
        ],
        "signature_changes": signatures,
        "files": [
            {
                "filename": file_data.get(
                    "filename"
                ),
                "status": file_data.get(
                    "status"
                ),
                "additions": file_data.get(
                    "additions"
                ),
                "deletions": file_data.get(
                    "deletions"
                ),
                "subsystem": classify(
                    file_data.get(
                        "filename",
                        "",
                    )
                )[0],
                "component": classify(
                    file_data.get(
                        "filename",
                        "",
                    )
                )[1],
                "expected_test_hint": classify(
                    file_data.get(
                        "filename",
                        "",
                    )
                )[2],
            }
            for file_data in files
        ],
        "experts": experts,
        "labels": summarize_labels(
            labels,
            label_metadata(gh),
        ),
        "checks": checks,
        "linked_issues": linked_issues,
        "timeline": timeline,
        "evidence_counts": {
            "timeline_events": len(
                timeline
            ),
            "human_timeline_events": sum(
                not event.get(
                    "bot"
                )
                for event in timeline
            ),
            "reviews": len(
                evidence[
                    "reviews"
                ]
            ),
            "review_comments": len(
                evidence[
                    "review_comments"
                ]
            ),
            "issue_comments": len(
                evidence[
                    "issue_comments"
                ]
            ),
            "linked_issues": len(
                linked_issues
            ),
            "api_calls": gh.calls,
            "cache_hits": gh.cache_hits,
            "rate_limit_remaining": (
                gh.rate_remaining
            ),
            "rate_limit_reset": (
                gh.rate_reset
            ),
        },
    }


def ai_synthesis(report):
    if not ANTHROPIC_API_KEY:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set"
        )

    compact = json.dumps(
        report,
        ensure_ascii=False,
    )

    if len(compact) > 140_000:
        compact = (
            compact[:140_000]
            + "\n...[evidence truncated]"
        )

    system = """You are an assistant to CPython maintainers.
You are not a maintainer and must never claim to approve, reject, or merge a PR.
Use only the supplied evidence. Separate observed facts from inference.
Heuristic findings are review prompts, not proof of defects.
Do not invent tests, policy, owners, or historical facts.
Return JSON:
{
  "triage": "READY_FOR_MAINTAINER_REVIEW|NEEDS_MAINTAINER_ATTENTION|NEEDS_AUTHOR_CHANGES|PROCESS_BLOCKED|HIGH_RISK_REVIEW",
  "confidence": 1,
  "summary": "...",
  "top_risks": [{"risk":"...", "evidence":"..."}],
  "review_questions": ["..."],
  "expert_routing": [{"owner":"...", "reason":"..."}],
  "process_assessment": "...",
  "test_assessment": "...",
  "backport_assessment": "...",
  "uncertainties": ["..."]
}"""

    payload = {
        "model": os.environ.get(
            "ANTHROPIC_MODEL",
            "claude-sonnet-4-6",
        ),
        "max_tokens": 3000,
        "system": system,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Evidence package:\n"
                    + compact
                ),
            }
        ],
    }

    request = __import__(
        "urllib.request",
        fromlist=["Request"],
    ).Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(
            payload
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        },
    )

    with __import__(
        "urllib.request",
        fromlist=["urlopen"],
    ).urlopen(
        request,
        timeout=120,
    ) as response:
        data = json.loads(
            response.read().decode()
        )

    raw = "".join(
        item.get(
            "text",
            "",
        )
        for item in data.get(
            "content",
            [],
        )
        if item.get(
            "type"
        ) == "text"
    ).strip()

    raw = re.sub(
        r"^```(?:json)?\s*|\s*```$",
        "",
        raw,
    )

    return json.loads(
        raw
    )


def print_report(
    report,
    quiet=False,
):
    pr = report[
        "pr"
    ]

    print(
        "=" * 78
    )
    print(
        f"CPython PR Triager — #{pr['number']}"
    )
    print(
        "=" * 78
    )
    print(
        f"Title:       {pr['title']}"
    )
    print(
        f"State:       {pr['state']}"
        f"{' (merged)' if pr['merged'] else ''}"
    )
    print(
        f"Author:      @{pr['author']}"
    )
    print(
        f"Base:        {pr['base']}"
    )
    print(
        f"Size:        +{pr['additions']} "
        f"-{pr['deletions']} / "
        f"{pr['changed_files']} files"
    )
    print(
        f"Disposition: {report['disposition']}"
    )

    print(
        "\nProcess / Evidence Signals"
    )

    for item in report[
        "process_signals"
    ]:
        print(
            f"  [{item['signal']}] "
            f"{item['message']}"
        )

    print(
        "\nTechnical Findings"
    )

    if report[
        "technical_findings"
    ]:
        for finding in report[
            "technical_findings"
        ]:
            print(
                f"  [{finding['severity']}] "
                f"[{finding['confidence']}] "
                f"{finding['file']}: "
                f"{finding['message']}"
            )
            print(
                f"      {finding['evidence']}"
            )
    else:
        print(
            "  No heuristic findings triggered."
        )

    if report[
        "experts"
    ]:
        print(
            "\nCODEOWNERS Routing"
        )

        for expert in report[
            "experts"
        ]:
            print(
                f"  {expert['owner']} "
                f"<- {expert['file']} "
                f"({expert['pattern']})"
            )

    checks = report.get(
        "checks",
        {},
    )

    if checks.get(
        "available"
    ):
        summary = checks.get(
            "summary",
            {},
        )

        print(
            "\nCI / Checks"
        )
        print(
            f"  Check runs: {summary.get('check_runs', 0)}"
        )
        print(
            f"  Completed:  {summary.get('completed', 0)}"
        )
        print(
            f"  Successes:  {summary.get('successes', 0)}"
        )
        print(
            f"  Failures:  {summary.get('failures', 0)}"
        )

        if summary.get(
            "legacy_status"
        ):
            print(
                f"  Commit status: "
                f"{summary['legacy_status']}"
            )

    if not quiet:
        ec = report[
            "evidence_counts"
        ]

        print(
            "\nEvidence Counts"
        )
        print(
            f"  Timeline: {ec['timeline_events']} "
            f"({ec['human_timeline_events']} human)"
        )
        print(
            f"  Reviews: {ec['reviews']} "
            f"| inline: {ec['review_comments']}"
        )
        print(
            f"  Issue comments: {ec['issue_comments']} "
            f"| linked issues: {ec['linked_issues']}"
        )
        print(
            f"  API calls: {ec['api_calls']} "
            f"| cache hits: {ec['cache_hits']}"
        )

    print(
        "\nHeuristic findings are review prompts, "
        "not proof of defects."
    )
    print(
        "Final decisions remain with CPython maintainers."
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Evidence-first CPython "
            "pull-request triager"
        )
    )

    parser.add_argument(
        "pr_number",
        nargs="?",
        type=int,
    )
    parser.add_argument(
        "--ai",
        action="store_true",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
    )
    parser.add_argument(
        "--patterns",
        help="Historical statistics JSON",
    )
    parser.add_argument(
        "--learn-patterns",
        type=int,
        metavar="N",
    )
    parser.add_argument(
        "--output-patterns"
    )
    parser.add_argument(
        "--no-linked-issues",
        action="store_true",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
    )

    args = parser.parse_args()

    global CACHE_TTL

    if args.no_cache:
        CACHE_TTL = 0

    gh = GitHub()

    if args.learn_patterns is not None:
        if args.learn_patterns < 1:
            parser.error(
                "--learn-patterns must be >= 1"
            )

        print(
            "Collecting a reproducible sample "
            f"of {args.learn_patterns} PRs..."
        )

        data = collect_historical_sample(
            gh,
            args.learn_patterns,
        )

        if args.output_patterns:
            Path(
                args.output_patterns
            ).parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            Path(
                args.output_patterns
            ).write_text(
                json.dumps(
                    data,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            print(
                f"Wrote {args.output_patterns}"
            )
        else:
            print(
                json.dumps(
                    data,
                    indent=2,
                    ensure_ascii=False,
                )
            )

        return

    if args.pr_number is None:
        parser.error(
            "pr_number is required unless "
            "--learn-patterns is used"
        )

    evidence = fetch_pr_evidence(
        gh,
        args.pr_number,
    )

    pr = evidence[
        "pr"
    ]

    if args.no_linked_issues:
        linked, peps, discussions = (
            [],
            [],
            [],
        )
    else:
        (
            linked,
            peps,
            discussions,
        ) = fetch_linked_issues(
            gh,
            args.pr_number,
            pr.get(
                "body"
            ) or "",
            evidence[
                "timeline"
            ],
        )

    base_sha = (
        pr.get(
            "base"
        )
        or {}
    ).get(
        "sha"
    )

    codeowners_path, codeowners_text = (
        gh.codeowners(
            base_sha
        )
    )

    rules = parse_codeowners(
        codeowners_text
    )

    experts = resolve_codeowners(
        rules,
        [
            file_data.get(
                "filename",
                "",
            )
            for file_data in evidence[
                "files"
            ]
        ],
    )

    patterns = None

    if args.patterns:
        try:
            patterns = json.loads(
                Path(
                    args.patterns
                ).read_text(
                    encoding="utf-8"
                )
            )
        except Exception as exc:
            print(
                f"Warning: unable to read patterns: {exc}",
                file=sys.stderr,
            )

    report = make_report(
        gh,
        evidence,
        linked,
        experts,
        patterns,
    )

    report[
        "references"
    ] = {
        "peps": peps,
        "discussions": discussions,
    }

    report[
        "repository_metadata"
    ] = {
        "codeowners_path": codeowners_path,
        "codeowners_rules": len(
            rules
        ),
        "base_sha": base_sha,
    }

    if args.ai:
        try:
            report[
                "ai_synthesis"
            ] = ai_synthesis(
                report
            )
        except Exception as exc:
            report[
                "ai_error"
            ] = str(exc)

    if args.as_json:
        print(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print_report(
            report,
            quiet=args.quiet,
        )

        if report.get(
            "ai_synthesis"
        ):
            ai = report[
                "ai_synthesis"
            ]

            print(
                f"\nAI synthesis: "
                f"{ai.get('triage')} "
                f"(confidence "
                f"{ai.get('confidence')}/5)"
            )

            print(
                ai.get(
                    "summary",
                    "",
                )
            )

            for question in ai.get(
                "review_questions",
                [],
            ):
                print(
                    f"  - {question}"
                )


if __name__ == "__main__":
    main()
