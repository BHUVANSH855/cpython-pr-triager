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

# Support direct execution with: python scripts/analyze.py
if __package__ in {None, ""}:
    REPO_ROOT = Path(__file__).resolve().parents[1]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

from scripts.triager.github import GitHub as TriagerGitHub
from scripts.triager.references import (
    collect_issue_numbers,
    issue_refs_from_timeline as extract_timeline_issue_refs,
)
from scripts.triager.analyzers import (
    analyze_files as analyze_file_set,
)
from scripts.triager.codeowners import (
    parse_codeowners as parse_codeowners_rules,
    resolve_codeowners as resolve_codeowners_matches,
)
from scripts.triager.report import (
    build_report,
)
from scripts.triager.policy import (
    disposition as policy_disposition,
    process_signals as policy_process_signals,
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
    """Compatibility wrapper around the modular CODEOWNERS parser."""
    rules = parse_codeowners_rules(
        text
    )

    return [
        {
            "line": rule.line,
            "pattern": rule.pattern,
            "owners": list(rule.owners),
        }
        for rule in rules
    ]


def codeowners_match(
    pattern,
    path,
):
    """Compatibility wrapper around the modular CODEOWNERS matcher."""
    from scripts.triager.codeowners import _matches

    return _matches(
        pattern,
        path,
    )


def resolve_codeowners(
    rules,
    filenames,
):
    """Compatibility wrapper around the modular CODEOWNERS resolver."""
    parsed_rules = [
        rule
        if hasattr(rule, "pattern")
        else type(
            "CompatCodeOwnerRule",
            (),
            {
                "pattern": rule["pattern"],
                "owners": tuple(rule["owners"]),
                "line": rule["line"],
            },
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
        for match in resolve_codeowners_matches(
            parsed_rules,
            filenames,
        )
    ]


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
    """
    Compatibility wrapper around the modular PR evidence collector.

    The CLI still expects the historical evidence dictionary, while the
    modular GitHub client owns network access and collection.
    """
    result = gh.pull_request_evidence(
        number,
    )

    evidence = result["evidence"]

    # Preserve the legacy evidence shape consumed by the rest of
    # analyze.py. The modular collector already returns these keys;
    # this wrapper only guarantees their presence.
    evidence.setdefault(
        "files",
        [],
    )
    evidence.setdefault(
        "reviews",
        [],
    )
    evidence.setdefault(
        "review_comments",
        [],
    )
    evidence.setdefault(
        "issue_comments",
        [],
    )
    evidence.setdefault(
        "timeline",
        [],
    )
    evidence.setdefault(
        "linked_issues",
        [],
    )
    evidence.setdefault(
        "check_runs",
        {
            "total_count": 0,
            "check_runs": [],
        },
    )
    evidence.setdefault(
        "statuses",
        [],
    )
    evidence.setdefault(
        "codeowners_path",
        None,
    )
    evidence.setdefault(
        "codeowners_text",
        None,
    )

    return evidence


def fetch_linked_issues(
    gh,
    pr_number,
    pr_body,
    timeline,
    limit=20,
):
    """
    Discover explicitly referenced GitHub issues and fetch their evidence.

    Reference discovery remains local to the orchestration layer so that
    CPython-specific reference semantics are preserved. Network retrieval
    is delegated to the modular GitHub evidence client.
    """
    text = pr_body or ""

    github_issue_numbers = {
        int(number)
        for number in re.findall(
            r"\b(?:GH-|gh-)(\d{3,7})\b",
            text,
        )
    }

    github_issue_numbers.update(
        int(number)
        for number in re.findall(
            r"(?<!\w)#(\d{3,7})\b",
            text,
        )
    )

    timeline_refs = issue_refs_from_timeline(
        timeline
    )

    github_issue_numbers.update(
        ref["number"]
        for ref in timeline_refs
        if ref["number"] != pr_number
    )

    numbers = sorted(
        number
        for number in github_issue_numbers
        if number != pr_number
    )[:limit]

    # Preserve the legacy reference outputs for PEPs and Discussions.
    _, peps, discussions = extract_refs(
        text
    )

    if not numbers:
        return (
            [],
            peps,
            discussions,
        )

    linked_issues = (
        gh.linked_issue_evidence_batch(
            numbers,
            bot_logins=BOT_LOGINS,
        )
    )

    return (
        linked_issues,
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
    """Compatibility wrapper around the modular deterministic analyzers."""
    return analyze_file_set(files)

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
        for item in evidence[
            "pr"
        ].get(
            "labels",
            [],
        )
    ]

    findings, signatures = analyze_diff(
        files
    )

    process, backports = policy_process_signals(
        evidence[
            "pr"
        ],
        files,
        timeline,
        labels,
        patterns,
    )

    report_disposition = policy_disposition(
        process,
        findings,
    )

    checks = build_checks(
        gh,
        evidence[
            "pr"
        ],
    )

    return build_report(
        repository=REPO,
        generated_at=now_utc().isoformat(),
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
            (
                (pr.get("title") or "")
                + "\n"
                + (pr.get("body") or "")
            ),
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
