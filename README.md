# CPython PR Triager

An evidence-first maintainer-assist tool for `python/cpython`.

CPython PR Triager gathers repository evidence, highlights technical and
process review questions, routes changes toward current CODEOWNERS, and
optionally uses an LLM to synthesize the collected evidence.

The goal is **not** to replace maintainers or make merge decisions. The goal is
to make the evidence and review surface easier for maintainers to inspect.

## Design principles

1. **Evidence before inference.**
2. **Heuristics are review prompts, never proof of a defect.**
3. **Repository-current data beats hard-coded assumptions.**
4. **Complete pagination is preferred to arbitrary first-page limits.**
5. **Historical statistics are descriptive and reproducible, not universal truth.**
6. **AI is a synthesis layer, not the decision maker.**
7. **Incomplete evidence must be visible.**
8. **Reviewer-specific claims require reviewer-specific evidence.**
9. **Aggregate operation counts are not ownership analysis.**
10. **Deterministic policy remains authoritative over AI output.**

---

## Two distinct tools

This repository ships two separate tools that do **not** share code:

| Tool            | File                 | How it works                                                                                                                                                                                                                                                                                                                               |
| --------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Python CLI**  | `scripts/analyze.py` | Runs server-side. Uses complete pagination, local caching, retries, live CODEOWNERS, deterministic analysis, policy evaluation, and optional AI synthesis. This is the authoritative/recommended path.                                                                                                                                     |
| **Web triager** | `index.html`         | Runs entirely in the browser and calls the GitHub API directly. It fetches CODEOWNERS from the PR's base SHA and provides a quick-look version of the deterministic analysis. It fetches only one page per GitHub endpoint and therefore can report partial evidence when pagination limits are reached. It does not perform AI synthesis. |

The web UI has its own, deliberately smaller implementation of the deterministic
analysis rules. It is intended for quick inspection and sharing rather than
being a replacement for the fully paginated CLI.

When evidence completeness matters, prefer the Python CLI.

---

## Requirements

* Python 3.11+
* No third-party Python packages are required at runtime
* `pytest` is required to run the test suite
* Internet access to the GitHub REST API
* A `GITHUB_TOKEN` is strongly recommended

Install the project and test dependencies with:

```powershell
pip install -e ".[test]"
```

### GitHub API rate limits

Authenticated GitHub API requests provide substantially more capacity than
unauthenticated requests.

Set your token before running the CLI:

```powershell
$env:GITHUB_TOKEN="YOUR_TOKEN"
```

Do not commit or otherwise expose the token.

---

# Run

Run commands from the **project root**.

Analyze a pull request:

```powershell
python scripts/analyze.py 123456
```

Generate JSON output:

```powershell
python scripts/analyze.py 123456 --json > report.json
```

Skip linked issue history:

```powershell
python scripts/analyze.py 123456 --no-linked-issues
```

This is faster and reduces API work, but it deliberately produces a less
complete evidence package and reports that limitation.

Disable the local HTTP cache:

```powershell
python scripts/analyze.py 123456 --no-cache
```

> **Important:** run the command from the repository root, not from inside
> `scripts/`. The CLI adds the project root to `sys.path` when launched from
> the root, allowing imports such as `from scripts.triager import ...`.

---

# Evidence model

The triager separates **collected evidence**, **deterministic analysis**, and
**synthesis**.

Conceptually:

```text
GitHub repository
       │
       ▼
Evidence collection
       │
       ├── PR metadata
       ├── changed files
       ├── reviews
       ├── review comments
       ├── review threads
       ├── issue comments
       ├── timeline
       ├── linked issues
       ├── CI/checks
       ├── CODEOWNERS
       └── repository policy
       │
       ▼
Evidence normalization
       │
       ▼
Deterministic analysis
       │
       ├── technical review prompts
       ├── process signals
       ├── reviewer state
       ├── routing
       └── historical context
       │
       ▼
Maintainer-facing report
       │
       └── optional AI synthesis
```

The tool attempts to distinguish between:

* **Observed evidence**
* **Derived deterministic signals**
* **Review prompts**
* **Historical context**
* **Missing or unavailable evidence**
* **AI-generated synthesis**

A missing evidence source is not silently treated as an empty successful
result.

---

# What the analyzer examines

## Repository evidence

The CLI collects and analyzes:

* PR metadata
* changed-file information
* complete changed-file pagination
* submitted PR reviews
* inline review comments
* issue comments
* issue timeline events
* bot-vs-human timeline activity
* review threads
* linked issue references
* linked issue comments and timeline information
* PEP references
* `discuss.python.org` references
* current repository labels
* PR-base CODEOWNERS
* PR head checks
* legacy commit statuses
* branch and backport information
* repository policy data

Where GitHub exposes paginated data, the CLI attempts to walk the complete
available result set rather than treating the first page as the complete
dataset.

---

# Review evidence

Reviewer activity is deliberately separated from generic reviewer routing.

The tool distinguishes between:

* submitted PR reviews
* inline review comments
* general issue comments
* review-thread state

A comment written by a reviewer is not automatically treated as a submitted
review.

Reviewer activity can include evidence such as:

* submitted review counts
* approval counts
* change-request counts
* approval-rate samples
* response-time statistics
* recent review activity
* recurring review phrases

These measurements are derived from the reviewer's actual GitHub activity
when the required evidence is available.

If the required reviewer evidence cannot be fetched, the tool reports that
availability state rather than inventing a reviewer-specific conclusion.

---

# Review threads

Unresolved review threads are treated as first-class review evidence.

The tool records thread state rather than reducing all review activity to
simple approval/change-request counts.

This allows the report to distinguish situations such as:

```text
APPROVED review
+
unresolved review thread
```

from:

```text
APPROVED review
+
no unresolved threads
```

Review-thread evidence can be unavailable independently of other review
evidence. An unavailable thread query is therefore not interpreted as
"zero unresolved threads."

---

# Process signals

The deterministic policy layer evaluates repository process information such
as:

* current labels
* `DO-NOT-MERGE`
* `awaiting changes`
* `awaiting merge`
* NEWS requirements
* `skip news` waivers
* test-coverage signals
* review state
* unresolved review threads
* branch lifecycle
* backport labels
* CI/check state
* required-check state

The policy layer is intentionally deterministic.

AI synthesis does not override authoritative process policy.

---

# CPython branch policy

Branch lifecycle is evaluated using the repository's branch-policy snapshot
rather than being inferred solely from version numbers.

The current policy snapshot represents:

| Branch | Lifecycle status     |
| ------ | -------------------- |
| `main` | Feature development  |
| `3.15` | Prerelease           |
| `3.14` | Bugfix / maintenance |
| `3.13` | Bugfix / maintenance |
| `3.12` | Security-fix-only    |
| `3.11` | Security-fix-only    |
| `3.10` | Security-fix-only    |

These statuses are treated as policy evidence.

The analyzer can emit review signals when the target branch, labels, or change
classification appear inconsistent with the current lifecycle policy.

The policy data is repository-maintained and can be updated independently of
the analyzer implementation.

---

# Backport detection

The analyzer recognizes the current spaced CPython format:

```text
needs backport to 3.13
```

It also recognizes the older hyphenated form:

```text
needs-backport-to-3.13
```

The legacy form is retained for compatibility with older pull requests.

---

# Technical review prompts

The static analyzer scans newly added diff lines where possible.

A matching pattern is **not automatically a vulnerability or correctness
bug**. Findings are review prompts intended to direct human inspection.

## C / memory safety

Examples include:

* `gets()` → CRITICAL
* `sprintf()` → CRITICAL
* `strcpy()` / `strcat()` → HIGH
* raw `malloc()` / `free()` / `realloc()` / `calloc()` → HIGH
* `PyCObject_*` usage → CRITICAL

The analyzer can point maintainers toward CPython-specific alternatives where
appropriate, such as `PyOS_snprintf()`, `PyMem_*`, or `PyCapsule`.

---

## CPython internals

The analyzer checks for patterns involving:

* private `_Py_*` API usage
* `PyErr_Clear()` silently discarding exceptions
* `_Py_IDENTIFIER`
* GIL/thread-state boundaries
* `Py_BEGIN_ALLOW_THREADS` / `Py_END_ALLOW_THREADS`
* free-threading-sensitive patterns
* other CPython-internal review surfaces

These findings are prompts for maintainer review, not automatic defect
classifications.

---

## Python

The analyzer checks for patterns including:

* `eval()` / `exec()`
* `pickle.load()`
* `subprocess(..., shell=True)`
* `tempfile.mktemp()`
* `hashlib.md5()` / `hashlib.sha1()`
* bare `except:`
* `assert` in production code
* `global` statements
* `DeprecationWarning` without `stacklevel=`

Where practical, the analyzer uses additional context to reduce false
positives. For example, `eval()` findings are AST-confirmed rather than being
based only on a raw text match.

---

# Refcount analysis

Refcount handling is intentionally conservative.

The analyzer **does not infer a leak or over-decref merely from aggregate
INCREF/DECREF counts across a diff**.

For example, this does not by itself establish a leak:

```c
Py_INCREF(obj);
Py_INCREF(obj);
```

Likewise, a difference between the number of `Py_INCREF()` and
`Py_DECREF()` operations does not establish that the operations refer to the
same object, ownership path, or lifetime.

The triager therefore avoids the previous diff-wide count heuristic.

Instead, refcount review focuses on localized structural patterns that are
more useful as human review prompts, such as suspicious lifetime operations
around a specific variable.

These findings should be interpreted as:

```text
"Review this ownership/lifetime pattern."
```

not:

```text
"This code definitely leaks or over-decrefs."
```

This distinction is particularly important for CPython C code, where ownership
can depend on API contracts, control flow, borrowed references, error paths,
reference-stealing operations, and object lifetime conventions.

---

# API and compatibility review

The analyzer checks for compatibility-sensitive changes such as:

* public Python signature changes
* positional-only parameter changes
* keyword-only parameter changes
* removed parameters
* public C header changes
* stable-ABI-sensitive changes
* grammar changes

Grammar findings include the relevant regeneration workflow:

```powershell
make regen-pegen && make regen-all && make regen-clinic
```

The purpose is to identify areas that deserve maintainer inspection rather than
to automatically classify a change as incompatible.

---

# CODEOWNERS

The tool fetches CODEOWNERS from the PR's **base SHA**, rather than assuming
that the current default branch represents the ownership rules that applied to
the PR.

The candidates are checked in this order:

1. `.github/CODEOWNERS`
2. `CODEOWNERS`
3. `docs/CODEOWNERS`

The last-matching-pattern rule is respected.

This allows routing decisions to be based on repository ownership information
that is relevant to the analyzed PR.

---

# Reviewer routing data

`scripts/triager/reviewer_profiles.py` contains project-maintained,
subsystem-specific routing guidance.

For example, a subsystem may have guidance that a particular generated file
requires a regeneration command.

This information is **generic subsystem guidance**.

It is not a record of anything a named individual has personally said or done.

The tool therefore keeps two concepts separate:

```text
Generic subsystem guidance
        ≠
Actual reviewer behavior
```

Actual reviewer behavior is derived from
`scripts/triager/reviewer_activity.py` using live GitHub evidence when
available.

The tool does not substitute generic routing data for unavailable
reviewer-specific evidence.

---

# Historical statistics

Generate a historical sample with:

```powershell
python scripts/analyze.py --learn-patterns 500 --output-patterns data/patterns.json
```

The collector walks the paginated pull-request endpoint instead of treating a
single search page as a complete historical sample.

The generated data records information such as:

* requested sample size
* candidate population
* actual collected records
* sampling method
* generation timestamp
* size percentiles
* merged-PR statistics
* label frequencies
* base-branch frequencies

Historical statistics are **descriptive**.

They should not be treated as proof that:

* a particular PR is abnormal
* a particular change is unsafe
* a particular reviewer will approve a change
* a PR should or should not merge

Historical data provides context, not authority.

---

# AI synthesis

No AI key is required for the deterministic report.

AI synthesis is optional and runs **after** the deterministic evidence package
has been constructed.

## Anthropic

```powershell
$env:ANTHROPIC_API_KEY="sk-ant-..."
python scripts/analyze.py 123456 --ai
```

## Gemini

```powershell
$env:GEMINI_API_KEY="..."
python scripts/analyze.py 123456 --ai --ai-provider gemini
```

The deterministic report is constructed first.

The model receives the collected evidence and deterministic analysis and is
instructed to:

* distinguish observed facts from inference
* identify uncertainty
* avoid claiming maintainer authority
* avoid inventing missing evidence
* summarize rather than override deterministic policy

AI output should therefore be treated as **synthesis and explanation**, not as
the source of truth.

Set a different Anthropic model when required:

```powershell
$env:ANTHROPIC_MODEL="claude-opus-5"
```

---

# Local cache

The CLI uses a local HTTP cache to reduce repeated GitHub API requests.

By default, cached responses are stored under:

```text
.triager-cache/
```

The cache directory is git-ignored.

The default cache lifetime is 15 minutes.

Change the TTL:

```powershell
$env:CPYTHON_TRIAGER_CACHE_TTL="3600"
```

Change the cache location:

```powershell
$env:CPYTHON_TRIAGER_CACHE="C:\temp\cache"
```

The cache is an optimization and is not a substitute for evidence freshness
where freshness is explicitly required.

---

# GitHub authentication

Set the GitHub token:

```powershell
$env:GITHUB_TOKEN="YOUR_TOKEN"
```

Do not commit the token.

Without authentication, GitHub API rate limits are significantly lower and
some evidence collection may become unavailable or partial.

---

# Testing

The canonical test command is:

```powershell
pip install -e ".[test]"
python -m pytest -q
```

The same test suite is used by CI through:

```text
.github/workflows/tests.yml
```

The current repository test suite contains **757 tests** covering the major
components of the project.

The most recent full local validation for this version completed with:

```text
757 passed
```

## Test coverage areas

| File                                 | Coverage                                                |
| ------------------------------------ | ------------------------------------------------------- |
| `tests/test_triager.py`              | `analyze.py` orchestration                              |
| `tests/test_analyzers.py`            | Static analysis rules                                   |
| `tests/test_policy.py`               | Process/policy signals, branch rules, backport handling |
| `tests/test_references.py`           | GitHub, PEP, and discussion reference extraction        |
| `tests/test_github.py`               | GitHub client, pagination, caching, retries             |
| `tests/test_reviewer_profiles.py`    | Static subsystem routing data                           |
| `tests/test_reviewer_activity.py`    | Live reviewer activity derived from GitHub evidence     |
| `tests/test_snapshot.py`             | Evidence snapshot normalization and round trips         |
| `tests/test_report.py`               | Report construction and evidence presentation           |
| `tests/test_models.py`               | Data models and serialization                           |
| `tests/test_history.py`              | Historical statistics                                   |
| `tests/test_ai.py`                   | AI synthesis behavior                                   |
| `tests/test_providers.py`            | AI provider integrations                                |
| `tests/test_codeowners.py`           | CODEOWNERS parsing and matching                         |
| `tests/test_update_branch_policy.py` | Branch-policy update tooling                            |

---

# Important limitations

CPython PR Triager is a **maintainer-assist tool**, not an automated merge
authority.

No static heuristic, historical statistic, or LLM can establish by itself
that a CPython change is correct.

A high-quality triage result should answer:

1. What evidence was collected?
2. What is directly observed?
3. What is deterministically derived?
4. What deserves human review?
5. Which repository ownership information is relevant?
6. What process gates remain?
7. What evidence is missing or unavailable?
8. Where does uncertainty remain?

The tool is deliberately designed to expose those distinctions rather than
hide them behind a single confidence score.

---

# Evidence completeness

Different data sources can have different availability states.

For example:

```text
reviews: available
review_threads: unavailable
```

does **not** mean:

```text
review_threads: zero
```

Similarly, a browser-side one-page API result does not imply that the complete
GitHub collection has been retrieved.

When evidence is incomplete, the tool should expose that limitation so that a
maintainer can decide whether additional investigation is necessary.

---

# Web triager limitations

`index.html` is designed for convenience and quick inspection.

It:

* runs entirely in the browser
* talks directly to GitHub
* has no server-side cache
* does not call an AI model
* has its own smaller deterministic analyzer
* fetches only one page per GitHub endpoint
* can therefore produce partial evidence when GitHub pagination limits are
  reached

When the web tool encounters a pagination limit, it indicates that the
evidence is partial.

For complete evidence collection, use:

```powershell
python scripts/analyze.py <PR_NUMBER>
```

---

# Project structure

```text
.
├── .github/
│   └── workflows/
│       └── tests.yml
├── data/
│   ├── .gitkeep
│   ├── branch-policy.json
│   └── cpython-review-policy.json
├── scripts/
│   ├── analyze.py
│   ├── check_ci.py
│   ├── update_branch_policy.py
│   └── triager/
│       ├── ai.py
│       ├── analyzers.py
│       ├── codeowners.py
│       ├── diff.py
│       ├── github.py
│       ├── history.py
│       ├── models.py
│       ├── policy.py
│       ├── providers.py
│       ├── references.py
│       ├── report.py
│       ├── reviewer_activity.py
│       ├── reviewer_profiles.py
│       └── snapshot.py
├── tests/
├── index.html
├── review-ui.css
├── pyproject.toml
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

# Changelog and audit history

The project has gone through multiple correctness and security-oriented audit
passes.

See [`CHANGELOG.md`](CHANGELOG.md) for:

* changes made in response to audits
* known limitations
* intentionally deferred work
* changes to evidence collection
* changes to reviewer analysis
* changes to policy handling
* changes to static analysis

Before relying on the tool for a particular triage workflow, review the
**Known, currently-accepted limitations** section of the changelog.

---

# License

Apache License 2.0 — see [`LICENSE`](LICENSE).

CPython PR Triager is independent tooling for working with
`python/cpython`. It is **not part of CPython itself** and is not covered by
the Python Software Foundation License.
