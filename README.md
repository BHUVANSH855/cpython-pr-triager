# CPython PR Triager

An evidence-first maintainer-assist tool for `python/cpython`.

The goal is not to replace maintainers. The tool gathers repository evidence,
highlights review questions, routes changes toward current CODEOWNERS, checks
process signals, and optionally asks an LLM to synthesise the evidence.

## Design principles

1. **Evidence before inference.**
2. **Heuristics are review prompts, never proof of a defect.**
3. **Repository-current data beats hard-coded assumptions.**
4. **Complete pagination is preferred to arbitrary first-page limits.**
5. **Historical statistics are descriptive and reproducible, not universal truth.**
6. **AI is a synthesis layer, not the decision maker.**
7. **Incomplete evidence must be visible.**

## Two distinct tools

This repository ships two separate tools that do **not** share code:

| Tool | File | How it works |
|------|------|--------------|
| **Python CLI** | `scripts/analyze.py` | Runs server-side. Full pagination, caching, retries, CODEOWNERS from the live repo. Use this for reliable results. |
| **Web triager** | `index.html` | Runs in-browser. Calls the GitHub API and Anthropic API directly. Faster to share but has no server-side caching or pagination guarantees. |

The web UI (`index.html`) contains its own hard-coded CODEOWNERS expert list
and layout rules which may drift from the Python package. Treat it as a
quick-look tool, not a source of truth.

## Requirements

- Python 3.11+
- No third-party Python packages
- Internet access to the GitHub REST API
- `GITHUB_TOKEN` is strongly recommended (5 000 req/hr vs 60 unauthenticated)

Optional:

- `ANTHROPIC_API_KEY` for AI synthesis

## Run

From the **project root** (required so the package import works):

```powershell
python scripts/analyze.py 123456
```

JSON output:

```powershell
python scripts/analyze.py 123456 --json > report.json
```

Skip linked issue history (faster, but less evidence — prints a warning):

```powershell
python scripts/analyze.py 123456 --no-linked-issues
```

Disable the local HTTP cache:

```powershell
python scripts/analyze.py 123456 --no-cache
```

> **Important:** always run from the repository root, not from inside `scripts/`.
> The package import (`from scripts.triager import ...`) requires the root to be
> on `sys.path`.  Running `python scripts/analyze.py` from the root works because
> `analyze.py` adds the root to `sys.path` automatically.  Running
> `cd scripts && python analyze.py` will fail with `ModuleNotFoundError`.

## Historical statistics

Generate a real historical sample (walks the full paginated endpoint):

```powershell
python scripts/analyze.py --learn-patterns 500 --output-patterns data/patterns.json
```

The collector walks the paginated pull-request endpoint rather than pretending
that a single 100-result search page is a 500-PR dataset.

The output records requested sample size, candidate population, actual collected
records, sampling method, generation timestamp, size percentiles, merged-PR
statistics, label frequencies, and base-branch frequencies.

These statistics are descriptive. They should not be treated as proof that a
particular PR is abnormal or unsafe.

## AI synthesis

```powershell
$env:ANTHROPIC_API_KEY="..."
python scripts/analyze.py 123456 --ai
```

The deterministic report is constructed first. The model receives that evidence
package and is instructed to distinguish facts from inference and never claim
maintainer authority.

Set a different model if required:

```powershell
$env:ANTHROPIC_MODEL="claude-opus-5"
```

## What the analyzer examines

### Repository evidence

- PR metadata
- complete changed-file pagination
- complete reviews
- complete inline review comments
- complete issue comments
- complete issue timeline (with bot events correctly identified)
- linked issue references (gh-NNNNN, bpo-NNN, closes #NNN, etc.)
- linked issue comments/timeline
- PEP references
- discuss.python.org thread URLs
- current repository labels
- PR-base CODEOWNERS (fetched live from the repo at the base SHA)
- PR head checks/statuses

### Process signals

- current labels and their meanings
- `DO-NOT-MERGE`
- `awaiting changes` / `awaiting merge`
- NEWS entry presence (or `skip news` waiver)
- test coverage signals
- review state (approvals, change requests, stale PRs)
- maintenance-branch policy signals
  - 3.10 is **security-fix-only** — bug and feature PRs are blocked
  - 3.11–3.13 stable — only bug fixes
  - 3.14 prerelease — features allowed carefully
- `needs-backport-to-X.Y` label detection (hyphenated format)
- current CI/check state

### Technical review prompts

**C / memory safety:**
- `gets()` → CRITICAL
- `sprintf()` → CRITICAL (use `PyOS_snprintf()`)
- `strcpy()` / `strcat()` → HIGH
- `malloc()`, `free()`, `realloc()`, `calloc()` → HIGH (use `PyMem_*`)
- `PyCObject_*` → CRITICAL (removed; use `PyCapsule`)

**CPython internals:**
- Private `_Py_*` API usage
- `PyErr_Clear()` silently discarding exceptions
- `_Py_IDENTIFIER` (deprecated; use `&_Py_ID()`)
- GIL/thread-state boundaries (`Py_BEGIN/END_ALLOW_THREADS`)
- Free-threading risk in GIL-sensitive subsystems (with `--disable-gil` note)

**Python:**
- `eval()` / `exec()` — AST-confirmed
- `pickle.load()` — untrusted input risk
- `subprocess shell=True` — injection risk
- `tempfile.mktemp()` — TOCTOU race
- `hashlib.md5()` / `hashlib.sha1()` — cryptographically broken
- bare `except:` — catches `BaseException`
- `assert` in non-test production code
- `global` statement — module-level shared state
- `DeprecationWarning` without `stacklevel=` — shows wrong call site

**API / compatibility:**
- Public Python signature changes (positional-only, keyword-only, removed params)
- Public C header changes (stable ABI impact)
- Grammar changes (includes exact `make regen-pegen && make regen-all && make regen-clinic` command)
- Low-confidence refcount imbalance prompts (INCREF vs DECREF count)

The analyzer scans newly added diff lines where possible. It does not claim
that a matching pattern is itself a vulnerability.

## CODEOWNERS

The tool fetches the live CODEOWNERS file from the PR base SHA using these
candidates in order:

1. `.github/CODEOWNERS`
2. `CODEOWNERS`
3. `docs/CODEOWNERS`

The last-matching-pattern rule is followed correctly.

## Local cache

Responses are cached under `.triager-cache/` (git-ignored, expires in 15 min).

```powershell
$env:CPYTHON_TRIAGER_CACHE_TTL="3600"   # change TTL in seconds
$env:CPYTHON_TRIAGER_CACHE="C:\temp\cache"  # change location
```

## GitHub authentication

```powershell
$env:GITHUB_TOKEN="YOUR_TOKEN"
```

Do not commit the token. Without a token the API rate limit is 60 requests/hr.

## Testing

```powershell
# From the repository root:
python -m unittest discover -s tests -v
```

Test files:

| File | What it covers |
|------|---------------|
| `tests/test_triager.py` | `analyze.py` orchestration layer |
| `tests/test_analyzers.py` | Static analysis rules (all 23-point fixes) |
| `tests/test_policy.py` | Process/policy signals, branch rules, backport regex |
| `tests/test_references.py` | Reference extraction (gh-, bpo-, discuss.python.org) |
| `tests/test_github.py` | GitHub client (pagination, caching, retries) |

## Important limitations

No static heuristic, historical statistic, or LLM can establish that a CPython
change is correct by itself.

A high-quality triage result answers:

1. What evidence was collected?
2. What is definitely observed?
3. What deserves human review?
4. Who appears relevant according to current repository ownership?
5. What process gates remain?
6. What evidence is missing or uncertain?

That is the standard this project is designed around.