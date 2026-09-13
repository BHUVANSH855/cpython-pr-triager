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
| **Web triager** | `index.html` | Runs in-browser. Calls the GitHub API directly. Fetches CODEOWNERS live from the PR's base SHA, same as the CLI. Faster to share, but fetches only **one page per GitHub endpoint** (no follow-up pagination) — the page shows an "EVIDENCE: PARTIAL" notice when a page limit is hit. It has no server-side caching, and it never calls an AI model (there is no LLM synthesis step in the browser tool, only the same deterministic static-analysis rules). |

The web UI (`index.html`) has its own implementation of the deterministic
analysis rules, kept deliberately smaller than the Python package. Treat it
as a quick-look tool, not a source of truth; the CLI is the reliable,
completely-paginated path.

## Requirements

- Python 3.11+
- No third-party Python packages at runtime
- `pytest` is required to run the test suite (`pip install -e ".[test]"`)
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

No AI key is required for the deterministic report. To enable AI synthesis:

**Anthropic:**

```powershell
$env:ANTHROPIC_API_KEY="sk-ant-..."
python scripts/analyze.py 123456 --ai
```

**Gemini (free tier):**

```powershell
$env:GEMINI_API_KEY="..."
python scripts/analyze.py 123456 --ai --ai-provider gemini
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
  - CPython branch lifecycle is evaluated from the repository's branch-policy
    snapshot rather than inferred from version numbers:

    | Branch | Current lifecycle status |
    |--------|--------------------------|
    | `main` | Feature development |
    | `3.15` | Prerelease |
    | `3.14` | Bugfix / maintenance |
    | `3.13` | Bugfix / maintenance |
    | `3.12` | Security-fix-only |
    | `3.11` | Security-fix-only |
    | `3.10` | Security-fix-only |
  - The analyzer treats these statuses as policy evidence and emits a review
    signal when a PR's labels or target branch appear inconsistent with the
    current lifecycle policy.
- `needs backport to X.Y` label detection (current spaced format; the
  legacy hyphenated `needs-backport-to-X.Y` is also recognized for
  compatibility with older PRs, but current CPython PRs use the spaced form)
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

## Reviewer routing data — what's real and what's generic

`scripts/triager/reviewer_profiles.py` groups a per-subsystem review
checklist under the username that owns that area in CODEOWNERS (e.g.
"changes to `bytecodes.c` usually need `make regen-cases`"). **This
checklist is generic, project-maintained guidance about the subsystem —
it is never a record of anything the named individual has actually said,
and it must not be presented as a quote or personal characterization.**

Anything that claims to describe what a *specific person* actually does —
their approval rate, what they've recently asked for in reviews, response
patterns — comes only from `scripts/triager/reviewer_activity.py`, which
computes it live from that person's real, freshly-fetched GitHub review
comments (cached for 24h). If that live data isn't available, the tool
omits the per-person claim rather than substituting a guess.

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

The canonical, supported way to run the test suite is `pytest` (some test
files depend on it directly and will fail to even import under plain
`unittest`):

```powershell
pip install -e ".[test]"
python -m pytest -q
```

This is also exactly what CI runs (`.github/workflows/tests.yml`).

Test files:

| File | What it covers |
|------|---------------|
| `tests/test_triager.py` | `analyze.py` orchestration layer |
| `tests/test_analyzers.py` | Static analysis rules |
| `tests/test_policy.py` | Process/policy signals, branch rules, backport regex |
| `tests/test_references.py` | Reference extraction (gh-, bpo-, discuss.python.org) |
| `tests/test_github.py` | GitHub client (pagination, caching, retries) |
| `tests/test_reviewer_profiles.py` | Static subsystem routing data (see note below) |
| `tests/test_reviewer_activity.py` | Live, per-reviewer activity derived from real comments |

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

## License

Apache License 2.0 — see [LICENSE](LICENSE). This project is independent
tooling for working with `python/cpython`; it is not part of CPython
itself and is not covered by the PSF License.

## Changelog / audit history

This project has been through external audit passes; see
[CHANGELOG.md](CHANGELOG.md) for exactly what was fixed in response to
each, and what was deliberately deferred and why. If you're deciding
whether to trust this tool for a specific use, read that file's "Known,
currently-accepted limitations" section before the rest of this README.