# CPython PR Triager

An evidence-first maintainer-assist tool for `python/cpython`.

The goal is not to replace maintainers. The tool gathers repository evidence, highlights review questions, routes changes toward current CODEOWNERS, checks process signals, and optionally asks an LLM to synthesize the evidence.

## Design principles

1. **Evidence before inference.**
2. **Heuristics are review prompts, never proof of a defect.**
3. **Repository-current data beats hard-coded assumptions.**
4. **Complete pagination is preferred to arbitrary first-page limits.**
5. **Historical statistics are descriptive and reproducible, not universal truth.**
6. **AI is a synthesis layer, not the decision maker.**
7. **Incomplete evidence must be visible.**

## Requirements

- Python 3.11+
- No third-party Python packages
- Internet access to the GitHub REST API
- `GITHUB_TOKEN` is strongly recommended for reliable rate limits

Optional:
- `ANTHROPIC_API_KEY` for AI synthesis

## Run

From the project root:

```powershell
python scripts/analyze.py 123456
```

JSON:

```powershell
python scripts/analyze.py 123456 --json > report.json
```

Skip linked issue history when you need a cheaper run:

```powershell
python scripts/analyze.py 123456 --no-linked-issues
```

Disable the local HTTP cache:

```powershell
python scripts/analyze.py 123456 --no-cache
```

## Historical statistics

Generate a real historical sample:

```powershell
python scripts/analyze.py --learn-patterns 500 --output-patterns data/patterns.json
```

The collector walks the paginated pull-request endpoint rather than pretending that a single 100-result search page is a 500-PR dataset.

The output records:

- requested sample size
- candidate population
- actual collected records
- sampling method
- generation timestamp
- size percentiles
- merged-PR statistics
- label frequencies
- base-branch frequencies
- individual sample records

These statistics are descriptive. They should not be treated as proof that a particular PR is abnormal or unsafe.

## AI synthesis

```powershell
$env:ANTHROPIC_API_KEY="..."
python scripts/analyze.py 123456 --ai
```

The deterministic report is constructed first. The model receives that evidence package and is instructed to distinguish facts from inference and never claim maintainer authority.

Set a different model if required:

```powershell
$env:ANTHROPIC_MODEL="..."
```

## What the analyzer examines

### Repository evidence

- PR metadata
- complete changed-file pagination
- complete reviews
- complete inline review comments
- complete issue comments
- complete issue timeline
- linked issue references
- linked issue comments/timeline
- PEP references
- Python Discussions references
- current repository labels
- PR-base CODEOWNERS
- PR head checks/statuses

### Process

- current labels and label descriptions
- `DO-NOT-MERGE`
- author-action labels
- NEWS signals
- test coverage signals
- review state
- stale/inactive signals
- maintenance-branch policy signals
- `needs backport to X.Y` labels
- current CI/check state

### Technical review prompts

- unsafe C APIs
- private `_Py_*` APIs
- exception clearing
- GIL/thread-state boundaries
- Python `eval`/`exec`
- pickle loading
- shell execution
- unsafe temporary-file creation
- bare `except`
- `assert` in non-test Python
- public-looking Python signature changes
- public C header changes
- grammar changes
- low-confidence refcount prompts

The analyzer scans newly added diff lines where possible. It does not claim that a matching pattern is itself a vulnerability.

## CODEOWNERS

The tool first looks for:

1. `.github/CODEOWNERS`
2. `CODEOWNERS`
3. `docs/CODEOWNERS`

using the PR base commit.

It follows the important CODEOWNERS rule that the **last matching pattern wins**.

The matcher intentionally covers common CODEOWNERS patterns and refuses to pretend that unsupported syntax is exact.

## Local cache

Responses are cached under:

```text
.triager-cache/
```

The cache is ignored by Git and expires after 15 minutes by default.

Change the TTL:

```powershell
$env:CPYTHON_TRIAGER_CACHE_TTL="3600"
```

Change the cache location:

```powershell
$env:CPYTHON_TRIAGER_CACHE="C:\temp\cpython-triager-cache"
```

## GitHub authentication

Set a token in PowerShell:

```powershell
$env:GITHUB_TOKEN="YOUR_TOKEN"
```

A token is especially useful when collecting many historical PRs because GitHub rate limits API requests.

Do not commit the token.

## Testing

Run:

```powershell
python -m unittest discover -s tests -v
```

Run syntax validation:

```powershell
python -m py_compile scripts/analyze.py
```

## Suggested validation methodology

Before trusting the tool on new PRs, build a fixture set covering:

- bug fixes
- security fixes
- crash fixes
- features
- refactors
- documentation-only changes
- test-only changes
- C API changes
- grammar/parser changes
- maintenance-branch fixes
- backport PRs
- PRs with explicit process blockers
- PRs with long review histories
- PRs with no NEWS requirement

For every fixture, record:

- what the repository actually showed
- what a maintainer would reasonably notice
- what the deterministic analyzer reported
- which signals were useful
- which were false positives
- which important facts were missed

The objective is to reduce false positives and false negatives before adding more heuristics.

## Important limitation

No static heuristic, historical statistic, or LLM can establish that a CPython change is correct by itself.

A high-quality triage result should answer:

1. What evidence was collected?
2. What is definitely observed?
3. What deserves human review?
4. Who appears relevant according to current repository ownership?
5. What process gates remain?
6. What evidence is missing or uncertain?

That is the standard this project is designed around.
