# Changelog

This project has been through two external audit passes so far. This file
tracks what was actually fixed in response to each, using the audits' own
item IDs, so a reviewer can check specific claims against the diff instead
of taking a summary on faith.

Both audits are LLM-generated documents supplied by the maintainer, not
independent human review — they are treated here as a checklist to verify
against the code, not as ground truth. Several claims in the second audit
(e.g. specific coverage percentages, the `.github/workflows` omission)
were independently re-verified against this codebase before acting on them.

## Round 2 (this update) — response to `CPython_PR_Triager_Updated_Deep_Audit.md`

### Fixed

- **Packaging bug (found via audit's P1-20)**: the previous release zip's
  packaging command excluded `.github/workflows/tests.yml` because its
  `-x "*.git*"` exclude pattern also matches the unrelated `.github`
  directory. Fixed the packaging command; this zip includes `.github/`.
- **P0-02 / P0-03 — browser evidence gaps**: `index.html`'s changed-files
  fetch now flags when it hits GitHub's 100-item page cap. The file-history,
  linked-issues, PEP, and discuss.python.org collectors now report their
  caps (requested vs. collected vs. reason) into the same partial-evidence
  banner introduced in the previous round, instead of only some collectors
  disclosing their limits.
- **P0-05 — AI prompt truncation**: `_compact_report()` in `ai.py` no
  longer truncates evidence by raw character offset. It now serializes
  fields in a fixed priority order (disposition, evidence completeness,
  process signals, technical findings, CI state, PR metadata, ownership,
  history, then everything else) and stops adding fields once the budget
  is spent, naming the omitted sections explicitly. This means the fields
  a maintainer most needs to trust a result are the ones least likely to
  be dropped on an unusually large PR. New tests
  (`test_compact_report_preserves_high_priority_fields_when_truncating`)
  assert this directly with a synthetic oversized payload.
- **P0-06 — CI freshness**: `build_checks()` in `analyze.py` now
  independently checks whether every returned check run's own `head_sha`
  actually matches the PR's current head SHA, rather than only trusting
  the request parameters used to fetch them. Exposes `pr_head_sha`,
  `ci_fresh`, and `stale_check_shas`; raises a `WARN` process signal on
  mismatch; the CLI prints an explicit FRESH/STALE/unknown line.
- **P1-04 — reviewer approval-rate sample size**: `reviewer_activity.py`
  now suppresses `approval_rate` entirely below `MIN_APPROVAL_RATE_SAMPLE`
  (5) verdicts instead of reporting a falsely precise percentage from a
  tiny sample. The real sample size (`approval_rate_sample_size`) is
  always exposed so a report can say "insufficient sample (n=3)" instead
  of silently having no signal at all. Threaded through `ExpertContext`
  and the CLI printer.
- **P1-08 — raw-content host allowlist**: `GitHub.raw_content()` now
  rejects any `download_url` whose host isn't one of
  `raw.githubusercontent.com`, `github.com`, `api.github.com`, or
  `codeload.github.com`, raising `GitHubError` instead of fetching it.
  `download_url` always comes from GitHub's own API response in normal
  operation, so this is defense-in-depth, not a fix for an observed
  exploit.
- **P1-09 — AI expert-routing owner validation**: the prompt already told
  the model not to invent reviewers; `_parse_response()` now also checks
  AI-suggested `expert_routing` owners against the deterministic expert
  evidence the report actually carried, and records any owner outside
  that set in `unverified_expert_owners` rather than trusting it silently.
- **Not in the audit, found while fixing P0-05/P1-09 — AI disposition
  enforcement was prompt-only, not code-enforced.** The prompt already
  said "the model must preserve deterministic disposition," but nothing
  in `ai.py` actually checked that. `_parse_response()` now always
  overrides the returned `triage` field with the deterministic
  disposition; if the model disagreed, that disagreement is kept visible
  in `ai_triage_disagreement` instead of being silently discarded or,
  worse, silently trusted.

### Added

- **P1-11 — adversarial prompt-injection test fixtures**: `test_ai.py`
  now includes parametrized tests with hostile payloads (`SYSTEM: ignore
  previous instructions...`, fake role claims, attempts to break out of
  the JSON evidence blob) proving the fixed instructional guard text
  survives verbatim and that hostile content can only ever reach the
  model as properly escaped, inert JSON data. This tests what `ai.py`
  actually controls (prompt construction); it does not and cannot test a
  live model's behavior, since this module never calls a real provider.
- **S5 — secret-boundary test**: `test_environment_secrets_are_not_
  injected_into_evidence` proves the evidence pipeline never pulls
  `GITHUB_TOKEN`/`ANTHROPIC_API_KEY`-style values from the process
  environment into the built prompt.
- `CHANGELOG.md` (this file).

### Explicitly not attempted in this round, with reasons

- **P0-01 — unify the CLI and web analyzers.** The web UI has no backend;
  making it call the Python engine requires a server component this
  project doesn't have. Documented as an open architectural item, not
  something a text edit can resolve.
- **P0-04 — per-source COMPLETE/PARTIAL/EMPTY/UNAVAILABLE/FAILED/SAMPLED
  status enum** for `ReviewSnapshot`. The existing complete/partial/
  unavailable model is real (verified directly against `snapshot.py`,
  not just the audit's claim) but does conflate "collected everything"
  with "collected within an intentional bound." A full enum migration
  touches many call sites and tests; deferred rather than rushed.
- **P0-07 — unresolved review-thread state.** GitHub only exposes
  thread-resolution status via GraphQL, which this project doesn't
  currently call. A real implementation needs a new authenticated
  GraphQL path and cannot be meaningfully tested in this sandbox (GraphQL
  requires a token; this environment's GitHub API quota was exhausted for
  both this round and the previous one).
- **P1-17/P1-18 — a real 150-PR CPython benchmark corpus and per-rule
  precision measurement.** Requires live GitHub API access this sandbox
  does not currently have (confirmed: `core` rate limit was 0/60
  remaining both times this was checked). No amount of code editing
  substitutes for actually running the tool against real PRs.
- ruff/mypy/bandit CI integration, coverage-gate enforcement, `src/`
  layout migration, rule-registry/rule-inventory generation — all real P2
  items, not started this round due to time; they don't change tool
  correctness or trustworthiness the way the P0/P1 items above do.

## Round 1 — response to the first deep audit

- Removed fabricated per-person quotes and response-time numbers from
  `reviewer_profiles.py` (the static "known_concerns"/"typical_response_
  days" table was presenting invented text as if it were something named,
  real CPython maintainers had actually said).
- Fixed the web UI's "Deep AI synthesis" step label — no LLM is called in
  browser mode; the step now says so.
- Added a browser partial-evidence banner for the timeline/reviews/
  comments endpoints that hit their first-page limit.
- Fixed the README's test instructions (`pytest`, not `unittest`) and its
  stale description of the web UI's CODEOWNERS handling.
- Added `LICENSE` (Apache-2.0).

## Round 3 — crash found by actually running the CLI against a real, live CPython PR

This is the payoff of the "you need to run this against real PRs" advice
repeated at the end of every previous round. First real run, first real
crash, found in minutes — no amount of additional code review or unit
testing surfaced this on its own.

### Fixed

- **`build_report()` crashed on any PR with a failing CI check.**
  `report.py`'s CI-failure-warning branch called
  `ProcessSignal(signal="WARN", message=...)`, but `ProcessSignal`'s
  actual field is `level`, not `signal` (every other `ProcessSignal`
  construction site in the codebase already used `level` correctly — this
  one call site didn't). Nothing in Rounds 1–2 touched this specific
  branch, so it predates this audit process, but it wasn't verified via
  `git blame` — stated here as "not one of ours," not as a verified fact.

  **Why 656/656 passing tests and 90% coverage didn't catch it:** every
  single test in `test_report.py` that exercises `build_report()` with a
  `checks` argument used `"failures": 0`, so the `if failures:` branch
  containing the bug was never executed by the test suite at all. This is
  a textbook case of the first audit's warning that coverage percentage
  and coverage *of the paths that matter* are different things — 90%
  coverage measured lines executed, not decision branches with real,
  nonzero inputs.

  Fixed the typo, and added
  `test_build_report_warns_on_ci_failures_without_crashing`, which
  exercises the branch with `"failures": 2` and would have caught this
  immediately. Confirmed by reverting the fix and re-running the new
  test alone: it fails with the exact same `TypeError` the user hit on
  the real PR, then passes once the fix is back.

- Also ran a mechanical sweep (AST-based, not manual) across every
  dataclass constructor call site in `scripts/` for the same class of
  bug (keyword argument not matching an actual dataclass field). No
  other instances found.

- **Same live run surfaced a second, real accuracy bug: duplicate CI-
  failure signals.** Once the crash above was fixed, the actual PR output
  showed the same fact reported twice:

  ```
  [BLOCK] 1 completed CI check(s) reported failure; the PR is not ready to merge...
  [WARN] 1 completed CI check(s) have failure-like conclusions.
  ```

  `build_report()` was independently re-deriving a CI-failure signal from
  raw check data — the exact same computation `analyze.py`'s
  `mergeability_signals()` already does more richly (correct BLOCK
  severity, better message) and already passes in via the `process`
  argument. Two code paths computing the same fact and both surfacing it
  is the same class of problem the CLI/web-UI duplication findings in the
  earlier audits were about, just at a smaller scope: `build_report()`
  should treat `process` as its single source of truth for process
  signals instead of also manufacturing its own from raw evidence it
  wasn't authoritative over. Removed the duplicate derivation; added
  tests asserting `build_report()` no longer invents signals on its own
  and correctly surfaces exactly the signal(s) its caller supplies.

  **This would not have been caught by re-reading the code** — both
  branches were individually reasonable-looking. It only became visible
  by reading real, rendered output from a real PR side by side.

### What this means for the "no real-PR validation yet" limitation

This is the first real signal that the deterministic report path has now
actually been exercised against live, non-synthetic GitHub API responses,
and it immediately found something the test suite missed. That's a
point in favor of continuing to run this against more real PRs — do not
treat "656 tests pass" as equivalent to "this works," a point this file
has made before and is now making with a concrete example instead of
just a warning.

## Round 4 — real accuracy bug found by reading real PR output closely (not just checking for crashes)

### Fixed

- **`_is_test_path()` in `analyzers.py` missed real CPython test
  directories, causing false "no test file changed" findings.** The
  function only recognized `Lib/test/`, `Tools/test/`, and
  `Modules/_testcapi/` as test locations. CPython actually keeps tests
  for several stdlib packages in their own nested `test/` directory —
  `Lib/ctypes/test/`, `Lib/tkinter/test/`, `Lib/sqlite3/test/`,
  `Lib/unittest/test/` — or a differently-named one
  (`Lib/idlelib/idle_test/`). A PR that added a real test file in any of
  those locations would be misclassified as having zero test coverage,
  producing a false-positive review prompt on a PR that did the right
  thing. Confirmed directly against real paths before fixing (not just
  inferred):

  ```
  'Lib/ctypes/test/test_values.py': analyzers.py says test=False   # wrong
  'Lib/tkinter/test/test_tkinter/test_widgets.py': test=False      # wrong
  'Lib/sqlite3/test/test_dbapi.py': test=False                     # wrong
  'Lib/idlelib/idle_test/test_editor.py': test=False               # wrong
  'Lib/unittest/test/test_case.py': test=False                     # wrong
  'Lib/test/test_asyncio/test_tasks.py': test=True                 # only this one was right
  ```

  This is worse than the Round 3 findings: those were about the *same*
  fact being reported redundantly or crashing outright. This one is two
  independently-maintained classifiers (`analyzers.py`'s `_is_test_path`
  vs `policy.py`'s broader, correct test-file detection in
  `file_signals`) *disagreeing* on real inputs — meaning the tool could
  actively mislead a maintainer into thinking test coverage was missing
  when it wasn't. Fixed by broadening `_is_test_path` to match
  `policy.py`'s semantics (nested `/test/`, `/tests/`, or a `test_`-
  prefixed basename, not just a fixed prefix list).

  **How this was found**: not by code review, and not by unit tests (none
  existed for this function before this fix) — by reading real,
  rendered CLI output against a real, open CPython PR (`#157349`) and
  independently sanity-checking one of its findings against actual
  CPython repository layout knowledge, rather than trusting that "the
  tool ran without crashing" meant "the tool was right."

  Added `TestPathClassificationTests` in `test_analyzers.py`: direct
  unit tests for `_is_test_path` against real CPython paths, plus an
  end-to-end test through `analyze_files()` proving no false-positive
  "no test file changed" finding is produced when a nested-directory
  test file is present. Verified these tests actually catch the original
  bug by reverting the fix and confirming 6 of them fail with the exact
  mismatch, then re-applying the fix and confirming all pass.

### Noted but not changed

- The same underlying "no test file changed" fact is still reported from
  two places when it's genuinely true: a PR-level `[WARN]` process signal
  (`policy.py`) and a file-level `[LOW]` technical finding
  (`analyzers.py`), as seen in PR #157349's real output. Unlike the
  Round 3 CI-failure case, these aren't verbatim-identical claims — one
  is PR-wide, one names the specific file — so this was left as a
  judgment call rather than deduplicated outright. Worth revisiting if a
  maintainer using the tool finds it noisy in practice.

## Known, currently-accepted limitations (as of Round 4)

- The web UI (`index.html`) remains a separate, smaller implementation of
  the analysis rules from the Python CLI. Treat the CLI as authoritative;
  the web UI as a quick-look/demo tool. See `README.md`.
- No real-world CPython PR benchmark exists yet. All 656 tests passing
  and ~90% coverage demonstrate the implementation matches its own test
  fixtures — they do not demonstrate triage accuracy against real CPython
  PRs. Do not treat either number as evidence of the latter. (Round 3's
  crash is the concrete proof of that gap, not just an assertion of it.)
