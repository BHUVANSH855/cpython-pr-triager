from __future__ import annotations

from types import SimpleNamespace

from scripts.analyze import _suppress_redundant_process_signals
from scripts.triager.policy import disposition as policy_disposition
from scripts.triager.report import (
    _build_evidence_counts,
    _build_expert_contexts,
    _build_historical_context,
    build_report,
)


def _history_entry(
    sha: str = "abc123",
    message: str = "Update implementation",
    author: str = "developer",
    date: str = "2026-09-01T12:00:00Z",
    html_url: str = "https://github.com/python/cpython/commit/abc123",
) -> dict:
    return {
        "sha": sha,
        "message": message,
        "author": author,
        "date": date,
        "html_url": html_url,
    }


def _file(
    filename: str,
    history: list[dict] | None = None,
) -> dict:
    result = {
        "filename": filename,
        "status": "modified",
        "additions": 10,
        "deletions": 5,
    }

    if history is not None:
        result["history"] = history

    return result


class HistoricalContextTests:
    def test_empty_evidence_has_no_history(self):
        result = _build_historical_context({})

        assert result == {
            "available": False,
            "status": "complete",
            "history_files": 0,
            "history_commits": 0,
            "history_errors": 0,
            "files": [],
        }

    def test_builds_context_for_file_history(self):
        history = [
            _history_entry(
                sha="abc123",
                message="Latest change",
                author="alice",
            ),
            _history_entry(
                sha="def456",
                message="Older change",
                author="bob",
            ),
        ]

        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        history,
                    )
                ]
            }
        )

        assert result["available"] is True
        assert result["status"] == "complete"
        assert result["history_files"] == 1
        assert result["history_commits"] == 2
        assert result["history_errors"] == 0

        assert result["files"] == [
            {
                "filename": "Objects/object.c",
                "commit_count": 2,
                "latest_commit": {
                    "sha": "abc123",
                    "message": "Latest change",
                    "author": "alice",
                    "date": "2026-09-01T12:00:00Z",
                    "html_url": (
                        "https://github.com/python/cpython/"
                        "commit/abc123"
                    ),
                },
                "authors": [
                    "alice",
                    "bob",
                ],
            }
        ]

    def test_files_without_history_are_not_reported(self):
        result = _build_historical_context(
            {
                "files": [
                    _file("Objects/object.c"),
                    _file(
                        "Python/pythonrun.c",
                        [],
                    ),
                ]
            }
        )

        assert result["available"] is True
        assert result["status"] == "complete"
        assert result["history_files"] == 1
        assert result["history_commits"] == 0

        assert result["files"] == [
            {
                "filename": "Python/pythonrun.c",
                "commit_count": 0,
                "latest_commit": None,
                "authors": [],
            }
        ]

    def test_multiple_files_are_summarized(self):
        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [
                            _history_entry(
                                sha="one",
                                author="alice",
                            )
                        ],
                    ),
                    _file(
                        "Python/pythonrun.c",
                        [
                            _history_entry(
                                sha="two",
                                author="bob",
                            ),
                            _history_entry(
                                sha="three",
                                author="alice",
                            ),
                        ],
                    ),
                ]
            }
        )

        assert result["history_files"] == 2
        assert result["history_commits"] == 3
        assert [
            item["filename"]
            for item in result["files"]
        ] == [
            "Objects/object.c",
            "Python/pythonrun.c",
        ]

    def test_invalid_history_entries_are_ignored(self):
        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [
                            _history_entry(
                                sha="abc",
                                author="alice",
                            ),
                            None,
                            "invalid",
                            123,
                        ],
                    )
                ]
            }
        )

        assert result["history_files"] == 1
        assert result["history_commits"] == 1
        assert result["files"][0]["commit_count"] == 1
        assert result["files"][0]["authors"] == ["alice"]

    def test_authors_are_unique_and_sorted(self):
        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [
                            _history_entry(
                                sha="one",
                                author="charlie",
                            ),
                            _history_entry(
                                sha="two",
                                author="alice",
                            ),
                            _history_entry(
                                sha="three",
                                author="charlie",
                            ),
                            _history_entry(
                                sha="four",
                                author="bob",
                            ),
                        ],
                    )
                ]
            }
        )

        assert result["files"][0]["authors"] == [
            "alice",
            "bob",
            "charlie",
        ]

    def test_missing_author_is_not_added(self):
        entry = _history_entry()
        entry["author"] = None

        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [entry],
                    )
                ]
            }
        )

        assert result["files"][0]["authors"] == []
        assert result["files"][0]["latest_commit"]["author"] is None

    def test_author_mapping_uses_login(self):
        entry = _history_entry()
        entry["author"] = {
            "login": "octocat",
            "name": "The Octocat",
        }

        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [entry],
                    )
                ]
            }
        )

        assert result["files"][0]["authors"] == ["octocat"]
        assert (
            result["files"][0]["latest_commit"]["author"]
            == "octocat"
        )

    def test_author_mapping_falls_back_to_name(self):
        entry = _history_entry()
        entry["author"] = {
            "name": "Developer Name",
        }

        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [entry],
                    )
                ]
            }
        )

        assert result["files"][0]["authors"] == [
            "Developer Name"
        ]

    def test_date_falls_back_to_committed_at(self):
        entry = _history_entry()
        entry.pop("date")
        entry["committed_at"] = "2026-08-20T10:00:00Z"

        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [entry],
                    )
                ]
            }
        )

        assert (
            result["files"][0]["latest_commit"]["date"]
            == "2026-08-20T10:00:00Z"
        )

    def test_date_falls_back_to_created_at(self):
        entry = _history_entry()
        entry.pop("date")
        entry["created_at"] = "2026-08-19T10:00:00Z"

        result = _build_historical_context(
            {
                "files": [
                    _file(
                        "Objects/object.c",
                        [entry],
                    )
                ]
            }
        )

        assert (
            result["files"][0]["latest_commit"]["date"]
            == "2026-08-19T10:00:00Z"
        )

    def test_history_errors_make_context_available(self):
        result = _build_historical_context(
            {
                "files": [],
                "evidence_errors": {
                    "history:Objects/object.c": (
                        "GitHub request failed"
                    )
                },
            }
        )

        assert result["available"] is True
        assert result["status"] == "partial"
        assert result["history_files"] == 0
        assert result["history_commits"] == 0
        assert result["history_errors"] == 1
        assert result["files"] == []

    def test_none_history_error_is_not_counted(self):
        result = _build_historical_context(
            {
                "files": [],
                "evidence_errors": {
                    "history:Objects/object.c": None,
                },
            }
        )

        assert result["available"] is False
        assert result["history_errors"] == 0

    def test_non_history_errors_are_not_counted(self):
        result = _build_historical_context(
            {
                "files": [],
                "evidence_errors": {
                    "base_file_contents": "failed",
                    "history:Objects/object.c": "failed",
                },
            }
        )

        assert result["history_errors"] == 1

    def test_historical_prs_build_size_baseline(self):
        result = _build_historical_context(
            {
                "files": [],
                "historical_prs": [
                    {
                        "number": 1,
                        "additions": 10,
                        "deletions": 5,
                        "changed_files": 2,
                        "base": {"ref": "main"},
                    },
                    {
                        "number": 2,
                        "additions": 20,
                        "deletions": 10,
                        "changed_files": 3,
                        "base": {"ref": "main"},
                    },
                ],
            }
        )

        assert "size_baseline" in result
        assert result["size_baseline"]["sample_size"] == 2
        assert result["size_baseline"]["branches"] == {
            "main": 2,
        }

    def test_non_list_historical_prs_are_ignored(self):
        result = _build_historical_context(
            {
                "files": [],
                "historical_prs": "invalid",
            }
        )

        assert "size_baseline" not in result


class EvidenceCountsTests:
    def test_counts_history_files_and_commits(self):
        evidence = {
            "files": [
                _file(
                    "Objects/object.c",
                    [
                        _history_entry(sha="one"),
                        _history_entry(sha="two"),
                    ],
                ),
                _file(
                    "Python/pythonrun.c",
                    [
                        _history_entry(sha="three"),
                    ],
                ),
                _file("Doc/library.rst"),
            ]
        }

        result = _build_evidence_counts(
            evidence,
            [],
            SimpleNamespace(
                calls=0,
                cache_hits=0,
                rate_remaining=None,
                rate_reset=None,
            ),
        )

        assert result["history_files"] == 2
        assert result["history_commits"] == 3
        assert result["history_errors"] == 0

    def test_counts_history_errors(self):
        evidence = {
            "files": [],
            "evidence_errors": {
                "history:Objects/object.c": "failed",
                "history:Python/pythonrun.c": "failed",
                "base_file_contents": "failed",
            },
        }

        result = _build_evidence_counts(
            evidence,
            [],
            SimpleNamespace(
                calls=0,
                cache_hits=0,
                rate_remaining=None,
                rate_reset=None,
            ),
        )

        assert result["history_files"] == 0
        assert result["history_commits"] == 0
        assert result["history_errors"] == 2

    def test_none_history_errors_are_ignored(self):
        evidence = {
            "files": [],
            "evidence_errors": {
                "history:Objects/object.c": None,
                "history:Python/pythonrun.c": "failed",
            },
        }

        result = _build_evidence_counts(
            evidence,
            [],
            SimpleNamespace(
                calls=0,
                cache_hits=0,
                rate_remaining=None,
                rate_reset=None,
            ),
        )

        assert result["history_errors"] == 1

    def test_existing_evidence_counts_remain_present(self):
        evidence = {
            "files": [],
            "timeline": [
                {"bot": False},
                {"bot": True},
            ],
            "reviews": [{"id": 1}],
            "review_comments": [{"id": 2}],
            "issue_comments": [{"id": 3}],
        }

        result = _build_evidence_counts(
            evidence,
            [{"number": 123}],
            SimpleNamespace(
                calls=7,
                cache_hits=3,
                rate_remaining=4993,
                rate_reset=123456,
            ),
        )

        assert result["timeline_events"] == 2
        assert result["human_timeline_events"] == 1
        assert result["reviews"] == 1
        assert result["review_comments"] == 1
        assert result["issue_comments"] == 1
        assert result["linked_issues"] == 1
        assert result["api_calls"] == 7
        assert result["cache_hits"] == 3
        assert result["rate_limit_remaining"] == 4993
        assert result["rate_limit_reset"] == 123456


def test_evidence_errors_do_not_override_available_sources():
    from scripts.triager.report import _build_evidence_completeness

    result = _build_evidence_completeness({
        "pr": {},
        "files": [],
        "timeline": [],
        "reviews": [],
        "review_comments": [],
        "issue_comments": [],
        "evidence_errors": {"reviews": "transient failure after partial collection"},
    })

    assert "reviews" in result.available
    assert "reviews" not in result.missing
    assert "reviews" in result.errors


def test_explicit_evidence_statuses_override_presence_ambiguity():
    from scripts.triager.report import _build_evidence_completeness

    result = _build_evidence_completeness({
        "pr": {},
        "files": [],
        "timeline": [],
        "reviews": [],
        "review_comments": [],
        "issue_comments": [],
        "evidence_statuses": {
            "reviews": "failed",
            "timeline": "partial",
        },
    })

    assert "reviews" in result.missing
    assert "reviews" not in result.available
    assert "timeline" in result.available
    assert "timeline" not in result.missing


def test_file_patch_availability_survives_report_assembly():
    inputs = _build_report_inputs(evidence={
        "files": [{
            "filename": "Objects/object.c",
            "status": "modified",
            "additions": 1,
            "deletions": 0,
            "patch_available": True,
        }],
    })
    report = build_report(**inputs)

    assert report["files"][0]["patch_available"] is True


def test_raw_checks_are_json_safe():
    checks = {
        "summary": {},
        "check_runs": [],
        "unexpected": object(),
    }
    report = build_report(**_build_report_inputs(checks=checks))

    assert report["checks"]["unexpected"]["type"] == "object"
    assert isinstance(report["checks"]["unexpected"]["repr"], str)


def test_history_status_surfaces_sampling():
    result = _build_historical_context({
        "files": [_file("Objects/object.c", [_history_entry()])],
        "evidence_statuses": {"history:Objects/object.c": "sampled"},
    })

    assert result["available"] is True
    assert result["status"] == "sampled"


def _build_report_inputs(
    *,
    checks: dict | None = None,
    evidence: dict | None = None,
) -> dict:
    base_evidence = {
        "pr": {
            "number": 123,
            "title": "Test PR",
            "state": "open",
            "user": {"login": "developer"},
            "base": {"ref": "main", "sha": "base123"},
            "head": {"ref": "feature", "sha": "head123"},
            "labels": [],
        },
        "files": [],
        "timeline": [],
        "reviews": [],
        "review_comments": [],
        "issue_comments": [],
    }

    if evidence:
        base_evidence.update(evidence)

    return {
        "repository": "python/cpython",
        "generated_at": "2026-09-06T12:00:00Z",
        "evidence": base_evidence,
        "linked_issues": [],
        "experts": [],
        "findings": [],
        "signatures": [],
        "process": [],
        "backports": [],
        "disposition": "READY_FOR_MAINTAINER_REVIEW",
        "checks": checks or {},
        "classify": lambda filename: (
            "runtime",
            "interpreter",
            None,
        ),
        "summarize_labels": lambda labels, metadata: [],
        "label_metadata": lambda gh: {},
        "gh": SimpleNamespace(),
    }


class ReportAssemblyTests:
    def test_build_report_does_not_crash_on_ci_failure_data(self):
        """Regression test for a real bug found by running the CLI against
        a live CPython PR (see CHANGELOG.md, Round 3): a stray
        ProcessSignal(signal=..., ...) call here used the wrong keyword
        (the dataclass field is `level`) and crashed the moment any real
        PR had a failing check. Every test that reached this code with a
        `checks` argument used failures=0, so the bug was invisible to
        the suite despite 90% coverage.

        Once fixed, a second issue turned up in the same live run: this
        function used to *also* independently derive a CI-failure
        ProcessSignal from raw check data, duplicating (with a less
        informative message) the BLOCK signal that
        scripts/analyze.py's mergeability_signals() already computes and
        passes in via the `process` argument. build_report() must not
        re-derive process signals from raw evidence it's already been
        given a canonical, richer version of — the `process` argument is
        the single source of truth. This test locks in that build_report()
        does not crash AND does not manufacture a second, redundant
        signal of its own; the CI-failure signal is provided by the
        caller instead (see test_reports_the_ci_failure_signal_the_caller_provided).
        """
        checks = {
            "summary": {
                "name": "CI",
                "status": "failure",
                "available": 5,
                "passed": 3,
                "failed": 2,
                "skipped": 0,
                "failures": 2,
            },
            "check_runs": [
                {"name": "test-a", "conclusion": "failure"},
                {"name": "test-b", "conclusion": "success"},
            ],
        }

        report = build_report(**_build_report_inputs(checks=checks))

        # No signal was manufactured out of thin air by build_report()
        # itself — the caller (process=[]) supplied none, so none appear.
        assert report["process_signals"] == []

    def test_reports_the_ci_failure_signal_the_caller_provided(self):
        """The real CI-failure signal comes from the caller (in
        production, analyze.py's mergeability_signals()) via the
        `process` argument, not from build_report() re-deriving it."""
        checks = {"summary": {"failures": 2}, "check_runs": []}
        process = [
            (
                "BLOCK",
                "2 completed CI check(s) reported failure; the PR is not "
                "ready to merge until the failures are resolved or "
                "explicitly explained.",
            )
        ]

        inputs = _build_report_inputs(checks=checks)
        inputs["process"] = process
        report = build_report(**inputs)

        block_signals = [
            s for s in report["process_signals"] if s.get("level") == "BLOCK"
        ]
        assert len(block_signals) == 1
        assert "reported failure" in block_signals[0]["message"]

    def test_redundant_test_process_warning_is_suppressed_only_from_report(self):
        """The technical finding is the human-facing representation of the
        missing-test condition, but the policy warning remains available to
        deterministic disposition.
        """
        process = [
            (
                "WARN",
                "No test file changed; verify whether regression or "
                "behavior coverage is needed.",
            ),
            ("INFO", "Unrelated process signal."),
        ]

        finding = SimpleNamespace(
            rule_id="production-change-without-tests",
        )

        filtered = _suppress_redundant_process_signals(
            process,
            [finding],
        )

        assert filtered == [
            ("INFO", "Unrelated process signal."),
        ]

        disposition = policy_disposition(
            process,
            [],
            None,
        )

        assert disposition == "NEEDS_MAINTAINER_ATTENTION"

    def test_redundant_news_process_warning_is_suppressed_only_from_report(self):
        """The NEWS technical finding replaces the duplicate human-facing
        policy warning, while the original policy warning still participates
        in disposition.
        """
        process = [
            (
                "WARN",
                "No Misc/NEWS.d entry detected; verify whether the change "
                "requires one under CPython's NEWS policy.",
            ),
            ("INFO", "Unrelated process signal."),
        ]

        finding = SimpleNamespace(
            rule_id="user-visible-change-without-news",
        )

        filtered = _suppress_redundant_process_signals(
            process,
            [finding],
        )

        assert filtered == [
            ("INFO", "Unrelated process signal."),
        ]

        disposition = policy_disposition(
            process,
            [],
            None,
        )

        assert disposition == "NEEDS_MAINTAINER_ATTENTION"

    def test_redundant_process_warning_is_not_suppressed_without_matching_finding(self):
        """A policy warning must remain visible when no canonical technical
        finding covers the same condition.
        """
        process = [
            (
                "WARN",
                "No test file changed; verify whether regression or "
                "behavior coverage is needed.",
            ),
        ]

        filtered = _suppress_redundant_process_signals(
            process,
            [],
        )

        assert filtered == process

    def test_unrelated_process_signals_are_preserved(self):
        """Filtering duplicate change-impact warnings must not remove
        unrelated process or evidence signals.
        """
        process = [
            (
                "WARN",
                "No test file changed; verify whether regression or "
                "behavior coverage is needed.",
            ),
            (
                "BLOCK",
                "Explicit repository process blocker.",
            ),
            (
                "WARN",
                "Review evidence is incomplete.",
            ),
        ]

        finding = SimpleNamespace(
            rule_id="production-change-without-tests",
        )

        filtered = _suppress_redundant_process_signals(
            process,
            [finding],
        )

        assert filtered == [
            (
                "BLOCK",
                "Explicit repository process blocker.",
            ),
            (
                "WARN",
                "Review evidence is incomplete.",
            ),
        ]

    def test_docs_warning_is_not_suppressed_by_unrelated_change_impact_finding(self):
        """The documentation warning is intentionally not treated as a
        duplicate because there is no equivalent suppression rule.
        """
        process = [
            (
                "WARN",
                "No documentation file changed; verify whether public API "
                "documentation needs updating.",
            ),
        ]

        finding = SimpleNamespace(
            rule_id="public-api-change-without-docs",
        )

        filtered = _suppress_redundant_process_signals(
            process,
            [finding],
        )

        assert filtered == process

    def test_build_report_exposes_canonical_check_summaries(self):
        checks = {
            "summary": {
                "name": "CI",
                "status": "success",
                "available": 5,
                "passed": 5,
                "failed": 0,
                "skipped": 0,
            },
            "check_runs": [{"name": "CI", "conclusion": "success"}],
        }

        report = build_report(**_build_report_inputs(checks=checks))

        assert report["checks"] == checks
        assert report["check_summaries"] == {
            "available": True,
            "check_runs": 5,
            "completed": 0,
            "successes": 5,
            "failures": 0,
            "pending": 0,
            "legacy_status": None,
            "error": None,
            "pr_head_sha": None,
            "ci_fresh": None,
        }

    def test_raw_checks_do_not_replace_canonical_check_summaries(self):
        checks = {
            "summary": {
                "name": "CI",
                "status": "failure",
                "available": 3,
                "passed": 2,
                "failed": 1,
                "skipped": 0,
            },
            "check_runs": [
                {"name": "CI", "conclusion": "failure"},
                {"name": "extra", "conclusion": "cancelled"},
            ],
            "unexpected": object(),
        }

        report = build_report(**_build_report_inputs(checks=checks))

        assert report["check_summaries"]["available"] is True
        assert report["check_summaries"]["check_runs"] == 3
        assert report["check_summaries"]["successes"] == 2
        assert report["check_summaries"]["failures"] == 1
        assert report["checks"]["check_runs"] == checks["check_runs"]
        assert report["checks"]["unexpected"]["type"] == "object"
        assert isinstance(report["checks"]["unexpected"]["repr"], str)

    def test_malformed_raw_check_summary_does_not_corrupt_canonical_summary(self):
        checks = {
            "summary": "not-a-mapping",
            "check_runs": [{"name": "CI", "conclusion": "failure"}],
        }

        report = build_report(**_build_report_inputs(checks=checks))

        assert report["checks"] == checks
        assert report["check_summaries"] == {
            "available": False,
            "check_runs": 0,
            "completed": 0,
            "successes": 0,
            "failures": 0,
            "pending": 0,
            "legacy_status": None,
            "error": None,
            "pr_head_sha": None,
            "ci_fresh": None,
        }

    def test_report_metadata_cannot_overwrite_canonical_fields(self):
        evidence = {
            "report_metadata": {
                "repository": "attacker/replacement",
                "checks": ["replacement"],
                "check_summaries": ["replacement"],
                "custom": "preserved",
            }
        }

        report = build_report(
            **_build_report_inputs(evidence=evidence)
        )

        assert report["repository"] == "python/cpython"
        assert report["checks"] == {}
        assert report["check_summaries"] == {
            "available": False,
            "check_runs": 0,
            "completed": 0,
            "successes": 0,
            "failures": 0,
            "pending": 0,
            "legacy_status": None,
            "error": None,
            "pr_head_sha": None,
            "ci_fresh": None,
        }
        assert report["metadata"]["custom"] == "preserved"

    def test_historical_context_survives_report_assembly(self):
        evidence = {
            "files": [
                _file(
                    "Objects/object.c",
                    [_history_entry(sha="history123")],
                )
            ],
            "historical_prs": [
                {
                    "number": 1,
                    "additions": 10,
                    "deletions": 5,
                    "changed_files": 2,
                    "base": {"ref": "main"},
                }
            ],
        }

        report = build_report(
            **_build_report_inputs(evidence=evidence)
        )

        assert report["historical_context"]["available"] is True
        assert report["historical_context"]["history_files"] == 1
        assert report["historical_context"]["history_commits"] == 1
        assert report["historical_context"]["files"][0]["filename"] == (
            "Objects/object.c"
        )
        assert report["historical_context"]["size_baseline"]["sample_size"] == 1



def _expert_match(owner="alice"):
    return {"owner": owner, "file": "Objects/listobject.c", "pattern": "Objects/*", "line": 1}


def test_build_expert_contexts_surfaces_activity_unavailable():
    class FailingCache:
        def get(self, username):
            from scripts.triager.reviewer_activity import ReviewerActivity
            return ReviewerActivity(
                username=username,
                available=False,
                error="both endpoints failed: rate limited",
            )

    contexts = _build_expert_contexts([_expert_match()], FailingCache())
    assert len(contexts) == 1
    ctx = contexts[0].as_dict()
    assert ctx["activity_unavailable"] is True
    assert "rate limited" in ctx["activity_error"]
    # A failure must not be presented as a real, confirmed zero.
    assert ctx["approval_rate"] is None
    assert ctx["approval_rate_sample_size"] == 0


def test_build_expert_contexts_normal_case_has_no_unavailable_flag():
    class WorkingCache:
        def get(self, username):
            from scripts.triager.reviewer_activity import ReviewerActivity
            return ReviewerActivity(username=username, available=True)

    contexts = _build_expert_contexts([_expert_match()], WorkingCache())
    ctx = contexts[0].as_dict()
    assert ctx["activity_unavailable"] is False
    assert ctx["activity_error"] is None
