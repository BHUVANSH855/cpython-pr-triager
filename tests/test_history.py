from __future__ import annotations

from scripts.triager.history import (
    _percentile,
    contextual_size_signal,
    stratify,
    summarize_sizes,
)


def _pr(
    number: int = 1,
    additions: int = 10,
    deletions: int = 5,
    changed_files: int = 2,
    base: str = "main",
    labels: list[str] | None = None,
) -> dict:
    return {
        "number": number,
        "additions": additions,
        "deletions": deletions,
        "changed_files": changed_files,
        "base": {"ref": base},
        "labels": [
            {"name": label}
            for label in (labels or [])
        ],
    }


class SummarizeSizesTests:
    def test_builds_size_baseline(self):
        prs = [
            _pr(
                number=1,
                additions=10,
                deletions=5,
                changed_files=2,
                base="main",
            ),
            _pr(
                number=2,
                additions=20,
                deletions=10,
                changed_files=4,
                base="3.15",
            ),
            _pr(
                number=3,
                additions=5,
                deletions=5,
                changed_files=1,
                base="main",
            ),
        ]

        result = summarize_sizes(prs)

        assert result["sample_size"] == 3
        assert result["size"]["median"] == 15
        assert result["size"]["max"] == 30
        assert result["changed_files"]["median"] == 2
        assert result["changed_files"]["max"] == 4
        assert result["branches"] == {
            "main": 2,
            "3.15": 1,
        }

    def test_preserves_relevant_row_fields(self):
        result = summarize_sizes(
            [
                _pr(
                    number=42,
                    additions=12,
                    deletions=3,
                    changed_files=4,
                    base="3.14",
                )
            ]
        )

        assert result["rows"] == [
            {
                "number": 42,
                "additions": 12,
                "deletions": 3,
                "changed_files": 4,
                "base": "3.14",
            }
        ]

    def test_empty_sample_returns_zero_statistics(self):
        result = summarize_sizes([])

        assert result["sample_size"] == 0
        assert result["rows"] == []
        assert result["size"] == {
            "median": 0,
            "p95": 0,
            "max": 0,
        }
        assert result["changed_files"] == {
            "median": 0,
            "p95": 0,
            "max": 0,
        }
        assert result["branches"] == {}

    def test_skips_non_mapping_records(self):
        result = summarize_sizes(
            [
                _pr(number=1),
                None,
                "invalid",
                123,
                _pr(number=2, additions=20),
            ]
        )

        assert result["sample_size"] == 2
        assert [
            row["number"]
            for row in result["rows"]
        ] == [1, 2]

    def test_invalid_numeric_values_use_zero(self):
        result = summarize_sizes(
            [
                {
                    "number": 1,
                    "additions": "invalid",
                    "deletions": None,
                    "changed_files": "invalid",
                    "base": {"ref": "main"},
                }
            ]
        )

        assert result["sample_size"] == 1
        assert result["rows"] == [
            {
                "number": 1,
                "additions": 0,
                "deletions": 0,
                "changed_files": 0,
                "base": "main",
            }
        ]

    def test_negative_numeric_values_are_clamped(self):
        result = summarize_sizes(
            [
                {
                    "number": 1,
                    "additions": -10,
                    "deletions": -5,
                    "changed_files": -2,
                    "base": {"ref": "main"},
                }
            ]
        )

        assert result["rows"] == [
            {
                "number": 1,
                "additions": 0,
                "deletions": 0,
                "changed_files": 0,
                "base": "main",
            }
        ]

    def test_malformed_base_does_not_crash(self):
        result = summarize_sizes(
            [
                {
                    "number": 1,
                    "additions": 10,
                    "deletions": 2,
                    "changed_files": 1,
                    "base": "invalid",
                },
                {
                    "number": 2,
                    "additions": 5,
                    "deletions": 1,
                    "changed_files": 1,
                },
            ]
        )

        assert result["sample_size"] == 2
        assert result["rows"][0]["base"] is None
        assert result["rows"][1]["base"] is None
        assert result["branches"] == {}


class PercentileTests:
    def test_empty_values_return_zero(self):
        assert _percentile([], 0.95) == 0

    def test_single_value_returns_that_value(self):
        assert _percentile([42], 0.95) == 42.0

    def test_calculates_interpolated_p95(self):
        result = _percentile(
            [10, 20, 30, 40, 50],
            0.95,
        )

        assert result == 48.0

    def test_clamps_percentile_below_zero(self):
        assert _percentile(
            [10, 20, 30],
            -1,
        ) == 10.2

    def test_clamps_percentile_above_one(self):
        assert _percentile(
            [10, 20, 30],
            2,
        ) == 29.8


class ContextualSizeSignalTests:
    def test_without_baseline_returns_unknown(self):
        result = contextual_size_signal(
            additions=100,
            deletions=20,
            changed_files=5,
            baseline=None,
        )

        assert result == {
            "status": "unknown",
            "reason": "No historical baseline supplied.",
        }

    def test_empty_baseline_returns_typical(self):
        result = contextual_size_signal(
            additions=10,
            deletions=5,
            changed_files=2,
            baseline={},
        )

        assert result["status"] == "typical"
        assert result["flags"] == []
        assert result["sample_size"] == 0

    def test_typical_pr_has_no_flags(self):
        baseline = summarize_sizes(
            [
                _pr(
                    number=1,
                    additions=10,
                    deletions=5,
                    changed_files=2,
                ),
                _pr(
                    number=2,
                    additions=20,
                    deletions=10,
                    changed_files=4,
                ),
                _pr(
                    number=3,
                    additions=5,
                    deletions=5,
                    changed_files=1,
                ),
                _pr(
                    number=4,
                    additions=15,
                    deletions=5,
                    changed_files=3,
                ),
            ]
        )

        result = contextual_size_signal(
            additions=10,
            deletions=5,
            changed_files=2,
            baseline=baseline,
        )

        assert result["status"] == "typical"
        assert result["flags"] == []
        assert result["sample_size"] == 4

    def test_large_pr_can_trigger_size_flag(self):
        baseline = summarize_sizes(
            [
                _pr(
                    number=1,
                    additions=10,
                    deletions=5,
                    changed_files=2,
                ),
                _pr(
                    number=2,
                    additions=20,
                    deletions=10,
                    changed_files=3,
                ),
                _pr(
                    number=3,
                    additions=15,
                    deletions=5,
                    changed_files=2,
                ),
                _pr(
                    number=4,
                    additions=5,
                    deletions=5,
                    changed_files=1,
                ),
            ]
        )

        result = contextual_size_signal(
            additions=100,
            deletions=50,
            changed_files=2,
            baseline=baseline,
        )

        assert result["status"] == "unusual"
        assert "total_change_size_above_p95" in result["flags"]

    def test_large_file_count_can_trigger_file_flag(self):
        baseline = summarize_sizes(
            [
                _pr(
                    number=1,
                    additions=10,
                    deletions=5,
                    changed_files=1,
                ),
                _pr(
                    number=2,
                    additions=20,
                    deletions=10,
                    changed_files=2,
                ),
                _pr(
                    number=3,
                    additions=15,
                    deletions=5,
                    changed_files=2,
                ),
                _pr(
                    number=4,
                    additions=5,
                    deletions=5,
                    changed_files=1,
                ),
            ]
        )

        result = contextual_size_signal(
            additions=1,
            deletions=1,
            changed_files=10,
            baseline=baseline,
        )

        assert result["status"] == "unusual"
        assert "changed_files_above_p95" in result["flags"]

    def test_can_trigger_both_flags(self):
        baseline = summarize_sizes(
            [
                _pr(
                    number=1,
                    additions=10,
                    deletions=5,
                    changed_files=1,
                ),
                _pr(
                    number=2,
                    additions=20,
                    deletions=10,
                    changed_files=2,
                ),
                _pr(
                    number=3,
                    additions=15,
                    deletions=5,
                    changed_files=2,
                ),
                _pr(
                    number=4,
                    additions=5,
                    deletions=5,
                    changed_files=1,
                ),
            ]
        )

        result = contextual_size_signal(
            additions=100,
            deletions=50,
            changed_files=10,
            baseline=baseline,
        )

        assert result["status"] == "unusual"
        assert result["flags"] == [
            "total_change_size_above_p95",
            "changed_files_above_p95",
        ]

    def test_malformed_baseline_fields_are_safe(self):
        result = contextual_size_signal(
            additions="invalid",
            deletions=None,
            changed_files="invalid",
            baseline={
                "sample_size": "invalid",
                "size": {
                    "p95": "invalid",
                },
                "changed_files": {
                    "p95": None,
                },
            },
        )

        assert result["status"] == "typical"
        assert result["flags"] == []
        assert result["sample_size"] == 0


class StratifyTests:
    def test_groups_by_branch_and_labels(self):
        prs = [
            _pr(
                number=1,
                base="main",
                labels=["enhancement"],
            ),
            _pr(
                number=2,
                base="main",
                labels=["enhancement"],
            ),
            _pr(
                number=3,
                base="3.14",
                labels=["bug"],
            ),
        ]

        result = stratify(prs)

        assert set(result) == {
            "main|enhancement",
            "3.14|bug",
        }

        assert result["main|enhancement"]["sample_size"] == 2
        assert result["3.14|bug"]["sample_size"] == 1

    def test_normalizes_labels(self):
        result = stratify(
            [
                _pr(
                    number=1,
                    base="main",
                    labels=[
                        " Bug ",
                        "enhancement",
                        "BUG",
                    ],
                )
            ]
        )

        assert list(result) == [
            "main|bug,enhancement"
        ]

    def test_limits_group_key_to_three_labels(self):
        result = stratify(
            [
                _pr(
                    number=1,
                    base="main",
                    labels=[
                        "zeta",
                        "alpha",
                        "gamma",
                        "beta",
                        "delta",
                    ],
                )
            ]
        )

        assert list(result) == [
            "main|alpha,beta,delta"
        ]

    def test_empty_labels_have_stable_group(self):
        result = stratify(
            [
                _pr(
                    number=1,
                    base="main",
                    labels=[],
                ),
                _pr(
                    number=2,
                    base="main",
                    labels=[],
                ),
            ]
        )

        assert list(result) == ["main|"]
        assert result["main|"]["sample_size"] == 2

    def test_missing_base_uses_unknown_group(self):
        result = stratify(
            [
                {
                    "number": 1,
                    "additions": 10,
                    "deletions": 2,
                    "changed_files": 1,
                    "labels": [],
                }
            ]
        )

        assert list(result) == ["unknown|"]
        assert result["unknown|"]["sample_size"] == 1

    def test_malformed_labels_do_not_crash(self):
        result = stratify(
            [
                {
                    "number": 1,
                    "additions": 10,
                    "deletions": 2,
                    "changed_files": 1,
                    "base": {"ref": "main"},
                    "labels": "not-a-list",
                },
                {
                    "number": 2,
                    "additions": 5,
                    "deletions": 1,
                    "changed_files": 1,
                    "base": {"ref": "main"},
                    "labels": None,
                },
            ]
        )

        assert list(result) == ["main|"]
        assert result["main|"]["sample_size"] == 2

    def test_ignores_non_mapping_records(self):
        result = stratify(
            [
                _pr(number=1),
                None,
                "invalid",
                123,
            ]
        )

        assert list(result) == ["main|"]
        assert result["main|"]["sample_size"] == 1

    def test_groups_are_returned_in_deterministic_order(self):
        result = stratify(
            [
                _pr(
                    number=1,
                    base="3.15",
                    labels=["bug"],
                ),
                _pr(
                    number=2,
                    base="main",
                    labels=["enhancement"],
                ),
                _pr(
                    number=3,
                    base="3.14",
                    labels=["bug"],
                ),
            ]
        )

        assert list(result) == [
            "3.14|bug",
            "3.15|bug",
            "main|enhancement",
        ]
