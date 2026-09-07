from __future__ import annotations

import pytest

from scripts.triager.models import (
    CheckSummary,
    EvidenceCompleteness,
    EvidenceRef,
    FileEvidence,
    Finding,
    OwnershipMatch,
    ProcessSignal,
    TriageReport,
)


def test_evidence_ref_accepts_valid_data():
    ref = EvidenceRef(
        kind="file",
        description="Changed Python source file",
        source="GitHub",
        file="Lib/socket.py",
        line=42,
        url="https://example.com/pr/1",
        observed="socket.py",
    )

    assert ref.kind == "file"
    assert ref.description == "Changed Python source file"
    assert ref.line == 42
    assert ref.as_dict()["file"] == "Lib/socket.py"


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", ""),
        ("kind", "   "),
        ("description", ""),
        ("description", "   "),
    ],
)
def test_evidence_ref_rejects_empty_required_strings(field, value):
    kwargs = {
        "kind": "file",
        "description": "valid description",
    }
    kwargs[field] = value

    with pytest.raises(
        ValueError,
        match=f"EvidenceRef\\.{field}",
    ):
        EvidenceRef(**kwargs)


@pytest.mark.parametrize(
    "line",
    [
        0,
        -1,
        "0",
        "-5",
        "not-a-number",
        object(),
    ],
)
def test_evidence_ref_rejects_invalid_line(line):
    with pytest.raises(
        ValueError,
        match="EvidenceRef.line",
    ):
        EvidenceRef(
            kind="file",
            description="valid",
            line=line,
        )


def test_evidence_ref_normalizes_numeric_line():
    ref = EvidenceRef(
        kind="file",
        description="valid",
        line="12",
    )

    assert ref.line == 12


@pytest.mark.parametrize(
    "field",
    [
        "source",
        "file",
        "url",
        "observed",
    ],
)
def test_evidence_ref_rejects_non_string_optional_fields(field):
    kwargs = {
        "kind": "file",
        "description": "valid",
        field: 123,
    }

    with pytest.raises(
        TypeError,
        match=f"EvidenceRef\\.{field}",
    ):
        EvidenceRef(**kwargs)


def test_evidence_ref_is_immutable():
    ref = EvidenceRef(
        kind="file",
        description="valid",
    )

    with pytest.raises(AttributeError):
        ref.kind = "diff"


def test_finding_accepts_valid_data():
    finding = Finding(
        severity="HIGH",
        category="testing",
        message="A test should be reviewed.",
        confidence="high",
    )

    assert finding.status == "review"
    assert finding.source == "deterministic"
    assert finding.evidence_refs == []


@pytest.mark.parametrize(
    "severity",
    [
        "",
        "INVALID",
        "critical",
        None,
    ],
)
def test_finding_rejects_invalid_severity(severity):
    with pytest.raises(
        ValueError,
        match="Finding.severity",
    ):
        Finding(
            severity=severity,
            category="testing",
            message="message",
            confidence="high",
        )


@pytest.mark.parametrize(
    "confidence",
    [
        "",
        "HIGH",
        "INVALID",
        None,
    ],
)
def test_finding_rejects_invalid_confidence(confidence):
    with pytest.raises(
        ValueError,
        match="Finding.confidence",
    ):
        Finding(
            severity="HIGH",
            category="testing",
            message="message",
            confidence=confidence,
        )


@pytest.mark.parametrize(
    "status",
    [
        "",
        "INVALID",
        "pending",
        None,
    ],
)
def test_finding_rejects_invalid_status(status):
    with pytest.raises(
        ValueError,
        match="Finding.status",
    ):
        Finding(
            severity="HIGH",
            category="testing",
            message="message",
            confidence="high",
            status=status,
        )


@pytest.mark.parametrize(
    "field",
    [
        "category",
        "message",
    ],
)
def test_finding_rejects_empty_required_strings(field):
    kwargs = {
        "severity": "HIGH",
        "category": "testing",
        "message": "message",
        "confidence": "high",
    }
    kwargs[field] = "   "

    with pytest.raises(
        ValueError,
        match=f"Finding\\.{field}",
    ):
        Finding(**kwargs)


def test_finding_normalizes_dictionary_evidence_refs():
    finding = Finding(
        severity="MEDIUM",
        category="testing",
        message="Review tests.",
        confidence="medium",
        evidence_refs=[
            {
                "kind": "file",
                "description": "Changed test file",
                "file": "Lib/test/test_socket.py",
                "line": 10,
            }
        ],
    )

    assert len(finding.evidence_refs) == 1
    assert isinstance(
        finding.evidence_refs[0],
        EvidenceRef,
    )
    assert finding.evidence_refs[0].line == 10


def test_finding_accepts_evidence_ref_objects():
    ref = EvidenceRef(
        kind="file",
        description="Changed source",
    )

    finding = Finding(
        severity="LOW",
        category="source",
        message="Review source.",
        confidence="low",
        evidence_refs=[ref],
    )

    assert finding.evidence_refs == [ref]


@pytest.mark.parametrize(
    "refs",
    [
        "not-a-list",
        {"kind": "file"},
        [object()],
    ],
)
def test_finding_rejects_malformed_evidence_refs(refs):
    with pytest.raises(
        (TypeError, ValueError),
    ):
        Finding(
            severity="LOW",
            category="source",
            message="Review source.",
            confidence="low",
            evidence_refs=refs,
        )


def test_process_signal_accepts_valid_data():
    signal = ProcessSignal(
        level="WARN",
        message="Maintainer attention may be required.",
    )

    assert signal.source == "policy"
    assert signal.evidence_refs == []


@pytest.mark.parametrize(
    "level",
    [
        "",
        "INVALID",
        "BLOCKED",
        None,
    ],
)
def test_process_signal_rejects_invalid_level(level):
    with pytest.raises(
        ValueError,
        match="ProcessSignal.level",
    ):
        ProcessSignal(
            level=level,
            message="message",
        )


def test_process_signal_rejects_empty_message():
    with pytest.raises(
        ValueError,
        match="ProcessSignal.message",
    ):
        ProcessSignal(
            level="INFO",
            message="   ",
        )


def test_process_signal_normalizes_dictionary_evidence_refs():
    signal = ProcessSignal(
        level="INFO",
        message="Context available.",
        evidence_refs=[
            {
                "kind": "timeline",
                "description": "Timeline event",
            }
        ],
    )

    assert isinstance(
        signal.evidence_refs[0],
        EvidenceRef,
    )


@pytest.mark.parametrize(
    "refs",
    [
        "not-a-list",
        [object()],
    ],
)
def test_process_signal_rejects_malformed_evidence_refs(refs):
    with pytest.raises(
        (TypeError, ValueError),
    ):
        ProcessSignal(
            level="INFO",
            message="message",
            evidence_refs=refs,
        )


def test_evidence_completeness_normalizes_sources():
    completeness = EvidenceCompleteness(
        attempted=["pr", "files", "pr", " "],
        available=["files", "files"],
        missing=["timeline", "timeline"],
        errors={
            "reviews": "request failed",
        },
    )

    assert completeness.attempted == [
        "files",
        "pr",
        "reviews",
        "timeline",
    ]
    assert completeness.available == ["files"]
    assert completeness.missing == ["timeline"]
    assert completeness.errors == {
        "reviews": "request failed"
    }


def test_evidence_completeness_errors_mark_source_as_attempted():
    completeness = EvidenceCompleteness(
        errors={
            "reviews": "request failed",
        },
    )

    assert completeness.attempted == ["reviews"]
    assert completeness.available == []
    assert completeness.missing == []
    assert completeness.status == "unavailable"


def test_evidence_completeness_available_and_missing_conflict():
    completeness = EvidenceCompleteness(
        attempted=["files"],
        available=["files"],
        missing=["files"],
    )

    assert completeness.available == ["files"]
    assert completeness.missing == []
    assert completeness.complete is True


def test_evidence_completeness_score_is_one_when_empty():
    completeness = EvidenceCompleteness()

    assert completeness.score == 1.0
    assert completeness.complete is True
    assert completeness.status == "complete"


def test_evidence_completeness_score_is_complete():
    completeness = EvidenceCompleteness(
        attempted=["pr", "files"],
        available=["pr", "files"],
    )

    assert completeness.score == 1.0
    assert completeness.complete is True
    assert completeness.status == "complete"


def test_evidence_completeness_score_is_partial():
    completeness = EvidenceCompleteness(
        attempted=["pr", "files", "reviews"],
        available=["pr", "files"],
    )

    assert completeness.score == pytest.approx(2 / 3)
    assert completeness.complete is False
    assert completeness.status == "partial"


def test_evidence_completeness_score_is_unavailable():
    completeness = EvidenceCompleteness(
        attempted=["pr", "files"],
    )

    assert completeness.score == 0.0
    assert completeness.complete is False
    assert completeness.status == "unavailable"


def test_evidence_completeness_as_dict_contains_derived_fields():
    completeness = EvidenceCompleteness(
        attempted=["pr", "files"],
        available=["pr"],
    )

    data = completeness.as_dict()

    assert data["score"] == 0.5
    assert data["complete"] is False
    assert data["status"] == "partial"


@pytest.mark.parametrize(
    "field",
    [
        "attempted",
        "available",
        "missing",
    ],
)
def test_evidence_completeness_rejects_non_list_source_fields(field):
    kwargs = {field: "not-a-list"}

    with pytest.raises(
        TypeError,
        match="Evidence source names must be lists",
    ):
        EvidenceCompleteness(**kwargs)


def test_evidence_completeness_rejects_non_dict_errors():
    with pytest.raises(
        TypeError,
        match="errors must be a dictionary",
    ):
        EvidenceCompleteness(
            errors=[],
        )


def test_file_evidence_accepts_valid_data():
    file_data = FileEvidence(
        filename="Lib/socket.py",
        status="modified",
        additions=10,
        deletions=3,
        patch_available=True,
        subsystem="networking",
        component="socket",
        expected_test_hint="Add socket tests.",
    )

    assert file_data.filename == "Lib/socket.py"
    assert file_data.additions == 10
    assert file_data.deletions == 3
    assert file_data.patch_available is True


def test_file_evidence_rejects_empty_filename():
    with pytest.raises(
        ValueError,
        match="FileEvidence.filename",
    ):
        FileEvidence(filename="   ")


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "invalid",
        -5,
        object(),
    ],
)
def test_file_evidence_normalizes_invalid_counts_to_zero(value):
    file_data = FileEvidence(
        filename="Lib/socket.py",
        additions=value,
        deletions=value,
    )

    assert file_data.additions == 0
    assert file_data.deletions == 0


def test_file_evidence_normalizes_numeric_counts():
    file_data = FileEvidence(
        filename="Lib/socket.py",
        additions="12",
        deletions="4",
    )

    assert file_data.additions == 12
    assert file_data.deletions == 4


@pytest.mark.parametrize(
    "field",
    [
        "status",
        "subsystem",
        "component",
        "expected_test_hint",
    ],
)
def test_file_evidence_rejects_non_string_optional_fields(field):
    kwargs = {
        "filename": "Lib/socket.py",
        field: 123,
    }

    with pytest.raises(
        TypeError,
        match=f"FileEvidence\\.{field}",
    ):
        FileEvidence(**kwargs)


def test_check_summary_normalizes_counts():
    checks = CheckSummary(
        available=True,
        check_runs="5",
        completed="4",
        successes="3",
        failures="1",
        pending="0",
    )

    assert checks.available is True
    assert checks.check_runs == 5
    assert checks.completed == 4
    assert checks.successes == 3
    assert checks.failures == 1
    assert checks.pending == 0


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "invalid",
        -1,
        object(),
    ],
)
def test_check_summary_normalizes_invalid_counts_to_zero(value):
    checks = CheckSummary(
        available=True,
        check_runs=value,
        completed=value,
        successes=value,
        failures=value,
        pending=value,
    )

    assert checks.check_runs == 0
    assert checks.completed == 0
    assert checks.successes == 0
    assert checks.failures == 0
    assert checks.pending == 0


def test_check_summary_coerces_available_to_bool():
    assert CheckSummary(available=1).available is True
    assert CheckSummary(available=0).available is False


@pytest.mark.parametrize(
    "field",
    [
        "legacy_status",
        "error",
    ],
)
def test_check_summary_rejects_non_string_optional_fields(field):
    with pytest.raises(
        TypeError,
        match=f"CheckSummary\\.{field}",
    ):
        CheckSummary(
            available=True,
            **{field: 123},
        )


def test_ownership_match_accepts_valid_data():
    match = OwnershipMatch(
        owner="@python/core",
        file="Lib/socket.py",
        pattern="Lib/*.py",
        line=42,
    )

    assert match.owner == "@python/core"
    assert match.line == 42
    assert match.source == "CODEOWNERS"


@pytest.mark.parametrize(
    "field",
    [
        "owner",
        "file",
        "pattern",
    ],
)
def test_ownership_match_rejects_empty_required_strings(field):
    kwargs = {
        "owner": "@python",
        "file": "Lib/socket.py",
        "pattern": "*.py",
        "line": 1,
    }
    kwargs[field] = "   "

    with pytest.raises(
        ValueError,
        match=f"OwnershipMatch\\.{field}",
    ):
        OwnershipMatch(**kwargs)


def test_ownership_match_normalizes_line():
    match = OwnershipMatch(
        owner="@python",
        file="Lib/socket.py",
        pattern="*.py",
        line="7",
    )

    assert match.line == 7


@pytest.mark.parametrize(
    "line",
    [
        0,
        -1,
        "0",
        "-4",
        "invalid",
        object(),
    ],
)
def test_ownership_match_rejects_invalid_line(line):
    with pytest.raises(
        ValueError,
        match="OwnershipMatch.line",
    ):
        OwnershipMatch(
            owner="@python",
            file="Lib/socket.py",
            pattern="*.py",
            line=line,
        )


def test_ownership_match_rejects_non_string_source():
    with pytest.raises(
        TypeError,
        match="OwnershipMatch.source",
    ):
        OwnershipMatch(
            owner="@python",
            file="Lib/socket.py",
            pattern="*.py",
            line=1,
            source=123,
        )


def test_triage_report_accepts_nested_dataclasses():
    report = TriageReport(
        schema_version="1.1",
        repository="python/cpython",
        generated_at="2026-09-06T00:00:00Z",
        disposition="READY_FOR_MAINTAINER_REVIEW",
        pr={"number": 123},
        process_signals=[
            ProcessSignal(
                level="INFO",
                message="Checks available.",
            )
        ],
        technical_findings=[
            Finding(
                severity="LOW",
                category="testing",
                message="Review tests.",
                confidence="medium",
            )
        ],
        files=[
            FileEvidence(
                filename="Lib/socket.py",
            )
        ],
        experts=[
            OwnershipMatch(
                owner="@python",
                file="Lib/socket.py",
                pattern="Lib/*.py",
                line=1,
            )
        ],
        checks=CheckSummary(
            available=True,
        ),
    )

    data = report.as_dict()

    assert data["schema_version"] == "1.1"
    assert data["pr"]["number"] == 123
    assert data["process_signals"][0]["level"] == "INFO"
    assert data["technical_findings"][0]["severity"] == "LOW"
    assert data["files"][0]["filename"] == "Lib/socket.py"
    assert data["experts"][0]["owner"] == "@python"
    assert data["checks"]["available"] is True


def test_triage_report_normalizes_nested_dictionaries():
    report = TriageReport(
        schema_version="1.1",
        repository="python/cpython",
        generated_at="2026-09-06T00:00:00Z",
        disposition="READY_FOR_MAINTAINER_REVIEW",
        pr={"number": 123},
        evidence_completeness={
            "attempted": ["pr"],
            "available": ["pr"],
        },
        process_signals=[
            {
                "level": "INFO",
                "message": "Informational signal.",
            }
        ],
        technical_findings=[
            {
                "severity": "LOW",
                "category": "testing",
                "message": "Review tests.",
                "confidence": "low",
            }
        ],
        files=[
            {
                "filename": "Lib/socket.py",
                "additions": "2",
            }
        ],
        experts=[
            {
                "owner": "@python",
                "file": "Lib/socket.py",
                "pattern": "*.py",
                "line": "3",
            }
        ],
        checks={
            "available": True,
            "check_runs": "4",
        },
    )

    assert isinstance(
        report.evidence_completeness,
        EvidenceCompleteness,
    )
    assert isinstance(
        report.process_signals[0],
        ProcessSignal,
    )
    assert isinstance(
        report.technical_findings[0],
        Finding,
    )
    assert isinstance(
        report.files[0],
        FileEvidence,
    )
    assert isinstance(
        report.experts[0],
        OwnershipMatch,
    )
    assert isinstance(
        report.checks,
        CheckSummary,
    )

    assert report.files[0].additions == 2
    assert report.experts[0].line == 3
    assert report.checks.check_runs == 4


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "repository",
        "generated_at",
        "disposition",
    ],
)
def test_triage_report_rejects_empty_required_strings(field):
    kwargs = {
        "schema_version": "1.1",
        "repository": "python/cpython",
        "generated_at": "2026-09-06T00:00:00Z",
        "disposition": "READY_FOR_MAINTAINER_REVIEW",
        "pr": {},
    }
    kwargs[field] = "   "

    with pytest.raises(
        ValueError,
        match=f"TriageReport\\.{field}",
    ):
        TriageReport(**kwargs)


def test_triage_report_rejects_non_dict_pr():
    with pytest.raises(
        TypeError,
        match="TriageReport.pr",
    ):
        TriageReport(
            schema_version="1.1",
            repository="python/cpython",
            generated_at="2026-09-06T00:00:00Z",
            disposition="READY_FOR_MAINTAINER_REVIEW",
            pr=[],
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("process_signals", {}),
        ("technical_findings", {}),
        ("files", {}),
        ("experts", {}),
        ("linked_issues", {}),
        ("references", []),
        ("backport_targets", {}),
        ("signature_changes", {}),
        ("metadata", []),
    ],
)
def test_triage_report_rejects_wrong_container_types(field, value):
    kwargs = {
        "schema_version": "1.1",
        "repository": "python/cpython",
        "generated_at": "2026-09-06T00:00:00Z",
        "disposition": "READY_FOR_MAINTAINER_REVIEW",
        "pr": {},
        field: value,
    }

    with pytest.raises(
        TypeError,
        match=f"TriageReport\\.{field}",
    ):
        TriageReport(**kwargs)


def test_triage_report_rejects_invalid_historical_context():
    with pytest.raises(
        TypeError,
        match="historical_context",
    ):
        TriageReport(
            schema_version="1.1",
            repository="python/cpython",
            generated_at="2026-09-06T00:00:00Z",
            disposition="READY_FOR_MAINTAINER_REVIEW",
            pr={},
            historical_context=[],
        )


def test_triage_report_rejects_invalid_ai_synthesis():
    with pytest.raises(
        TypeError,
        match="ai_synthesis",
    ):
        TriageReport(
            schema_version="1.1",
            repository="python/cpython",
            generated_at="2026-09-06T00:00:00Z",
            disposition="READY_FOR_MAINTAINER_REVIEW",
            pr={},
            ai_synthesis=[],
        )


def test_triage_report_rejects_invalid_ai_error():
    with pytest.raises(
        TypeError,
        match="ai_error",
    ):
        TriageReport(
            schema_version="1.1",
            repository="python/cpython",
            generated_at="2026-09-06T00:00:00Z",
            disposition="READY_FOR_MAINTAINER_REVIEW",
            pr={},
            ai_error=123,
        )


def test_triage_report_rejects_invalid_checks_type():
    with pytest.raises(
        TypeError,
        match="TriageReport.checks",
    ):
        TriageReport(
            schema_version="1.1",
            repository="python/cpython",
            generated_at="2026-09-06T00:00:00Z",
            disposition="READY_FOR_MAINTAINER_REVIEW",
            pr={},
            checks=[],
        )


def test_triage_report_rejects_invalid_evidence_completeness_type():
    report = TriageReport(
        schema_version="1.1",
        repository="python/cpython",
        generated_at="2026-09-06T00:00:00Z",
        disposition="READY_FOR_MAINTAINER_REVIEW",
        pr={},
        evidence_completeness="invalid",
    )

    assert isinstance(
        report.evidence_completeness,
        EvidenceCompleteness,
    )


def test_triage_report_rejects_malformed_evidence_completeness_dict():
    with pytest.raises(
        TypeError,
    ):
        TriageReport(
            schema_version="1.1",
            repository="python/cpython",
            generated_at="2026-09-06T00:00:00Z",
            disposition="READY_FOR_MAINTAINER_REVIEW",
            pr={},
            evidence_completeness={
                "attempted": "invalid",
            },
        )


def test_default_lists_are_independent():
    first = TriageReport(
        schema_version="1.1",
        repository="python/cpython",
        generated_at="2026-09-06T00:00:00Z",
        disposition="READY_FOR_MAINTAINER_REVIEW",
        pr={},
    )

    second = TriageReport(
        schema_version="1.1",
        repository="python/cpython",
        generated_at="2026-09-06T00:00:00Z",
        disposition="READY_FOR_MAINTAINER_REVIEW",
        pr={},
    )

    first.files.append(
        FileEvidence(filename="Lib/socket.py")
    )

    first.metadata["changed"] = True

    assert second.files == []
    assert second.metadata == {}


def test_as_dict_recursively_serializes_nested_models():
    ref = EvidenceRef(
        kind="file",
        description="Changed file",
        file="Lib/socket.py",
        line=10,
    )

    finding = Finding(
        severity="HIGH",
        category="source",
        message="Review changed source.",
        confidence="high",
        evidence_refs=[ref],
    )

    report = TriageReport(
        schema_version="1.1",
        repository="python/cpython",
        generated_at="2026-09-06T00:00:00Z",
        disposition="NEEDS_MAINTAINER_ATTENTION",
        pr={"number": 123},
        technical_findings=[finding],
    )

    data = report.as_dict()

    assert data["technical_findings"][0]["evidence_refs"][0] == {
        "kind": "file",
        "description": "Changed file",
        "source": None,
        "file": "Lib/socket.py",
        "line": 10,
        "url": None,
        "observed": None,
    }