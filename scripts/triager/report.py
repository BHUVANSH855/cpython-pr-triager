"""
Canonical report construction for CPython PR triage.

Updated to include reviewer profile context and dynamic activity data
in the expert routing section of the report.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .history import summarize_sizes
from .models import (
    CheckSummary,
    EvidenceCompleteness,
    ExpertContext,
    FileEvidence,
    Finding,
    OwnershipMatch,
    ProcessSignal,
    TriageReport,
)

SCHEMA_VERSION = "1.2"

REQUIRED_EVIDENCE_SOURCES = (
    "pr",
    "files",
    "timeline",
    "reviews",
    "review_comments",
    "issue_comments",
)


def _collection_available(evidence: Mapping[str, Any], key: str) -> bool:
    return key in evidence and evidence[key] is not None


def _base_content_requirements(evidence: Mapping[str, Any]) -> tuple[bool, int]:
    files = evidence.get("files")
    if not isinstance(files, list):
        return False, 0
    required = 0
    for file_data in files:
        if not isinstance(file_data, Mapping):
            continue
        filename = str(file_data.get("filename") or "")
        if not (filename.endswith(".py") or filename.endswith(".pyi") or filename.endswith(".pyx")):
            continue
        if file_data.get("status") == "added":
            continue
        required += 1
    return required > 0, required


def _build_evidence_completeness(evidence: Mapping[str, Any]) -> EvidenceCompleteness:
    attempted = list(REQUIRED_EVIDENCE_SOURCES)
    available: list[str] = []
    missing: list[str] = []
    raw_errors = evidence.get("evidence_errors", {})
    errors = (
        {str(k): str(v) for k, v in raw_errors.items() if v is not None}
        if isinstance(raw_errors, Mapping)
        else {}
    )
    for source in REQUIRED_EVIDENCE_SOURCES:
        if _collection_available(evidence, source):
            available.append(source)
        else:
            missing.append(source)
    for source in errors:
        if source in available:
            available.remove(source)
        if source not in missing:
            missing.append(source)

    needs_base, required_base = _base_content_requirements(evidence)
    if needs_base:
        attempted.append("base_file_contents")
        base_contents = evidence.get("base_file_contents")
        if not isinstance(base_contents, Mapping):
            missing.append("base_file_contents")
            errors.setdefault("base_file_contents",
                f"Base contents unavailable for {required_base} existing Python file(s).")
        else:
            available_base = {str(p) for p in base_contents if isinstance(p, str)}
            missing_base = []
            for file_data in (evidence.get("files") or []):
                if not isinstance(file_data, Mapping):
                    continue
                fname = str(file_data.get("filename") or "")
                if not (fname.endswith(".py") or fname.endswith(".pyi") or fname.endswith(".pyx")):
                    continue
                if file_data.get("status") == "added":
                    continue
                if fname not in available_base:
                    missing_base.append(fname)
            if missing_base:
                missing.append("base_file_contents")
                errors.setdefault("base_file_contents",
                    "Missing base content for: " + ", ".join(sorted(missing_base)))
            else:
                available.append("base_file_contents")

    return EvidenceCompleteness(attempted=attempted, available=available, missing=missing, errors=errors)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalise_labels(pr: Mapping[str, Any]) -> list[str]:
    labels: list[str] = []
    for item in (pr.get("labels") or []):
        name = item.get("name") if isinstance(item, Mapping) else item
        if name is not None:
            text = str(name).strip()
            if text:
                labels.append(text)
    return labels


def _normalise_files(evidence: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    files = evidence.get("files")
    if not isinstance(files, list):
        return []
    return [item for item in files if isinstance(item, Mapping)]


def _normalise_timeline(evidence: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    timeline = evidence.get("timeline")
    if not isinstance(timeline, list):
        return []
    return [item for item in timeline if isinstance(item, Mapping)]


def _build_pr_summary(pr, labels, additions, deletions):
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    user = pr.get("user") or {}
    if not isinstance(base, Mapping): base = {}
    if not isinstance(head, Mapping): head = {}
    if not isinstance(user, Mapping): user = {}
    return {
        "number": pr.get("number"),
        "title": pr.get("title"),
        "state": pr.get("state"),
        "merged": bool(pr.get("merged_at")),
        "draft": bool(pr.get("draft")),
        "author": user.get("login"),
        "base": base.get("ref"),
        "base_sha": base.get("sha"),
        "head": head.get("ref"),
        "head_sha": head.get("sha"),
        "labels": labels,
        "additions": additions,
        "deletions": deletions,
        "changed_files": pr.get("changed_files"),
        "commits": pr.get("commits"),
        "created_at": pr.get("created_at"),
        "updated_at": pr.get("updated_at"),
        "closed_at": pr.get("closed_at"),
        "merged_at": pr.get("merged_at"),
        "mergeable": pr.get("mergeable"),
        "mergeable_state": pr.get("mergeable_state"),
    }


def _build_file_reports(files, classify):
    result = []
    for file_data in files:
        filename = str(file_data.get("filename") or "")
        subsystem, component, expected_test_hint = classify(filename)
        result.append({
            "filename": file_data.get("filename"),
            "status": file_data.get("status"),
            "additions": file_data.get("additions"),
            "deletions": file_data.get("deletions"),
            "subsystem": subsystem,
            "component": component,
            "expected_test_hint": expected_test_hint,
        })
    return result


def _build_file_models(file_reports):
    return [
        FileEvidence(
            filename=str(item.get("filename") or ""),
            status=str(item.get("status") or "modified"),
            additions=_safe_int(item.get("additions")),
            deletions=_safe_int(item.get("deletions")),
            subsystem=str(item.get("subsystem") or "unknown"),
            component=str(item.get("component") or "unknown"),
            expected_test_hint=item.get("expected_test_hint"),
        )
        for item in file_reports
    ]


def _build_evidence_counts(evidence, linked_issues, gh):
    timeline = _normalise_timeline(evidence)
    reviews = evidence.get("reviews", [])
    review_comments = evidence.get("review_comments", [])
    issue_comments = evidence.get("issue_comments", [])
    history_files = history_commits = history_errors = 0
    for file_data in _normalise_files(evidence):
        history = file_data.get("history")
        if isinstance(history, list):
            history_files += 1
            history_commits += len(history)
    evidence_errors = evidence.get("evidence_errors", {})
    if isinstance(evidence_errors, Mapping):
        history_errors = sum(
            1 for k, v in evidence_errors.items()
            if str(k).startswith("history:") and v is not None
        )
    return {
        "timeline_events": len(timeline),
        "human_timeline_events": sum(not bool(e.get("bot")) for e in timeline),
        "reviews": len(reviews) if isinstance(reviews, list) else 0,
        "review_comments": len(review_comments) if isinstance(review_comments, list) else 0,
        "issue_comments": len(issue_comments) if isinstance(issue_comments, list) else 0,
        "linked_issues": len(linked_issues),
        "history_files": history_files,
        "history_commits": history_commits,
        "history_errors": history_errors,
        "api_calls": getattr(gh, "calls", 0),
        "cache_hits": getattr(gh, "cache_hits", 0),
        "rate_limit_remaining": getattr(gh, "rate_remaining", None),
        "rate_limit_reset": getattr(gh, "rate_reset", None),
    }


def _history_entry_summary(entry):
    author = entry.get("author")
    if isinstance(author, Mapping):
        author = author.get("login") or author.get("name")
    return {
        "sha": entry.get("sha"),
        "message": entry.get("message"),
        "author": str(author) if author is not None else None,
        "date": entry.get("date") or entry.get("committed_at") or entry.get("created_at"),
        "html_url": entry.get("html_url"),
    }


def _build_historical_context(evidence):
    files = []
    history_files = history_commits = history_errors = 0
    for file_data in _normalise_files(evidence):
        filename = str(file_data.get("filename") or "")
        history = file_data.get("history")
        if not isinstance(history, list):
            continue
        history_files += 1
        history_commits += len(history)
        commits = [_history_entry_summary(e) for e in history if isinstance(e, Mapping)]
        authors = sorted({str(c["author"]) for c in commits if c.get("author")})
        files.append({
            "filename": filename,
            "commit_count": len(commits),
            "latest_commit": commits[0] if commits else None,
            "authors": authors,
        })
    evidence_errors = evidence.get("evidence_errors", {})
    if isinstance(evidence_errors, Mapping):
        history_errors = sum(
            1 for k, v in evidence_errors.items()
            if str(k).startswith("history:") and v is not None
        )
    context: dict[str, Any] = {
        "available": bool(history_files or history_errors),
        "history_files": history_files,
        "history_commits": history_commits,
        "history_errors": history_errors,
        "files": files,
    }
    historical_prs = evidence.get("historical_prs")
    if isinstance(historical_prs, list):
        context["size_baseline"] = summarize_sizes(historical_prs)
    return context


def _normalise_process(process):
    result: list[ProcessSignal] = []
    for item in process:
        if isinstance(item, ProcessSignal):
            result.append(item)
            continue
        if isinstance(item, Mapping):
            result.append(ProcessSignal(
                level=str(item.get("level") or item.get("signal") or "INFO"),
                message=str(item.get("message") or ""),
                source=str(item.get("source") or "policy"),
                rule_id=str(item["rule_id"]) if item.get("rule_id") is not None else None,
            ))
            continue
        try:
            signal, message = item
            result.append(ProcessSignal(level=str(signal), message=str(message)))
        except (TypeError, ValueError):
            continue
    return result


def _normalise_findings(findings):
    result: list[Finding] = []
    for finding in findings:
        if isinstance(finding, Finding):
            result.append(finding)
            continue
        if isinstance(finding, Mapping):
            result.append(Finding(**dict(finding)))
            continue
        as_dict = getattr(finding, "as_dict", None)
        if callable(as_dict):
            payload = as_dict()
            if isinstance(payload, Mapping):
                result.append(Finding(**dict(payload)))
    return result


def _normalise_experts(experts: list[Any]) -> list[OwnershipMatch]:
    result: list[OwnershipMatch] = []
    for expert in experts:
        if isinstance(expert, OwnershipMatch):
            result.append(expert)
            continue
        if not isinstance(expert, Mapping):
            continue
        owner = expert.get("owner") or expert.get("owners")
        filename = expert.get("file") or expert.get("filename")
        result.append(OwnershipMatch(
            owner=str(owner or ""),
            file=str(filename or ""),
            pattern=str(expert.get("pattern") or ""),
            line=_safe_int(expert.get("line")),
        ))
    return result


def _build_expert_contexts(
    experts: list[Any],
    reviewer_activity_cache: Any | None = None,
) -> list[ExpertContext]:
    """
    Build enriched ExpertContext objects from CODEOWNERS matches.

    Merges static profiles from reviewer_profiles.py with optional
    dynamic activity from reviewer_activity.py.
    """
    try:
        from .reviewer_profiles import co_reviewer_suggestions, get_profile
    except ImportError:
        get_profile = lambda u: None
        co_reviewer_suggestions = lambda e, **kw: []

    result: list[ExpertContext] = []
    for expert in experts:
        if isinstance(expert, ExpertContext):
            result.append(expert)
            continue
        if not isinstance(expert, Mapping):
            continue

        owner = str(expert.get("owner") or expert.get("owners") or "")
        filename = str(expert.get("file") or expert.get("filename") or "")
        pattern = str(expert.get("pattern") or "")
        line = _safe_int(expert.get("line"))
        username = owner.lstrip("@")

        profile = get_profile(username)

        subsystems: list[str] = []
        co_owners: list[str] = []
        known_concerns: list[str] = []
        focus_keywords: list[str] = []
        typical_response_days: float | None = None

        if profile:
            subsystems = list(profile.subsystems)
            co_owners = list(profile.co_owners)
            known_concerns = list(profile.known_concerns)
            focus_keywords = list(profile.focus_keywords)
            typical_response_days = profile.typical_response_days

        # Dynamic activity (optional — gracefully skipped if unavailable)
        dynamic_concerns: list[str] = []
        approval_rate: float | None = None
        sample_phrases: list[str] = []

        if reviewer_activity_cache is not None:
            try:
                activity = reviewer_activity_cache.get(username)
                approval_rate = activity.approval_rate
                sample_phrases = activity.sample_phrases[:6]

                concern_labels = {
                    "needs_test": "typically requests a regression test",
                    "needs_news": "typically requests a NEWS entry",
                    "needs_docs": "typically requests documentation update",
                    "needs_regen": "typically requests regeneration of generated files",
                    "needs_benchmark": "typically requests a performance benchmark",
                    "minimal_change": "often asks to split large PRs",
                    "api_compat": "scrutinizes backward compatibility",
                    "thread_safety": "checks for thread safety / free-threading",
                    "security": "reviews security implications carefully",
                }
                dynamic_concerns = [
                    concern_labels[c]
                    for c in activity.top_concerns
                    if c in concern_labels
                ]
            except Exception:
                pass

        result.append(ExpertContext(
            owner=owner,
            file=filename,
            pattern=pattern,
            line=line,
            subsystems=subsystems,
            co_owners=co_owners,
            known_concerns=known_concerns,
            focus_keywords=focus_keywords,
            dynamic_concerns=dynamic_concerns,
            approval_rate=approval_rate,
            typical_response_days=typical_response_days,
            sample_phrases=sample_phrases,
        ))

    return result


def _normalise_check_models(checks: Mapping[str, Any]) -> CheckSummary:
    summary = checks.get("summary", {})
    if not isinstance(summary, Mapping):
        return CheckSummary(available=False)

    # "check_runs" count: prefer explicit key, then "total", then "available"
    # when available is an integer (some callers store count there), then
    # fall back to len(checks["check_runs"]) list.
    raw_available = summary.get("available")

    check_runs = summary.get("check_runs")
    if check_runs is None:
        check_runs = summary.get("total")
    if check_runs is None and isinstance(raw_available, int):
        # available is being used as the count (not a bool flag)
        check_runs = raw_available
    if check_runs is None:
        raw = checks.get("check_runs")
        check_runs = len(raw) if isinstance(raw, list) else 0

    completed = summary.get("completed", 0)

    # Support both "successes"/"passed" and "failures"/"failed" aliases
    successes = summary.get("successes")
    if successes is None:
        successes = summary.get("passed", 0)

    failures = summary.get("failures")
    if failures is None:
        failures = summary.get("failed", 0)

    pending = summary.get("pending")
    if pending is None:
        pending = summary.get("skipped", 0)

    # available flag: if it's an int we used it as count above, so coerce to bool
    if raw_available is None:
        available = bool(
            _safe_int(check_runs) or _safe_int(completed) or
            _safe_int(successes) or _safe_int(failures) or
            _safe_int(pending) or summary.get("legacy_status")
        )
    else:
        available = bool(raw_available)

    return CheckSummary(
        available=available,
        check_runs=_safe_int(check_runs),
        completed=_safe_int(completed),
        successes=_safe_int(successes),
        failures=_safe_int(failures),
        pending=_safe_int(pending),
        legacy_status=str(summary["legacy_status"]) if summary.get("legacy_status") is not None else None,
        error=str(summary["error"]) if summary.get("error") is not None else None,
    )


def build_report(
    *,
    repository: str,
    generated_at: str,
    evidence: dict[str, Any],
    linked_issues: list[dict[str, Any]],
    experts: list[dict[str, Any]],
    findings: list[Any],
    signatures: list[dict[str, Any]],
    process: list[tuple[str, str]],
    backports: list[str],
    disposition: str,
    checks: dict[str, Any],
    classify: Callable[[str], tuple[str, str, str | None]],
    summarize_labels: Callable[[list[str], dict[str, Any]], list[dict[str, Any]]],
    label_metadata: Callable[[Any], dict[str, Any]],
    gh: Any,
    reviewer_activity_cache: Any | None = None,
) -> dict[str, Any]:
    """Build and validate the triager report."""
    if not isinstance(evidence, Mapping): evidence = {}
    if not isinstance(linked_issues, list): linked_issues = []
    if not isinstance(experts, list): experts = []
    if not isinstance(findings, list): findings = []
    if not isinstance(signatures, list): signatures = []
    if not isinstance(process, list): process = list(process or [])
    if not isinstance(backports, list): backports = list(backports or [])
    if not isinstance(checks, Mapping): checks = {}

    pr = evidence.get("pr")
    if not isinstance(pr, Mapping): pr = {}

    files = _normalise_files(evidence)
    timeline = _normalise_timeline(evidence)
    labels = _normalise_labels(pr)

    additions = sum(_safe_int(f.get("additions")) for f in files)
    deletions = sum(_safe_int(f.get("deletions")) for f in files)

    process_models = _normalise_process(process)

    check_summary = checks.get("summary", {})
    if not isinstance(check_summary, Mapping): check_summary = {}
    failures = _safe_int(check_summary.get("failures"))
    if failures:
        process_models.append(ProcessSignal(
            signal="WARN",
            message=f"{failures} completed CI check(s) have failure-like conclusions.",
        ))

    evidence_completeness = _build_evidence_completeness(evidence)
    file_reports = _build_file_reports(files, classify)
    historical_context = _build_historical_context(evidence)

    # Build enriched ExpertContext objects with reviewer profiles + activity
    expert_contexts = _build_expert_contexts(experts, reviewer_activity_cache)

    canonical = TriageReport(
        schema_version=SCHEMA_VERSION,
        repository=str(repository),
        generated_at=str(generated_at),
        disposition=str(disposition),
        pr=_build_pr_summary(pr, labels, additions, deletions),
        process_signals=process_models,
        technical_findings=_normalise_findings(findings),
        files=_build_file_models(file_reports),
        experts=_normalise_experts(experts),
        expert_contexts=expert_contexts,
        checks=_normalise_check_models(checks),
        evidence_completeness=evidence_completeness,
        linked_issues=linked_issues,
        references={},
        backport_targets=[str(item) for item in backports],
        signature_changes=signatures,
        historical_context=historical_context,
        metadata={},
    )

    report = canonical.as_dict()

    # Capture canonical CheckSummary dict BEFORE overwriting report["checks"]
    # with the raw checks dict. check_summaries must be the normalized model output.
    canonical_check_summaries = report.get("checks")

    report["labels"] = summarize_labels(labels, label_metadata(gh))
    report["timeline"] = timeline
    report["checks"] = dict(checks)
    report["check_summaries"] = canonical_check_summaries
    report["evidence_counts"] = _build_evidence_counts(evidence, linked_issues, gh)

    extra_metadata = evidence.get("report_metadata")
    if isinstance(extra_metadata, Mapping):
        metadata = report.setdefault("metadata", {})
        if isinstance(metadata, dict):
            for key, value in extra_metadata.items():
                key = str(key)
                if key not in metadata:
                    metadata[key] = value

    return report