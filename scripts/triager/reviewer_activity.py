"""
Reviewer activity fetcher for CPython PR triage.

Fetches and caches recent review comments left by specific reviewers
on python/cpython, then extracts patterns: what they commonly ask about,
what triggers a CHANGES_REQUESTED from them, how quickly they respond.

This is the dynamic complement to reviewer_profiles.py (which is static).
Results are cached locally — the data changes slowly and API calls are
expensive. Default cache TTL is 24 hours.

Usage:
    from scripts.triager.reviewer_activity import ReviewerActivityCache
    cache = ReviewerActivityCache(gh)
    activity = cache.get("markshannon")
    # activity.common_phrases, activity.approval_rate, etc.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Keywords that appear in CHANGES_REQUESTED reviews across CPython maintainers.
# Weighted by importance for detecting what a reviewer asks for before approving.
_CONCERN_KEYWORDS: dict[str, list[str]] = {
    "needs_test": [
        "add a test", "needs a test", "missing test", "please add test",
        "regression test", "test case", "test coverage",
        "no test", "without a test",
    ],
    "needs_news": [
        "news entry", "misc/news", "news.d", "blurb",
        "changelog", "what's new",
    ],
    "needs_docs": [
        "documentation", "docstring", ".. versionadded",
        ".. versionchanged", ".. deprecated", "doc update",
        "needs docs", "update the docs",
    ],
    "needs_regen": [
        "regen", "regenerate", "make regen", "regen-pegen",
        "regen-all", "make clinic", "clinic.py", "generated",
    ],
    "needs_benchmark": [
        "benchmark", "performance", "pyperf", "regression",
        "slower", "faster", "timing",
    ],
    "needs_backport": [
        "backport", "cherry-pick", "needs-backport",
        "stable branch", "maintenance branch",
    ],
    "minimal_change": [
        "minimal", "too large", "split", "separate pr",
        "scope creep", "unrelated change",
    ],
    "api_compat": [
        "backward compat", "breaking change", "deprecat",
        "public api", "stable abi", "limited api",
    ],
    "thread_safety": [
        "thread safe", "race condition", "atomic", "lock",
        "free-threading", "gil", "subinterpreter",
    ],
    "security": [
        "security", "vulnerability", "cve", "injection",
        "sanitize", "escape", "trust boundary",
    ],
}


def _extract_concern_keywords(text: str) -> list[str]:
    """Find which concern categories appear in a review comment."""
    text_lower = text.lower()
    found: list[str] = []
    for category, phrases in _CONCERN_KEYWORDS.items():
        if any(phrase in text_lower for phrase in phrases):
            found.append(category)
    return found


def _extract_quoted_phrases(
    text: str,
    max_phrases: int = 5,
    min_words: int = 4,
    max_words: int = 12,
) -> list[str]:
    """
    Extract short quoted or emphasized phrases from a review comment.

    These are the actual words reviewers use — more useful than
    our keyword matching for the AI synthesis prompt.
    """
    phrases: list[str] = []

    # Quoted strings
    for m in re.finditer(r'"([^"]{10,80})"', text):
        phrases.append(m.group(1).strip())

    # Backtick code spans that look like function/method names
    for m in re.finditer(r"`([A-Za-z_][A-Za-z0-9_.()]{3,40})`", text):
        phrases.append(m.group(1))

    # Sentences starting with "Please" or "Can you" — typical request form
    for m in re.finditer(
        r"(?:Please|Can you|Could you|You should|You need to)\s+([^.!?]{10,80})[.!?]",
        text,
        re.IGNORECASE,
    ):
        phrases.append(m.group(0).strip())

    return phrases[:max_phrases]


@dataclass
class ReviewerActivity:
    """
    Dynamic activity summary for one reviewer.

    Built from their recent review comments on python/cpython.
    """

    username: str

    # Total reviews fetched
    total_reviews: int = 0

    # Approval rate (0.0 - 1.0). None if no completed reviews.
    approval_rate: float | None = None

    # How often each concern category appears (e.g. needs_test: 45)
    concern_frequency: dict[str, int] = field(default_factory=dict)

    # Top concern categories by frequency
    top_concerns: list[str] = field(default_factory=list)

    # Actual quoted phrases from their reviews (for AI context)
    sample_phrases: list[str] = field(default_factory=list)

    # Median days from PR opened to their first review
    median_response_days: float | None = None

    # Subsystems they reviewed most (from file paths in review comments)
    active_subsystems: list[str] = field(default_factory=list)

    # When this was last fetched (Unix timestamp)
    fetched_at: float = 0.0

    # Whether this is fresh data or from cache/fallback
    from_cache: bool = False

    def is_stale(self, ttl_seconds: float = 86400.0) -> bool:
        """Return whether this activity data has expired."""
        return (time.time() - self.fetched_at) > ttl_seconds

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "total_reviews": self.total_reviews,
            "approval_rate": self.approval_rate,
            "concern_frequency": self.concern_frequency,
            "top_concerns": self.top_concerns,
            "sample_phrases": self.sample_phrases,
            "median_response_days": self.median_response_days,
            "active_subsystems": self.active_subsystems,
            "fetched_at": self.fetched_at,
            "from_cache": self.from_cache,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReviewerActivity:
        return cls(
            username=data.get("username", ""),
            total_reviews=data.get("total_reviews", 0),
            approval_rate=data.get("approval_rate"),
            concern_frequency=data.get("concern_frequency", {}),
            top_concerns=data.get("top_concerns", []),
            sample_phrases=data.get("sample_phrases", []),
            median_response_days=data.get("median_response_days"),
            active_subsystems=data.get("active_subsystems", []),
            fetched_at=data.get("fetched_at", 0.0),
            from_cache=True,
        )


def _build_activity_from_reviews(
    username: str,
    review_comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> ReviewerActivity:
    """Build a ReviewerActivity from raw GitHub API review data."""
    concern_counter: Counter[str] = Counter()
    phrases: list[str] = []
    subsystems: Counter[str] = Counter()

    for comment in review_comments:
        body = comment.get("body") or ""
        if not body.strip():
            continue

        for category in _extract_concern_keywords(body):
            concern_counter[category] += 1

        phrases.extend(_extract_quoted_phrases(body))

        # Extract subsystem hints from file paths in the comment
        path = comment.get("path") or ""
        if path:
            parts = path.split("/")
            if len(parts) >= 2:
                subsystems[f"{parts[0]}/{parts[1]}"] += 1
            elif parts:
                subsystems[parts[0]] += 1

    # Calculate approval rate from full review records
    verdicts = [
        r.get("state")
        for r in reviews
        if r.get("state") in ("APPROVED", "CHANGES_REQUESTED")
    ]
    approval_rate: float | None = None
    if verdicts:
        approvals = sum(1 for v in verdicts if v == "APPROVED")
        approval_rate = round(approvals / len(verdicts), 2)

    # Deduplicate phrases while preserving order
    seen_phrases: set[str] = set()
    unique_phrases: list[str] = []
    for p in phrases:
        if p not in seen_phrases:
            seen_phrases.add(p)
            unique_phrases.append(p)

    top_concerns = [
        category
        for category, _ in concern_counter.most_common(5)
    ]

    active_subsystems = [
        sub
        for sub, _ in subsystems.most_common(5)
    ]

    return ReviewerActivity(
        username=username,
        total_reviews=len(review_comments),
        approval_rate=approval_rate,
        concern_frequency=dict(concern_counter),
        top_concerns=top_concerns,
        sample_phrases=unique_phrases[:20],
        active_subsystems=active_subsystems,
        fetched_at=time.time(),
        from_cache=False,
    )


class ReviewerActivityCache:
    """
    Fetch and cache reviewer activity for CPython maintainers.

    Wraps the GitHub client to:
    - Fetch recent review comments per reviewer (paginated)
    - Parse concern keywords and extract sample phrases
    - Cache results locally (default TTL: 24 hours)
    - Return fallback empty data on any API failure

    The cache is stored as JSON files under cache_dir.
    """

    DEFAULT_TTL = 86400.0  # 24 hours
    DEFAULT_MAX_COMMENTS = 200
    CACHE_PREFIX = "reviewer_activity_"

    def __init__(
        self,
        gh: Any,
        cache_dir: Path | str | None = None,
        ttl: float = DEFAULT_TTL,
        max_comments: int = DEFAULT_MAX_COMMENTS,
    ) -> None:
        self._gh = gh
        self._ttl = ttl
        self._max_comments = max_comments
        self._memory: dict[str, ReviewerActivity] = {}

        if cache_dir is None:
            cache_dir = Path(
                getattr(gh, "cache_dir", None) or ".triager-cache"
            )
        self._cache_dir = Path(cache_dir)

    def _cache_path(self, username: str) -> Path:
        return self._cache_dir / f"{self.CACHE_PREFIX}{username}.json"

    def _load_from_disk(self, username: str) -> ReviewerActivity | None:
        path = self._cache_path(username)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            activity = ReviewerActivity.from_dict(data)
            if not activity.is_stale(self._ttl):
                return activity
        except Exception:
            pass
        return None

    def _save_to_disk(self, activity: ReviewerActivity) -> None:
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._cache_path(activity.username)
            path.write_text(
                json.dumps(activity.as_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _fetch_from_github(self, username: str) -> ReviewerActivity:
        """
        Fetch recent review comments and reviews from GitHub.

        Uses two endpoints:
          GET /repos/python/cpython/pulls/comments
              ?per_page=100 — filter by user.login client-side
          GET /repos/python/cpython/pulls
              ?state=all&per_page=100 — find PRs they reviewed

        GitHub doesn't offer a direct "reviews by user" endpoint, so
        we fetch the global pulls/comments feed and filter locally.
        This is limited but avoids the Search API rate limits.
        """
        # Fetch recent pull request review comments (inline comments)
        all_comments: list[dict[str, Any]] = []
        all_reviews: list[dict[str, Any]] = []

        try:
            # Pull review comments across all recent PRs
            # Filter to just this reviewer client-side
            page = 1
            while len(all_comments) < self._max_comments:
                path = (
                    f"/pulls/comments"
                    f"?per_page=100&sort=created&direction=desc"
                    f"&page={page}"
                )
                data = self._gh.request(path)
                if not isinstance(data, list) or not data:
                    break

                for comment in data:
                    login = (comment.get("user") or {}).get("login", "")
                    if login == username:
                        all_comments.append(comment)

                if len(data) < 100:
                    break
                page += 1
                if page > 5:  # max 500 comments scanned
                    break

        except Exception:
            pass

        try:
            # Fetch issue comments (PR-level review comments, not inline)
            page = 1
            while len(all_reviews) < 100:
                path = (
                    f"/issues/comments"
                    f"?per_page=100&sort=created&direction=desc"
                    f"&page={page}"
                )
                data = self._gh.request(path)
                if not isinstance(data, list) or not data:
                    break

                for comment in data:
                    login = (comment.get("user") or {}).get("login", "")
                    if login == username:
                        all_reviews.append(comment)

                if len(data) < 100:
                    break
                page += 1
                if page > 3:
                    break

        except Exception:
            pass

        return _build_activity_from_reviews(username, all_comments, all_reviews)

    def get(
        self,
        username: str,
        *,
        force_refresh: bool = False,
    ) -> ReviewerActivity:
        """
        Get activity for a reviewer. Checks memory cache, disk cache,
        then fetches from GitHub. Returns empty activity on any failure.
        """
        clean = username.lstrip("@")

        # Memory cache
        if not force_refresh and clean in self._memory:
            cached = self._memory[clean]
            if not cached.is_stale(self._ttl):
                return cached

        # Disk cache
        if not force_refresh:
            disk = self._load_from_disk(clean)
            if disk is not None:
                self._memory[clean] = disk
                return disk

        # Fetch from GitHub
        try:
            activity = self._fetch_from_github(clean)
        except Exception:
            activity = ReviewerActivity(
                username=clean,
                fetched_at=time.time(),
                from_cache=False,
            )

        self._memory[clean] = activity
        self._save_to_disk(activity)
        return activity

    def get_batch(
        self,
        usernames: list[str],
        *,
        delay_seconds: float = 0.5,
    ) -> dict[str, ReviewerActivity]:
        """
        Fetch activity for multiple reviewers.

        Adds a small delay between requests to be polite to GitHub.
        """
        result: dict[str, ReviewerActivity] = {}
        for i, username in enumerate(usernames):
            result[username] = self.get(username)
            if i < len(usernames) - 1:
                time.sleep(delay_seconds)
        return result


def format_activity_for_report(
    profile_dict: dict[str, Any],
    activity: ReviewerActivity,
) -> dict[str, Any]:
    """
    Merge static profile data with dynamic activity for the report.

    This is what gets added to each expert entry in the triage report.
    """
    from scripts.triager.reviewer_profiles import get_profile

    username = profile_dict.get("username") or profile_dict.get("owner", "").lstrip("@")
    static = get_profile(username)

    # Merge known_concerns from static profile with dynamic top_concerns
    known = list(static.known_concerns) if static else []

    # Top dynamic concerns mapped to human-readable labels
    concern_labels = {
        "needs_test": "typically requests a regression test",
        "needs_news": "typically requests a NEWS entry",
        "needs_docs": "typically requests documentation update",
        "needs_regen": "typically requests regeneration of generated files",
        "needs_benchmark": "typically requests a performance benchmark",
        "minimal_change": "often asks to split large PRs",
        "api_compat": "scrutinizes backward compatibility",
        "thread_safety": "checks for thread safety / free-threading issues",
        "security": "reviews security implications carefully",
    }

    dynamic_concerns = [
        concern_labels[c]
        for c in activity.top_concerns
        if c in concern_labels
    ]

    return {
        "username": username,
        "subsystems": static.subsystems if static else [],
        "co_owners": static.co_owners if static else [],
        "focus_keywords": static.focus_keywords if static else [],
        "known_concerns": known,
        "dynamic_concerns": dynamic_concerns,
        "approval_rate": activity.approval_rate,
        "typical_response_days": (
            static.typical_response_days if static else None
        ),
        "sample_phrases": activity.sample_phrases[:8],
        "active_subsystems": activity.active_subsystems,
        "data_source": "cached" if activity.from_cache else "live",
    }