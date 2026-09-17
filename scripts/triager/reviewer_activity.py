"""
Reviewer activity fetcher for CPython PR triage.

Fetches and caches recent review activity left by specific reviewers
on python/cpython, then extracts patterns: what they commonly ask about,
what triggers a CHANGES_REQUESTED from them, how quickly they respond.

This is the dynamic complement to reviewer_profiles.py (which is static).
Results are cached locally — the data changes slowly and API calls are
expensive. Default cache TTL is 24 hours.

Important:
    GitHub exposes several different kinds of PR conversation objects.
    This module intentionally distinguishes:

    - Pull-request review comments: inline/file-level comments
    - Submitted pull-request reviews: APPROVED / CHANGES_REQUESTED / COMMENT
    - Issue comments: general PR conversation

    Issue comments are NOT treated as submitted reviews, because doing so
    would make approval-rate and review-verdict statistics incorrect.

Usage:
    from scripts.triager.reviewer_activity import ReviewerActivityCache

    cache = ReviewerActivityCache(gh)
    activity = cache.get("markshannon")

    # activity.approval_rate
    # activity.median_response_days
    # activity.sample_phrases
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Keywords that appear in CHANGES_REQUESTED reviews across CPython maintainers.
_CONCERN_KEYWORDS: dict[str, list[str]] = {
    "needs_test": [
        "add a test",
        "needs a test",
        "missing test",
        "please add test",
        "regression test",
        "test case",
        "test coverage",
        "no test",
        "without a test",
    ],
    "needs_news": [
        "news entry",
        "misc/news",
        "news.d",
        "blurb",
        "changelog",
        "what's new",
    ],
    "needs_docs": [
        "documentation",
        "docstring",
        ".. versionadded",
        ".. versionchanged",
        ".. deprecated",
        "doc update",
        "needs docs",
        "update the docs",
    ],
    "needs_regen": [
        "regen",
        "regenerate",
        "make regen",
        "regen-pegen",
        "regen-all",
        "make clinic",
        "clinic.py",
        "generated",
    ],
    "needs_benchmark": [
        "benchmark",
        "performance",
        "pyperf",
        "regression",
        "slower",
        "faster",
        "timing",
    ],
    "needs_backport": [
        "backport",
        "cherry-pick",
        "needs-backport",
        "stable branch",
        "maintenance branch",
    ],
    "minimal_change": [
        "minimal",
        "too large",
        "split",
        "separate pr",
        "scope creep",
        "unrelated change",
    ],
    "api_compat": [
        "backward compat",
        "breaking change",
        "deprecat",
        "public api",
        "stable abi",
        "limited api",
    ],
    "thread_safety": [
        "thread safe",
        "race condition",
        "atomic",
        "lock",
        "free-threading",
        "gil",
        "subinterpreter",
    ],
    "security": [
        "security",
        "vulnerability",
        "cve",
        "injection",
        "sanitize",
        "escape",
        "trust boundary",
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
    # Retained for compatibility with existing callers.
    del min_words, max_words

    phrases: list[str] = []

    # Quoted strings.
    for match in re.finditer(r'"([^"]{10,80})"', text):
        phrases.append(match.group(1).strip())

    # Backtick code spans that look like function/method names.
    for match in re.finditer(
        r"`([A-Za-z_][A-Za-z0-9_.()]{3,40})`",
        text,
    ):
        phrases.append(match.group(1))

    # Common review-request forms.
    for match in re.finditer(
        r"(?:Please|Can you|Could you|You should|You need to)\s+"
        r"([^.!?]{10,80})[.!?]",
        text,
        re.IGNORECASE,
    ):
        phrases.append(match.group(0).strip())

    return phrases[:max_phrases]


def _parse_github_datetime(value: Any) -> datetime | None:
    """
    Parse a GitHub ISO-8601 timestamp.

    Returns None for missing or malformed timestamps.
    """
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None


def _response_days(
    pr_created_at: Any,
    review_submitted_at: Any,
) -> float | None:
    """Return elapsed days between PR creation and review submission."""
    created = _parse_github_datetime(pr_created_at)
    submitted = _parse_github_datetime(review_submitted_at)

    if created is None or submitted is None:
        return None

    delta_seconds = (
        submitted - created
    ).total_seconds()

    if delta_seconds < 0:
        return None

    return delta_seconds / 86400.0


@dataclass
class ReviewerActivity:
    """
    Dynamic activity summary for one reviewer.

    Built from their recent GitHub review comments and submitted reviews
    on python/cpython.
    """

    username: str

    # Number of submitted PR review records fetched.
    total_reviews: int = 0

    # Approval rate based only on submitted review verdicts.
    approval_rate: float | None = None

    # Number of APPROVED/CHANGES_REQUESTED verdicts used for the rate.
    approval_rate_sample_size: int = 0

    # Concern frequency derived from review text.
    concern_frequency: dict[str, int] = field(default_factory=dict)

    # Top concern categories by frequency.
    top_concerns: list[str] = field(default_factory=list)

    # Actual quoted/request phrases from reviews.
    sample_phrases: list[str] = field(default_factory=list)

    # Median days from PR opened to the reviewer's first review.
    median_response_days: float | None = None

    # Subsystems represented by inline review comments.
    active_subsystems: list[str] = field(default_factory=list)

    # Unix timestamp of the fetch.
    fetched_at: float = 0.0

    # True when loaded from cache.
    from_cache: bool = False

    # Whether usable reviewer evidence was obtained.
    available: bool = True

    # Human-readable collection errors.
    error: str | None = None

    def is_stale(
        self,
        ttl_seconds: float = 86400.0,
    ) -> bool:
        """Return whether this activity data has expired."""
        return (
            time.time() - self.fetched_at
        ) > ttl_seconds

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "total_reviews": self.total_reviews,
            "approval_rate": self.approval_rate,
            "approval_rate_sample_size": (
                self.approval_rate_sample_size
            ),
            "concern_frequency": self.concern_frequency,
            "top_concerns": self.top_concerns,
            "sample_phrases": self.sample_phrases,
            "median_response_days": (
                self.median_response_days
            ),
            "active_subsystems": self.active_subsystems,
            "fetched_at": self.fetched_at,
            "from_cache": self.from_cache,
            "available": self.available,
            "error": self.error,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> ReviewerActivity:
        return cls(
            username=data.get("username", ""),
            total_reviews=data.get(
                "total_reviews",
                0,
            ),
            approval_rate=data.get(
                "approval_rate"
            ),
            approval_rate_sample_size=data.get(
                "approval_rate_sample_size",
                0,
            ),
            concern_frequency=data.get(
                "concern_frequency",
                {},
            ),
            top_concerns=data.get(
                "top_concerns",
                [],
            ),
            sample_phrases=data.get(
                "sample_phrases",
                [],
            ),
            median_response_days=data.get(
                "median_response_days"
            ),
            active_subsystems=data.get(
                "active_subsystems",
                [],
            ),
            fetched_at=data.get(
                "fetched_at",
                0.0,
            ),
            from_cache=True,
            available=data.get(
                "available",
                True,
            ),
            error=data.get("error"),
        )


MIN_APPROVAL_RATE_SAMPLE = 5

# Reviewer history is intentionally bounded.
DEFAULT_MAX_REVIEWED_PRS = 50
DEFAULT_MAX_REVIEW_SUBMISSIONS = 200


def _build_activity_from_reviews(
    username: str,
    review_comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> ReviewerActivity:
    """
    Build ReviewerActivity from raw GitHub review data.

    `review_comments` contains inline/file-level review comments.

    `reviews` contains actual submitted pull-request review records.

    Approval statistics are calculated ONLY from submitted review records.
    """

    concern_counter: Counter[str] = Counter()
    phrases: list[str] = []
    subsystems: Counter[str] = Counter()

    # ==============================================================
    # Inline review comments
    # ==============================================================
    for comment in review_comments:
        body = comment.get("body") or ""

        if body.strip():
            for category in _extract_concern_keywords(body):
                concern_counter[category] += 1

            phrases.extend(
                _extract_quoted_phrases(body)
            )

        path = comment.get("path") or ""

        if path:
            parts = path.split("/")

            if len(parts) >= 2:
                subsystems[
                    f"{parts[0]}/{parts[1]}"
                ] += 1
            else:
                subsystems[parts[0]] += 1

    # ==============================================================
    # Submitted review bodies
    # ==============================================================
    for review in reviews:
        body = review.get("body") or ""

        if not body.strip():
            continue

        for category in _extract_concern_keywords(body):
            concern_counter[category] += 1

        phrases.extend(
            _extract_quoted_phrases(body)
        )

    # ==============================================================
    # Approval rate
    # ==============================================================
    verdicts = [
        review.get("state")
        for review in reviews
        if review.get("state") in (
            "APPROVED",
            "CHANGES_REQUESTED",
        )
    ]

    approval_rate_sample_size = len(verdicts)
    approval_rate: float | None = None

    if approval_rate_sample_size >= MIN_APPROVAL_RATE_SAMPLE:
        approvals = sum(
            1
            for verdict in verdicts
            if verdict == "APPROVED"
        )

        approval_rate = round(
            approvals / approval_rate_sample_size,
            2,
        )

    # ==============================================================
    # Median response time
    # ==============================================================
    response_days: list[float] = []

    first_review_by_pr: dict[
        int,
        dict[str, Any],
    ] = {}

    for review in reviews:
        pr_number = review.get("pr_number")

        if not isinstance(pr_number, int):
            try:
                pr_number = int(pr_number)
            except (TypeError, ValueError):
                continue

        submitted_at = review.get(
            "submitted_at"
        )

        if _parse_github_datetime(
            submitted_at
        ) is None:
            continue

        existing = first_review_by_pr.get(
            pr_number
        )

        if existing is None:
            first_review_by_pr[pr_number] = review
            continue

        existing_time = _parse_github_datetime(
            existing.get("submitted_at")
        )

        current_time = _parse_github_datetime(
            submitted_at
        )

        if (
            existing_time is not None
            and current_time is not None
            and current_time < existing_time
        ):
            first_review_by_pr[pr_number] = review

    for review in first_review_by_pr.values():
        days = _response_days(
            review.get("pr_created_at"),
            review.get("submitted_at"),
        )

        if days is not None:
            response_days.append(days)

    median_response_days: float | None = None

    if response_days:
        response_days.sort()

        count = len(response_days)
        middle = count // 2

        if count % 2:
            median_response_days = round(
                response_days[middle],
                2,
            )
        else:
            median_response_days = round(
                (
                    response_days[middle - 1]
                    + response_days[middle]
                )
                / 2,
                2,
            )

    # ==============================================================
    # Deduplicate phrases
    # ==============================================================
    seen_phrases: set[str] = set()
    unique_phrases: list[str] = []

    for phrase in phrases:
        normalized = " ".join(
            phrase.split()
        )

        if not normalized:
            continue

        if normalized in seen_phrases:
            continue

        seen_phrases.add(normalized)
        unique_phrases.append(normalized)

    # ==============================================================
    # Top concerns / active subsystems
    # ==============================================================
    top_concerns = [
        category
        for category, _ in concern_counter.most_common(5)
    ]

    active_subsystems = [
        subsystem
        for subsystem, _ in subsystems.most_common(5)
    ]

    return ReviewerActivity(
        username=username,

        # IMPORTANT:
        # This is submitted-review count, NOT inline-comment count.
        total_reviews=len(reviews),

        approval_rate=approval_rate,
        approval_rate_sample_size=(
            approval_rate_sample_size
        ),
        concern_frequency=dict(
            concern_counter
        ),
        top_concerns=top_concerns,
        sample_phrases=unique_phrases[:20],
        median_response_days=(
            median_response_days
        ),
        active_subsystems=active_subsystems,
        fetched_at=time.time(),
        from_cache=False,
    )


class ReviewerActivityCache:
    """
    Fetch and cache reviewer activity for CPython maintainers.

    The collector distinguishes three different GitHub concepts:

    1. Inline review comments:
       GET /pulls/comments

    2. PRs reviewed by a reviewer:
       GET /search/issues with reviewed-by:<username>

    3. Submitted review verdicts:
       GET /pulls/{number}/reviews

    General issue comments are never treated as submitted reviews.

    A successful empty response is valid evidence.

    A source failure is different from "zero activity" and is preserved
    through the `available` and `error` fields.

    The cache is stored as JSON files under cache_dir.
    """

    DEFAULT_TTL = 86400.0
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
        self._memory: dict[
            str,
            ReviewerActivity,
        ] = {}

        if cache_dir is None:
            cache_dir = Path(
                getattr(
                    gh,
                    "cache_dir",
                    None,
                )
                or ".triager-cache"
            )

        self._cache_dir = Path(
            cache_dir
        )

    def _cache_path(
        self,
        username: str,
    ) -> Path:
        return (
            self._cache_dir
            / f"{self.CACHE_PREFIX}{username}.json"
        )

    def _load_from_disk(
        self,
        username: str,
    ) -> ReviewerActivity | None:
        path = self._cache_path(username)

        if not path.exists():
            return None

        try:
            data = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

            activity = ReviewerActivity.from_dict(
                data
            )

            # Never cache a completely unavailable result.
            if not activity.available:
                return None

            if not activity.is_stale(
                self._ttl
            ):
                return activity

        except Exception:
            pass

        return None

    def _save_to_disk(
        self,
        activity: ReviewerActivity,
    ) -> None:
        # Failed/unavailable collection must never be persisted.
        if not activity.available:
            return

        try:
            self._cache_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            path = self._cache_path(
                activity.username
            )

            path.write_text(
                json.dumps(
                    activity.as_dict(),
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        except Exception:
            pass

    def _fetch_from_github(
        self,
        username: str,
    ) -> ReviewerActivity:
        """
        Fetch recent review comments and submitted reviews from GitHub.

        Evidence paths:

        - /pulls/comments
        - /search/issues with reviewed-by:<username>
        - /pulls/{number}/reviews

        /issues/comments is intentionally not used for review verdicts.
        """

        all_comments: list[
            dict[str, Any]
        ] = []

        all_reviews: list[
            dict[str, Any]
        ] = []

        errors: list[str] = []

        review_comments_available = False
        review_search_available = False
        submitted_reviews_available = False

        # ==============================================================
        # 1. Inline review comments
        # ==============================================================
        try:
            page = 1

            while len(all_comments) < self._max_comments:
                path = (
                    "/pulls/comments"
                    "?per_page=100"
                    "&sort=created"
                    "&direction=desc"
                    f"&page={page}"
                )

                data = self._gh.request(path)

                if not isinstance(data, list):
                    raise ValueError(
                        "GitHub review-comments response "
                        "was not a list"
                    )

                if not data:
                    break

                for comment in data:
                    login = (
                        (comment.get("user") or {})
                        .get("login", "")
                    )

                    if login == username:
                        all_comments.append(
                            comment
                        )

                        if (
                            len(all_comments)
                            >= self._max_comments
                        ):
                            break

                if len(data) < 100:
                    break

                page += 1

                if page > 5:
                    break

            review_comments_available = True

        except Exception as exc:
            errors.append(
                f"review comments: {exc}"
            )

        # ==============================================================
        # 2. Find PRs reviewed by reviewer
        # ==============================================================
        reviewed_prs: list[
            dict[str, Any]
        ] = []

        try:
            query = urllib.parse.urlencode(
                {
                    "q": (
                        "repo:python/cpython "
                        "is:pr "
                        f"reviewed-by:{username}"
                    ),
                    "per_page": (
                        DEFAULT_MAX_REVIEWED_PRS
                    ),
                    "page": 1,
                }
            )

            search_path = (
                f"/search/issues?{query}"
            )

            search_data = self._gh.request(
                search_path
            )

            if not isinstance(
                search_data,
                dict,
            ):
                raise ValueError(
                    "GitHub search response "
                    "was not an object"
                )

            items = search_data.get(
                "items"
            )

            if not isinstance(
                items,
                list,
            ):
                raise ValueError(
                    "GitHub search response "
                    "did not contain items"
                )

            reviewed_prs = items[
                :DEFAULT_MAX_REVIEWED_PRS
            ]

            # Successful search, including an empty result, is valid.
            review_search_available = True

        except Exception as exc:
            errors.append(
                f"reviewed-by search: {exc}"
            )

        # ==============================================================
        # 3. Submitted reviews
        # ==============================================================
        if review_search_available:

            # Successful search with zero PRs is valid evidence.
            if not reviewed_prs:
                submitted_reviews_available = True

            else:
                for item in reviewed_prs:
                    number = item.get(
                        "number"
                    )

                    if not isinstance(
                        number,
                        int,
                    ):
                        try:
                            number = int(number)
                        except (
                            TypeError,
                            ValueError,
                        ):
                            continue

                    pr_created_at = item.get(
                        "created_at"
                    )

                    try:
                        page = 1

                        while (
                            len(all_reviews)
                            < DEFAULT_MAX_REVIEW_SUBMISSIONS
                        ):
                            path = (
                                f"/pulls/{number}/reviews"
                                "?per_page=100"
                                f"&page={page}"
                            )

                            data = self._gh.request(
                                path
                            )

                            if not isinstance(
                                data,
                                list,
                            ):
                                raise ValueError(
                                    "GitHub reviews response "
                                    "was not a list"
                                )

                            # The endpoint itself succeeded.
                            submitted_reviews_available = True

                            if not data:
                                break

                            for review in data:
                                login = (
                                    (
                                        review.get(
                                            "user"
                                        )
                                        or {}
                                    ).get(
                                        "login",
                                        "",
                                    )
                                )

                                if login != username:
                                    continue

                                enriched = dict(
                                    review
                                )

                                enriched[
                                    "pr_number"
                                ] = number

                                enriched[
                                    "pr_created_at"
                                ] = pr_created_at

                                all_reviews.append(
                                    enriched
                                )

                                if (
                                    len(all_reviews)
                                    >= DEFAULT_MAX_REVIEW_SUBMISSIONS
                                ):
                                    break

                            if len(data) < 100:
                                break

                            page += 1

                            if page > 5:
                                break

                    except Exception as exc:
                        errors.append(
                            "submitted reviews for "
                            f"PR #{number}: {exc}"
                        )

                    if (
                        len(all_reviews)
                        >= DEFAULT_MAX_REVIEW_SUBMISSIONS
                    ):
                        break

        # ==============================================================
        # Build activity
        # ==============================================================
        activity = _build_activity_from_reviews(
            username,
            all_comments,
            all_reviews,
        )

        # ==============================================================
        # Final availability
        # ==============================================================
        #
        # Usable evidence exists when either:
        #
        # - inline comments were successfully queried, OR
        # - submitted-review history was successfully queried.
        #
        # Therefore one failed source does not invalidate the other.
        #
        # If both fail, available=False and the result is never cached.
        # ==============================================================
        activity.available = (
            review_comments_available
            or submitted_reviews_available
        )

        if errors:
            activity.error = "; ".join(
                errors
            )

        return activity

    def get(
        self,
        username: str,
        *,
        force_refresh: bool = False,
    ) -> ReviewerActivity:
        """
        Get activity for a reviewer.

        Checks memory cache, disk cache, then GitHub.
        """
        clean = username.lstrip("@")

        # Memory cache.
        if (
            not force_refresh
            and clean in self._memory
        ):
            cached = self._memory[clean]

            if not cached.is_stale(
                self._ttl
            ):
                return cached

        # Disk cache.
        if not force_refresh:
            disk = self._load_from_disk(
                clean
            )

            if disk is not None:
                self._memory[clean] = disk
                return disk

        # GitHub.
        try:
            activity = self._fetch_from_github(
                clean
            )

        except Exception as exc:
            activity = ReviewerActivity(
                username=clean,
                fetched_at=time.time(),
                from_cache=False,
                available=False,
                error=str(exc),
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

        Adds a small delay between reviewers to be polite to GitHub.
        """
        result: dict[
            str,
            ReviewerActivity,
        ] = {}

        for i, username in enumerate(
            usernames
        ):
            result[username] = self.get(
                username
            )

            if i < len(usernames) - 1:
                time.sleep(
                    delay_seconds
                )

        return result


def format_activity_for_report(
    profile_dict: dict[str, Any],
    activity: ReviewerActivity,
) -> dict[str, Any]:
    """
    Merge static profile data with dynamic activity for the report.

    This is what gets added to each expert entry in the triage report.
    """
    from scripts.triager.reviewer_profiles import (
        get_profile,
    )

    username = (
        profile_dict.get("username")
        or profile_dict.get(
            "owner",
            "",
        ).lstrip("@")
    )

    static = get_profile(
        username
    )

    known = (
        list(static.known_concerns)
        if static
        else []
    )

    concern_labels = {
        "needs_test": (
            "typically requests a regression test"
        ),
        "needs_news": (
            "typically requests a NEWS entry"
        ),
        "needs_docs": (
            "typically requests documentation update"
        ),
        "needs_regen": (
            "typically requests regeneration of generated files"
        ),
        "needs_benchmark": (
            "typically requests a performance benchmark"
        ),
        "minimal_change": (
            "often asks to split large PRs"
        ),
        "api_compat": (
            "scrutinizes backward compatibility"
        ),
        "thread_safety": (
            "checks for thread safety / free-threading issues"
        ),
        "security": (
            "reviews security implications carefully"
        ),
    }

    dynamic_concerns = [
        concern_labels[concern]
        for concern in activity.top_concerns
        if concern in concern_labels
    ]

    return {
        "username": username,
        "subsystems": (
            static.subsystems
            if static
            else []
        ),
        "co_owners": (
            static.co_owners
            if static
            else []
        ),
        "focus_keywords": (
            static.focus_keywords
            if static
            else []
        ),
        "known_concerns": known,
        "dynamic_concerns": dynamic_concerns,
        "approval_rate": activity.approval_rate,
        "approval_rate_sample_size": (
            activity.approval_rate_sample_size
        ),
        "median_response_days": (
            activity.median_response_days
        ),
        "typical_response_days": (
            static.typical_response_days
            if static
            else None
        ),
        "sample_phrases": (
            activity.sample_phrases[:8]
        ),
        "active_subsystems": (
            activity.active_subsystems
        ),
        "activity_available": (
            activity.available
        ),
        "activity_error": (
            activity.error
        ),
        "data_source": (
            "cached"
            if activity.from_cache
            else "live"
        ),
    }