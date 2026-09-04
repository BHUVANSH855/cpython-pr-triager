"""
GitHub evidence collection for CPython PR triage.

This module owns network access, caching, retries, pagination, and
repository-content retrieval.

The rest of the application should consume the evidence returned here
rather than making GitHub API requests directly.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


DEFAULT_REPO = os.environ.get(
    "CPYTHON_REPO",
    "python/cpython",
)

DEFAULT_CACHE = Path(
    os.environ.get(
        "CPYTHON_TRIAGER_CACHE",
        ".triager-cache",
    )
)

DEFAULT_CACHE_TTL = int(
    os.environ.get(
        "CPYTHON_TRIAGER_CACHE_TTL",
        "900",
    )
)

API_VERSION = "2026-03-10"
USER_AGENT = "cpython-pr-triager"

DEFAULT_TIMEOUT = 45
DEFAULT_RETRIES = 4
DEFAULT_PER_PAGE = 100


class GitHubError(RuntimeError):
    """Raised when GitHub evidence cannot be collected."""


class GitHub:
    """
    Small standard-library-only GitHub API client.

    Responsibilities:

    - authentication
    - request construction
    - response decoding
    - caching
    - retries
    - pagination
    - rate-limit metadata
    - repository content retrieval
    - issue retrieval
    - base-SHA CODEOWNERS lookup
    - core pull-request evidence collection

    The client intentionally returns dictionaries/lists that mirror the
    GitHub REST API rather than imposing application-specific semantics.
    """

    def __init__(
        self,
        token: str | None = None,
        repo: str = DEFAULT_REPO,
        cache_dir: Path = DEFAULT_CACHE,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.token = (
            token
            if token is not None
            else os.environ.get("GITHUB_TOKEN", "")
        )

        self.repo = repo
        self.api = f"https://api.github.com/repos/{repo}"

        self.cache_dir = Path(cache_dir)
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.retries = retries

        self._opener = opener or urllib.request.urlopen

        self.calls = 0
        self.cache_hits = 0

        self.rate_remaining: str | None = None
        self.rate_reset: str | None = None

    # ------------------------------------------------------------------
    # Request / cache infrastructure
    # ------------------------------------------------------------------

    def _cache_path(self, url: str) -> Path:
        digest = hashlib.sha256(
            url.encode("utf-8")
        ).hexdigest()

        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, path: Path) -> Any | None:
        if (
            self.cache_ttl <= 0
            or not path.exists()
        ):
            return None

        try:
            age = time.time() - path.stat().st_mtime

            if age > self.cache_ttl:
                return None

            data = json.loads(
                path.read_text(
                    encoding="utf-8",
                )
            )

            self.cache_hits += 1
            return data

        except Exception:
            return None

    def _write_cache(
        self,
        path: Path,
        data: Any,
    ) -> None:
        """
        Write cache data atomically.

        A temporary file prevents an interrupted write from leaving a
        partially-written JSON cache entry.
        """

        try:
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            fd, temporary = tempfile.mkstemp(
                prefix=f"{path.name}.",
                suffix=".tmp",
                dir=str(path.parent),
            )

            temporary_path = Path(temporary)

            try:
                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    json.dump(
                        data,
                        handle,
                        ensure_ascii=False,
                    )

                temporary_path.replace(path)

            except Exception:
                try:
                    temporary_path.unlink(
                        missing_ok=True,
                    )
                except Exception:
                    pass

                raise

        except Exception:
            pass

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }

        if self.token:
            headers["Authorization"] = (
                f"Bearer {self.token}"
            )

        return headers

    def _url(
        self,
        path_or_url: str,
    ) -> str:
        if path_or_url.startswith("http://"):
            return path_or_url

        if path_or_url.startswith("https://"):
            return path_or_url

        if not path_or_url.startswith("/"):
            path_or_url = f"/{path_or_url}"

        return self.api + path_or_url

    def _update_rate_limit(
        self,
        headers: Any,
    ) -> None:
        self.rate_remaining = headers.get(
            "X-RateLimit-Remaining"
        )

        self.rate_reset = headers.get(
            "X-RateLimit-Reset"
        )

    @staticmethod
    def _retry_delay(
        attempt: int,
        headers: Any | None = None,
    ) -> float:
        if headers is not None:
            retry_after = headers.get(
                "Retry-After"
            )

            if retry_after:
                try:
                    return max(
                        0.0,
                        float(retry_after),
                    )
                except ValueError:
                    pass

        return min(
            2**attempt,
            16,
        )

    def request(
        self,
        path_or_url: str,
        *,
        use_cache: bool = True,
        retries: int | None = None,
    ) -> Any:
        """
        Perform one GitHub API request.

        Successful JSON responses are cached according to the configured
        cache policy.

        HTTP/rate-limit/network failures are retried when appropriate.
        """

        url = self._url(path_or_url)

        cache_path = self._cache_path(url)

        if use_cache:
            cached = self._read_cache(
                cache_path
            )

            if cached is not None:
                return cached

        retry_count = (
            self.retries
            if retries is None
            else retries
        )

        if retry_count < 1:
            retry_count = 1

        for attempt in range(retry_count):
            request = urllib.request.Request(
                url,
                headers=self._headers(),
                method="GET",
            )

            try:
                self.calls += 1

                with self._opener(
                    request,
                    timeout=self.timeout,
                ) as response:
                    self._update_rate_limit(
                        response.headers
                    )

                    raw = response.read()

                try:
                    data = json.loads(
                        raw.decode("utf-8")
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as exc:
                    raise GitHubError(
                        f"GitHub returned invalid JSON: {url}"
                    ) from exc

                if use_cache:
                    self._write_cache(
                        cache_path,
                        data,
                    )

                return data

            except urllib.error.HTTPError as exc:
                self._update_rate_limit(
                    exc.headers
                )

                retryable = exc.code in {
                    408,
                    429,
                    500,
                    502,
                    503,
                    504,
                }

                if (
                    retryable
                    and attempt < retry_count - 1
                ):
                    time.sleep(
                        self._retry_delay(
                            attempt,
                            exc.headers,
                        )
                    )
                    continue

                message = (
                    f"GitHub HTTP {exc.code}: {url}"
                )

                if exc.code == 401:
                    message += (
                        " (authentication failed)"
                    )
                elif exc.code == 403:
                    message += (
                        " (forbidden or rate-limited)"
                    )
                elif exc.code == 404:
                    message += (
                        " (not found)"
                    )

                raise GitHubError(
                    message
                ) from exc

            except (
                urllib.error.URLError,
                TimeoutError,
            ) as exc:
                if attempt < retry_count - 1:
                    time.sleep(
                        min(
                            2**attempt,
                            8,
                        )
                    )
                    continue

                raise GitHubError(
                    "GitHub request failed: "
                    f"{url}: {exc}"
                ) from exc

        raise GitHubError(
            f"GitHub request failed: {url}"
        )

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def paginate(
        self,
        path: str,
        *,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> list[dict[str, Any]]:
        """
        Fetch every page of a GitHub list endpoint.

        Pagination stops only when GitHub returns fewer items than the
        requested page size or a non-list response is encountered.
        """

        if per_page < 1:
            raise ValueError(
                "per_page must be at least 1"
            )

        page = 1
        result: list[dict[str, Any]] = []

        while True:
            separator = (
                "&"
                if "?" in path
                else "?"
            )

            page_path = (
                f"{path}"
                f"{separator}"
                f"per_page={per_page}"
                f"&page={page}"
            )

            data = self.request(
                page_path
            )

            if not isinstance(data, list):
                return result

            result.extend(
                item
                for item in data
                if isinstance(item, dict)
            )

            if len(data) < per_page:
                return result

            page += 1

    # ------------------------------------------------------------------
    # Basic PR evidence
    # ------------------------------------------------------------------

    def pr(
        self,
        number: int,
    ) -> dict[str, Any]:
        data = self.request(
            f"/pulls/{number}"
        )

        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected PR response for #{number}"
            )

        return data

    def files(
        self,
        number: int,
    ) -> list[dict[str, Any]]:
        return self.paginate(
            f"/pulls/{number}/files"
        )

    def reviews(
        self,
        number: int,
    ) -> list[dict[str, Any]]:
        return self.paginate(
            f"/pulls/{number}/reviews"
        )

    def review_comments(
        self,
        number: int,
    ) -> list[dict[str, Any]]:
        return self.paginate(
            f"/pulls/{number}/comments"
        )

    def issue_comments(
        self,
        number: int,
    ) -> list[dict[str, Any]]:
        return self.paginate(
            f"/issues/{number}/comments"
        )

    def timeline(
        self,
        number: int,
    ) -> list[dict[str, Any]]:
        return self.paginate(
            f"/issues/{number}/timeline"
        )

    # ------------------------------------------------------------------
    # Issues
    # ------------------------------------------------------------------

    def issue(
        self,
        number: int,
    ) -> dict[str, Any]:
        """
        Fetch one issue or pull-request issue resource.

        GitHub exposes pull requests through the issues API as well, so
        this method intentionally preserves the raw response.
        """

        data = self.request(
            f"/issues/{number}"
        )

        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected issue response for #{number}"
            )

        return data

    def linked_issue_evidence(
        self,
        number: int,
        *,
        bot_logins: set[str] | frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """Collect normalized evidence for one linked issue."""

        issue = self.issue(number)
        comments = self.issue_comments(number)
        timeline = self.timeline(number)

        bots = set(bot_logins or ())
        normalized_comments = []

        for comment in comments:
            user = comment.get("user") or {}
            login = user.get("login", "?")

            if login in bots:
                continue

            normalized_comments.append(
                {
                    "login": login,
                    "date": comment.get("created_at", ""),
                    "body": comment.get("body") or "",
                }
            )

        label_history = []

        for event in timeline:
            if event.get("event") != "labeled":
                continue

            label = event.get("label") or {}
            actor = event.get("actor") or {}

            label_history.append(
                {
                    "label": label.get("name", "?"),
                    "actor": actor.get("login", "?"),
                    "date": event.get("created_at", ""),
                }
            )

        cross_references = []

        for event in timeline:
            if event.get("event") != "cross-referenced":
                continue

            source = event.get("source") or {}
            referenced_issue = source.get("issue") or {}
            referenced_number = referenced_issue.get("number")

            if not isinstance(referenced_number, int):
                continue

            cross_references.append(
                {
                    "number": referenced_number,
                    "title": referenced_issue.get("title", ""),
                }
            )

        return {
            "number": number,
            "title": issue.get("title", ""),
            "state": issue.get("state", ""),
            "state_reason": issue.get("state_reason"),
            "labels": [
                label.get("name")
                for label in issue.get("labels", [])
                if isinstance(label, dict)
            ],
            "created_at": issue.get("created_at"),
            "closed_at": issue.get("closed_at"),
            "body": issue.get("body") or "",
            "comments": normalized_comments,
            "label_history": label_history,
            "cross_references": cross_references,
        }

    def linked_issue_evidence_batch(
        self,
        numbers: list[int] | tuple[int, ...] | set[int],
        *,
        bot_logins: set[str] | frozenset[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Collect normalized evidence for multiple linked issues."""

        seen: set[int] = set()
        result: list[dict[str, Any]] = []

        for number in numbers:
            if not isinstance(number, int):
                continue

            if number <= 0 or number in seen:
                continue

            seen.add(number)

            try:
                result.append(
                    self.linked_issue_evidence(
                        number,
                        bot_logins=bot_logins,
                    )
                )
            except Exception as exc:
                result.append(
                    {
                        "number": number,
                        "error": str(exc),
                    }
                )

        return result

    def linked_issues(
        self,
        numbers: list[int] | tuple[int, ...] | set[int],
    ) -> list[dict[str, Any]]:
        """
        Fetch a collection of explicitly identified linked issues.

        Issue numbers are deduplicated while preserving their first-seen
        order. A failure for one issue is raised rather than silently
        dropping that evidence; callers that need partial collection
        should isolate failures at the orchestration layer.
        """

        seen: set[int] = set()
        result: list[dict[str, Any]] = []

        for number in numbers:
            if not isinstance(
                number,
                int,
            ):
                continue

            if number <= 0:
                continue

            if number in seen:
                continue

            seen.add(number)

            result.append(
                self.issue(number)
            )

        return result

    # ------------------------------------------------------------------
    # CI
    # ------------------------------------------------------------------

    def check_runs(
        self,
        sha: str,
        *,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> dict[str, Any]:
        """
        Fetch all check runs for a commit.

        Unlike the normal list endpoints used by ``paginate()``, the
        GitHub check-runs endpoint returns an envelope:

            {
                "total_count": ...,
                "check_runs": [...]
            }

        Therefore it needs dedicated pagination logic.
        """

        if per_page < 1:
            raise ValueError(
                "per_page must be at least 1"
            )

        encoded_sha = urllib.parse.quote(
            sha,
            safe="",
        )

        page = 1
        runs: list[dict[str, Any]] = []
        total_count: int | None = None

        while True:
            path = (
                f"/commits/{encoded_sha}/check-runs"
                f"?per_page={per_page}"
                f"&page={page}"
            )

            data = self.request(path)

            if not isinstance(data, dict):
                raise GitHubError(
                    "Unexpected check-runs response "
                    f"for commit {sha}"
                )

            page_runs = data.get(
                "check_runs",
                [],
            )

            if not isinstance(
                page_runs,
                list,
            ):
                raise GitHubError(
                    "Invalid check_runs payload "
                    f"for commit {sha}"
                )

            runs.extend(
                item
                for item in page_runs
                if isinstance(item, dict)
            )

            if total_count is None:
                raw_total = data.get(
                    "total_count"
                )

                if isinstance(
                    raw_total,
                    int,
                ):
                    total_count = raw_total

            if len(page_runs) < per_page:
                break

            page += 1

        return {
            "total_count": (
                total_count
                if total_count is not None
                else len(runs)
            ),
            "check_runs": runs,
        }

    def statuses(
        self,
        sha: str,
    ) -> list[dict[str, Any]]:
        encoded_sha = urllib.parse.quote(
            sha,
            safe="",
        )

        return self.paginate(
            f"/commits/{encoded_sha}/statuses"
        )

    # ------------------------------------------------------------------
    # Repository content
    # ------------------------------------------------------------------

    def content(
        self,
        path: str,
        ref: str | None = None,
    ) -> dict[str, Any]:
        encoded_path = "/".join(
            urllib.parse.quote(
                component,
                safe="",
            )
            for component in path.split("/")
        )

        suffix = ""

        if ref is not None:
            suffix = (
                "?ref="
                + urllib.parse.quote(
                    ref,
                    safe="",
                )
            )

        data = self.request(
            f"/contents/{encoded_path}{suffix}"
        )

        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected content response for {path}"
            )

        return data

    def raw_content(
        self,
        path: str,
        ref: str | None = None,
    ) -> str | None:
        data = self.content(
            path,
            ref,
        )

        if (
            data.get("encoding") == "base64"
            and data.get("content")
        ):
            try:
                return base64.b64decode(
                    data["content"]
                ).decode(
                    "utf-8",
                    errors="replace",
                )
            except (
                ValueError,
                TypeError,
            ):
                return None

        download_url = data.get(
            "download_url"
        )

        if download_url:
            try:
                raw = self.request(
                    download_url,
                    use_cache=False,
                )

                if isinstance(raw, str):
                    return raw

            except GitHubError:
                pass

        return None

    def codeowners(
        self,
        ref: str | None = None,
    ) -> tuple[str | None, str | None]:
        """
        Find CODEOWNERS at the supplied repository ref.

        The ref should normally be the PR base SHA so ownership is
        resolved against the repository state that the PR targets.
        """

        candidates = (
            ".github/CODEOWNERS",
            "CODEOWNERS",
            "docs/CODEOWNERS",
        )

        for path in candidates:
            try:
                text = self.raw_content(
                    path,
                    ref,
                )

                if text is not None:
                    return path, text

            except GitHubError:
                continue

        return None, None

    # ------------------------------------------------------------------
    # Combined evidence
    # ------------------------------------------------------------------

    def pull_request_evidence(
        self,
        number: int,
        *,
        linked_issue_numbers: (
            list[int]
            | tuple[int, ...]
            | set[int]
            | None
        ) = None,
    ) -> dict[str, Any]:
        """
        Collect the core evidence package for one PR.

        The PR itself is required. Secondary evidence collectors are
        isolated so that one unavailable endpoint does not erase all
        other evidence.

        Failures are returned explicitly in ``errors``.

        ``linked_issue_numbers`` is intentionally supplied by the caller.
        Reference discovery belongs outside this network client.
        """

        pr = self.pr(number)

        evidence: dict[str, Any] = {
            "pr": pr,
        }

        errors: dict[str, str] = {}

        collectors = {
            "files": self.files,
            "reviews": self.reviews,
            "review_comments": self.review_comments,
            "issue_comments": self.issue_comments,
            "timeline": self.timeline,
        }

        for name, collector in collectors.items():
            try:
                evidence[name] = collector(
                    number
                )
            except Exception as exc:
                evidence[name] = []
                errors[name] = str(exc)

        if linked_issue_numbers:
            try:
                evidence["linked_issues"] = (
                    self.linked_issues(
                        linked_issue_numbers
                    )
                )
            except Exception as exc:
                evidence["linked_issues"] = []
                errors["linked_issues"] = str(exc)
        else:
            evidence["linked_issues"] = []

        base_sha = (
            pr.get("base") or {}
        ).get("sha")

        try:
            (
                evidence["codeowners_path"],
                evidence["codeowners_text"],
            ) = self.codeowners(
                base_sha
            )

        except Exception as exc:
            evidence["codeowners_path"] = None
            evidence["codeowners_text"] = None
            errors["codeowners"] = str(exc)

        head_sha = (
            pr.get("head") or {}
        ).get("sha")

        if head_sha:
            try:
                evidence["check_runs"] = (
                    self.check_runs(head_sha)
                )
            except Exception as exc:
                evidence["check_runs"] = {
                    "total_count": 0,
                    "check_runs": [],
                }
                errors["check_runs"] = str(exc)

            try:
                evidence["statuses"] = (
                    self.statuses(head_sha)
                )
            except Exception as exc:
                evidence["statuses"] = []
                errors["statuses"] = str(exc)

            evidence["head_sha"] = head_sha

        else:
            evidence["check_runs"] = {
                "total_count": 0,
                "check_runs": [],
            }
            evidence["statuses"] = []

        return {
            "evidence": evidence,
            "errors": errors,
            "stats": self.stats(),
        }

    # ------------------------------------------------------------------
    # Collector statistics
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """
        Return request/cache/rate-limit metadata.

        These values describe this client instance and are useful for
        reproducibility and evidence-completeness reporting.
        """

        return {
            "api_calls": self.calls,
            "cache_hits": self.cache_hits,
            "rate_limit_remaining": (
                self.rate_remaining
            ),
            "rate_limit_reset": (
                self.rate_reset
            ),
        }
