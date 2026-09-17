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
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_REPO = os.environ.get("CPYTHON_REPO", "python/cpython")

DEFAULT_CACHE = Path(
    os.environ.get("CPYTHON_TRIAGER_CACHE", ".triager-cache")
)

DEFAULT_CACHE_TTL = int(
    os.environ.get("CPYTHON_TRIAGER_CACHE_TTL", "900")
)

API_VERSION = "2022-11-28"
USER_AGENT = "cpython-pr-triager"

DEFAULT_TIMEOUT = 45
DEFAULT_RETRIES = 4
DEFAULT_PER_PAGE = 100

# Safety limits for evidence collection. These prevent a malformed,
# unexpectedly large, or changing GitHub response from causing an
# unbounded API walk or memory growth.
DEFAULT_MAX_PAGES = 100
MAX_RAW_CONTENT_BYTES = 10 * 1024 * 1024
MAX_PAGINATED_ITEMS = DEFAULT_MAX_PAGES * DEFAULT_PER_PAGE
DEFAULT_HISTORY_MAX_FILES = 20
DEFAULT_HISTORY_MAX_COMMITS = 5
MAX_SOURCE_FILES = 500
MAX_LINKED_ISSUES = 100

# Hosts this client will treat as legitimate sources of "repository
# content." download_url normally comes straight from GitHub's own API
# response, so in ordinary operation this always matches; the allowlist
# is defense-in-depth against a compromised/unexpected response causing
# this client to fetch and trust content from an arbitrary external host
# under the guise of "repository content."
ALLOWED_RAW_CONTENT_HOSTS = frozenset({
    "raw.githubusercontent.com",
    "github.com",
    "api.github.com",
    "codeload.github.com",
})


def _is_allowed_raw_host(url: str) -> bool:
    """Return whether ``url`` points at an allowed GitHub content host."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return False
    return host.lower() in ALLOWED_RAW_CONTENT_HOSTS


def _is_allowed_github_url(url: str) -> bool:
    """Return whether an absolute URL is an approved GitHub endpoint."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False

    if parsed.scheme != "https":
        return False

    host = (parsed.hostname or "").lower()
    return host in ALLOWED_RAW_CONTENT_HOSTS


def _safe_int(value: Any, default: int | None = None) -> int | None:
    """Coerce an integer-like value without raising on API metadata."""
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_DEFAULT_BOT_LOGINS: frozenset[str] = frozenset({
    "miss-islington",
    "bedevere-bot",
    "github-actions[bot]",
    "dependabot[bot]",
    "codecov[bot]",
    "python-security-bot",
    "python-triage-bot",
    "CLAassistant",
    "python-cla-bot",
})

def _is_bot_login(
    login: str,
    bot_logins: set[str] | frozenset[str] | None = None,
) -> bool:
    """
    Return whether a GitHub login should be treated as an automated actor.

    GitHub bot accounts commonly use the ``[bot]`` suffix, but the triager
    also keeps an explicit allowlist for known CPython automation accounts.
    """
    normalized = login.strip().lower()

    if not normalized:
        return False

    known = {
        value.strip().lower()
        for value in (
            bot_logins
            if bot_logins is not None
            else _DEFAULT_BOT_LOGINS
        )
    }

    return (
        normalized in known
        or normalized.endswith("[bot]")
        or normalized.endswith("-bot")
    )

class GitHubError(RuntimeError):
    """Raised when GitHub evidence cannot be collected."""


class GitHub:
    """
    Small standard-library-only GitHub API client.
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
        self._last_pagination: dict[str, Any] = {
            "items": [],
            "complete": True,
            "pages_fetched": 0,
        }

    def _cache_path(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, path: Path) -> Any | None:
        if self.cache_ttl <= 0 or not path.exists():
            return None

        try:
            age = time.time() - path.stat().st_mtime
            if age > self.cache_ttl:
                return None

            data = json.loads(path.read_text(encoding="utf-8"))
            self.cache_hits += 1
            return data
        except Exception:
            return None

    def _write_cache(self, path: Path, data: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
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
                    json.dump(data, handle, ensure_ascii=False)

                temporary_path.replace(path)
            except Exception:
                try:
                    temporary_path.unlink(missing_ok=True)
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
            headers["Authorization"] = f"Bearer {self.token}"

        return headers

    def _url(self, path_or_url: str) -> str:
        """Resolve a relative API path or validate an absolute GitHub URL."""
        if not isinstance(path_or_url, str) or not path_or_url:
            raise GitHubError("GitHub URL/path must be a non-empty string")

        if path_or_url.startswith(("http://", "https://")):
            if not _is_allowed_github_url(path_or_url):
                raise GitHubError(
                    "Refusing to request an unexpected GitHub host: "
                    f"{path_or_url}"
                )
            return path_or_url

        if not path_or_url.startswith("/"):
            path_or_url = f"/{path_or_url}"

        return self.api + path_or_url

    def _update_rate_limit(self, headers: Any) -> None:
        self.rate_remaining = headers.get("X-RateLimit-Remaining")
        self.rate_reset = headers.get("X-RateLimit-Reset")

    @staticmethod
    def _retry_delay(
        attempt: int,
        headers: Any | None = None,
    ) -> float:
        if headers is not None:
            retry_after = headers.get("Retry-After")
            if retry_after:
                try:
                    return max(0.0, float(retry_after))
                except (TypeError, ValueError):
                    pass

        return min(2 ** attempt, 16)

    @staticmethod
    def _http_error_message(
        exc: urllib.error.HTTPError,
        url: str,
    ) -> str:
        message = f"GitHub HTTP {exc.code}: {url}"

        if exc.code == 401:
            message += " (authentication failed)"
        elif exc.code == 403:
            message += " (forbidden or rate-limited)"
        elif exc.code == 404:
            message += " (not found)"

        reason = str(getattr(exc, "reason", "") or "").strip()
        if reason:
            message += f": {reason}"

        return message

    @staticmethod
    def _is_rate_limited(
        exc: urllib.error.HTTPError,
    ) -> bool:
        headers = exc.headers or {}
        remaining = headers.get("X-RateLimit-Remaining")
        retry_after = headers.get("Retry-After")

        return (
            exc.code in {429, 503}
            or bool(retry_after)
            or str(remaining).strip() == "0"
        )

    def _request_bytes(
        self,
        path_or_url: str,
        *,
        use_cache: bool = False,
        retries: int | None = None,
    ) -> bytes:
        """
        Perform one GitHub request and return the raw response bytes.

        This is intentionally separate from ``request()`` because GitHub
        endpoints can return non-JSON content, including repository source
        files. Raw responses must never be forced through ``json.loads()``.
        """
        url = self._url(path_or_url)

        retry_count = self.retries if retries is None else retries
        retry_count = max(int(retry_count), 1)

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
                    self._update_rate_limit(response.headers)
                    raw = response.read()

                if len(raw) > MAX_RAW_CONTENT_BYTES:
                    raise GitHubError(
                        "GitHub response exceeded the raw-content safety "
                        f"limit of {MAX_RAW_CONTENT_BYTES} bytes: {url}"
                    )

                return raw

            except urllib.error.HTTPError as exc:
                self._update_rate_limit(exc.headers)

                retryable = (
                    exc.code
                    in {
                        408,
                        429,
                        500,
                        502,
                        503,
                        504,
                    }
                    or (
                        exc.code == 403
                        and self._is_rate_limited(exc)
                    )
                )

                if retryable and attempt < retry_count - 1:
                    time.sleep(
                        self._retry_delay(
                            attempt,
                            exc.headers,
                        )
                    )
                    continue

                raise GitHubError(
                    self._http_error_message(exc, url)
                ) from exc

            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < retry_count - 1:
                    time.sleep(min(2 ** attempt, 8))
                    continue

                raise GitHubError(
                    f"GitHub request failed: {url}: {exc}"
                ) from exc

        raise GitHubError(
            f"GitHub request failed after retries: {url}"
        )

    def request_text(
        self,
        path_or_url: str,
        *,
        use_cache: bool = False,
        retries: int | None = None,
    ) -> str:
        """
        Fetch a non-JSON GitHub response as UTF-8 text.

        Raw source retrieval deliberately does not use the JSON cache because
        the cache format used by ``request()`` is JSON-specific.
        """
        raw = self._request_bytes(
            path_or_url,
            use_cache=use_cache,
            retries=retries,
        )

        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitHubError(
                f"GitHub returned non-UTF-8 text: {self._url(path_or_url)}"
            ) from exc

    def request(
        self,
        path_or_url: str,
        *,
        use_cache: bool = True,
        retries: int | None = None,
    ) -> Any:
        """Perform one GitHub API request with caching and retries."""
        url = self._url(path_or_url)
        cache_path = self._cache_path(url)

        if use_cache:
            cached = self._read_cache(cache_path)
            if cached is not None:
                return cached

        retry_count = self.retries if retries is None else retries
        retry_count = max(retry_count, 1)

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
                    self._update_rate_limit(response.headers)
                    raw = response.read()

                try:
                    data = json.loads(raw.decode("utf-8"))
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as exc:
                    raise GitHubError(
                        f"GitHub returned invalid JSON: {url}"
                    ) from exc

                if use_cache:
                    self._write_cache(cache_path, data)

                return data

            except urllib.error.HTTPError as exc:
                self._update_rate_limit(exc.headers)

                retryable = (
                    exc.code in {
                        408,
                        429,
                        500,
                        502,
                        503,
                        504,
                    }
                    or (
                        exc.code == 403
                        and self._is_rate_limited(exc)
                    )
                )

                if retryable and attempt < retry_count - 1:
                    time.sleep(
                        self._retry_delay(
                            attempt,
                            exc.headers,
                        )
                    )
                    continue

                raise GitHubError(
                    self._http_error_message(exc, url)
                ) from exc

            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < retry_count - 1:
                    time.sleep(min(2 ** attempt, 8))
                    continue

                raise GitHubError(
                    f"GitHub request failed: {url}: {exc}"
                ) from exc

        raise GitHubError(
            f"GitHub request failed after retries: {url}"
        )

    def paginate(
        self,
        path: str,
        *,
        per_page: int = DEFAULT_PER_PAGE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> list[dict[str, Any]]:
        """Fetch every page of a GitHub list endpoint within hard bounds.

        The method deliberately fails if the endpoint still returns a full
        page at ``max_pages``. Returning the collected prefix as if it were
        complete would create dangerous false evidence. Callers that want to
        preserve a partial prefix should use ``_paginate_partial``.
        """
        result, complete = self._paginate_partial(
            path, per_page=per_page, max_pages=max_pages
        )
        if not complete:
            raise GitHubError(
                f"GitHub pagination exceeded the safety limit of "
                f"{max_pages} pages: {path}"
            )
        return result

    def _paginate_partial(
        self,
        path: str,
        *,
        per_page: int = DEFAULT_PER_PAGE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return ``(items, complete)`` for a bounded list walk.

        This internal form is used by evidence collection so a safety-limit
        hit can be represented as PARTIAL rather than silently discarded.
        """
        if per_page < 1:
            raise ValueError("per_page must be at least 1")
        if per_page > DEFAULT_PER_PAGE:
            raise ValueError(
                f"per_page cannot exceed {DEFAULT_PER_PAGE}"
            )
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")

        page = 1
        result: list[dict[str, Any]] = []

        while page <= max_pages:
            separator = "&" if "?" in path else "?"
            page_path = (
                f"{path}{separator}"
                f"per_page={per_page}&page={page}"
            )
            data = self.request(page_path)
            if not isinstance(data, list):
                raise GitHubError(
                    f"Unexpected list response from GitHub: {page_path}"
                )

            for item in data:
                if isinstance(item, dict):
                    result.append(item)
                if len(result) > MAX_PAGINATED_ITEMS:
                    self._last_pagination = {
                        "items": result[:MAX_PAGINATED_ITEMS],
                        "complete": False,
                        "pages_fetched": page,
                    }
                    return result[:MAX_PAGINATED_ITEMS], False

            if len(data) < per_page:
                self._last_pagination = {
                    "items": list(result),
                    "complete": True,
                    "pages_fetched": page,
                }
                return result, True
            page += 1

        self._last_pagination = {
            "items": list(result),
            "complete": False,
            "pages_fetched": max_pages,
        }
        return result, False

    def pr(self, number: int) -> dict[str, Any]:
        data = self.request(f"/pulls/{number}")

        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected PR response for #{number}"
            )

        return data

    def head_commit_evidence(
        self,
        sha: str | None,
    ) -> dict[str, Any]:
        """Collect identity evidence for a PR head commit.

        This deliberately does not call the commit author/committer a
        "pusher". Git author, Git committer, and the GitHub actor that pushed
        a ref are distinct concepts. Downstream policy code must not infer
        push identity from commit metadata alone.
        """
        if not isinstance(sha, str) or not sha.strip():
            return {
                "status": "unavailable",
                "sha": sha,
                "author": None,
                "committer": None,
                "error": "PR head SHA is unavailable.",
            }

        encoded_sha = urllib.parse.quote(sha, safe="")

        try:
            data = self.request(
                f"/commits/{encoded_sha}",
            )
        except GitHubError as exc:
            return {
                "status": "failed",
                "sha": sha,
                "author": None,
                "committer": None,
                "error": str(exc),
            }

        if not isinstance(data, dict):
            return {
                "status": "failed",
                "sha": sha,
                "author": None,
                "committer": None,
                "error": "GitHub returned an invalid commit response.",
            }

        commit = data.get("commit")
        author = data.get("author")
        committer = data.get("committer")

        commit_author = (
            author.get("login")
            if isinstance(author, dict)
            else None
        )

        commit_committer = (
            committer.get("login")
            if isinstance(committer, dict)
            else None
        )

        raw_author = (
            commit.get("author")
            if isinstance(commit, dict)
            else None
        )

        raw_committer = (
            commit.get("committer")
            if isinstance(commit, dict)
            else None
        )

        return {
            "status": "complete",
            "sha": data.get("sha") or sha,
            "author": {
                "login": commit_author,
                "name": (
                    raw_author.get("name")
                    if isinstance(raw_author, dict)
                    else None
                ),
                "email": (
                    raw_author.get("email")
                    if isinstance(raw_author, dict)
                    else None
                ),
                "date": (
                    raw_author.get("date")
                    if isinstance(raw_author, dict)
                    else None
                ),
            },
            "committer": {
                "login": commit_committer,
                "name": (
                    raw_committer.get("name")
                    if isinstance(raw_committer, dict)
                    else None
                ),
                "email": (
                    raw_committer.get("email")
                    if isinstance(raw_committer, dict)
                    else None
                ),
                "date": (
                    raw_committer.get("date")
                    if isinstance(raw_committer, dict)
                    else None
                ),
            },
            "html_url": data.get("html_url"),
        }

    def files(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/pulls/{number}/files")

    def reviews(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/pulls/{number}/reviews")

    def review_comments(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/pulls/{number}/comments")

    def issue_comments(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/issues/{number}/comments")

    def timeline(
        self,
        number: int,
        *,
        bot_logins: frozenset[str] = _DEFAULT_BOT_LOGINS,
    ) -> list[dict[str, Any]]:
        """Fetch and normalize the issue timeline."""
        raw_events = self.paginate(
            f"/issues/{number}/timeline"
        )

        normalized: list[dict[str, Any]] = []

        for event in raw_events:
            actor = (
                event.get("actor")
                or event.get("user")
                or event.get("sender")
                or {}
            )

            login = (
                actor.get("login", "")
                if isinstance(actor, dict)
                else ""
            )

            is_bot = _is_bot_login(
                login,
                bot_logins,
            )

            ev = dict(event)
            ev["bot"] = is_bot

            # GitHub's issue timeline calls review submissions ``reviewed``
            # while the review API calls them reviews.  Normalize both to the
            # canonical kind consumed by policy/review-state code.  Preserve
            # the original event name for provenance/debugging.
            event_name = str(event.get("event") or "unknown")
            ev["event_type"] = event_name
            if event_name == "reviewed":
                ev["kind"] = "review"
            else:
                ev.setdefault("kind", event_name)

            ev.setdefault("login", login)
            ev.setdefault(
                "date",
                event.get("created_at")
                or event.get("submitted_at")
                or "",
            )
            ev.setdefault("body", event.get("body") or "")

            if event_name == "reviewed" or event.get("state"):
                ev["state"] = event.get("state", ev.get("state", ""))
                ev["review_state"] = ev.get("state", "")
                ev["review_id"] = event.get("id")
                ev["submitted_at"] = (
                    event.get("submitted_at")
                    or event.get("created_at")
                    or ""
                )

            normalized.append(ev)

        return normalized

    def labels(self) -> list[dict[str, Any]]:
        """Fetch all repository labels."""
        return self.paginate("/labels")

    def issue(self, number: int) -> dict[str, Any]:
        data = self.request(f"/issues/{number}")

        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected issue response for #{number}"
            )

        return data

    def linked_issue_evidence(
        self,
        number: int,
        *,
        bot_logins: set[str]
        | frozenset[str]
        | None = None,
    ) -> dict[str, Any]:
        """Collect normalized evidence for one linked issue."""
        issue = self.issue(number)
        comments = self.issue_comments(number)
        raw_tl = self.paginate(
            f"/issues/{number}/timeline"
        )

        bots = set(
            bot_logins or _DEFAULT_BOT_LOGINS
        )

        normalized_comments = []

        for comment in comments:
            user = comment.get("user") or {}
            login = user.get("login", "?")

            if _is_bot_login(login, bots):
                continue

            normalized_comments.append(
                {
                    "login": login,
                    "date": comment.get("created_at", ""),
                    "body": comment.get("body") or "",
                }
            )

        label_history = []
        cross_references = []

        for event in raw_tl:
            if event.get("event") == "labeled":
                label = event.get("label") or {}
                actor = event.get("actor") or {}

                label_history.append(
                    {
                        "label": label.get("name", "?"),
                        "actor": actor.get("login", "?"),
                        "date": event.get("created_at", ""),
                    }
                )

            if event.get("event") == "cross-referenced":
                source = event.get("source") or {}
                referenced_issue = source.get("issue") or {}
                referenced_number = referenced_issue.get(
                    "number"
                )

                if isinstance(referenced_number, int):
                    cross_references.append(
                        {
                            "number": referenced_number,
                            "title": referenced_issue.get(
                                "title",
                                "",
                            ),
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
        numbers: list[int]
        | tuple[int, ...]
        | set[int],
        *,
        bot_logins: set[str]
        | frozenset[str]
        | None = None,
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
        numbers: list[int]
        | tuple[int, ...]
        | set[int],
    ) -> list[dict[str, Any]]:
        """Fetch a collection of explicitly identified linked issues."""
        seen: set[int] = set()
        result: list[dict[str, Any]] = []

        for number in numbers:
            if (
                not isinstance(number, int)
                or number <= 0
                or number in seen
            ):
                continue

            seen.add(number)
            result.append(self.issue(number))

        return result
    def check_runs(
        self,
        sha: str,
        *,
        per_page: int = DEFAULT_PER_PAGE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> dict[str, Any]:
        """Fetch all check runs for a commit within a bounded page limit."""
        if per_page < 1:
            raise ValueError("per_page must be at least 1")

        if per_page > DEFAULT_PER_PAGE:
            raise ValueError(
                f"per_page cannot exceed {DEFAULT_PER_PAGE}"
            )

        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")

        encoded_sha = urllib.parse.quote(
            sha,
            safe="",
        )

        page = 1
        runs: list[dict[str, Any]] = []
        total_count: int | None = None
        complete = False

        while page <= max_pages:
            path = (
                f"/commits/{encoded_sha}/check-runs"
                f"?per_page={per_page}&page={page}"
            )
            data = self.request(path)
            if not isinstance(data, dict):
                raise GitHubError(
                    f"Unexpected check-runs response for commit {sha}"
                )

            page_runs = data.get("check_runs", [])
            if not isinstance(page_runs, list):
                raise GitHubError(
                    f"Invalid check_runs payload for commit {sha}"
                )

            for item in page_runs:
                if isinstance(item, dict):
                    runs.append(item)
                    if len(runs) > MAX_PAGINATED_ITEMS:
                        raise GitHubError(
                            f"GitHub check-run response exceeded the safety "
                            f"limit of {MAX_PAGINATED_ITEMS} items for {sha}"
                        )

            if total_count is None:
                raw_total = data.get("total_count")
                total_count = _safe_int(raw_total)

            if len(page_runs) < per_page:
                complete = True
                break
            page += 1

        if not complete:
            raise GitHubError(
                f"GitHub check-run pagination exceeded the safety "
                f"limit of {max_pages} pages for commit {sha}"
            )

        effective_total = total_count if total_count is not None else len(runs)
        if effective_total < len(runs):
            # The server's count must never make a larger collected set look
            # impossible; preserve the actual observed count as provenance.
            effective_total = len(runs)

        return {
            "total_count": effective_total,
            "check_runs": runs,
            "pagination_complete": complete,
            "pages_fetched": page,
        }

    def statuses(self, sha: str) -> list[dict[str, Any]]:
        encoded_sha = urllib.parse.quote(
            sha,
            safe="",
        )

        return self.paginate(
            f"/commits/{encoded_sha}/statuses"
        )

    def branch_protection(self, branch: str) -> dict[str, Any]:
        """Fetch authoritative classic branch-protection configuration."""
        if not isinstance(branch, str) or not branch.strip():
            raise ValueError("branch must be a non-empty string")

        encoded_branch = urllib.parse.quote(branch, safe="")
        data = self.request(f"/branches/{encoded_branch}/protection")
        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected branch-protection response for {branch!r}"
            )
        return data

    def branch_rules(self, branch: str) -> list[dict[str, Any]]:
        """Fetch effective repository rules reported for a branch."""
        if not isinstance(branch, str) or not branch.strip():
            raise ValueError("branch must be a non-empty string")

        encoded_branch = urllib.parse.quote(branch, safe="")
        data = self.request(f"/rules/branches/{encoded_branch}")
        if not isinstance(data, list):
            raise GitHubError(
                f"Unexpected branch-rules response for {branch!r}"
            )
        return [item for item in data if isinstance(item, dict)]

    @staticmethod
    def _required_checks_from_branch_protection(
        protection: dict[str, Any],
    ) -> list[dict[str, Any]]:
        required = protection.get("required_status_checks")
        if not isinstance(required, dict):
            return []

        result: list[dict[str, Any]] = []

        for context in required.get("contexts", []):
            if isinstance(context, str) and context.strip():
                result.append(
                    {
                        "name": context,
                        "source": "branch_protection",
                        "source_type": "protected_branch",
                        "integration_id": None,
                    }
                )

        for item in required.get("checks", []):
            if not isinstance(item, dict):
                continue
            context = item.get("context")
            if not isinstance(context, str) or not context.strip():
                continue
            result.append(
                {
                    "name": context,
                    "source": "branch_protection",
                    "source_type": "protected_branch",
                    "integration_id": item.get("app_id"),
                }
            )

        return result

    @staticmethod
    def _required_checks_from_branch_rules(
        rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []

        for rule in rules:
            if str(rule.get("type") or "").strip() != "required_status_checks":
                continue

            parameters = rule.get("parameters")
            if not isinstance(parameters, dict):
                continue

            checks = parameters.get("required_status_checks")
            if not isinstance(checks, list):
                continue

            source = rule.get("ruleset_source")
            source_type = rule.get("ruleset_source_type")
            ruleset_id = rule.get("ruleset_id")

            for item in checks:
                if not isinstance(item, dict):
                    continue
                context = item.get("context")
                if not isinstance(context, str) or not context.strip():
                    continue
                result.append(
                    {
                        "name": context,
                        "source": source or "ruleset",
                        "source_type": source_type or "ruleset",
                        "ruleset_id": ruleset_id,
                        "integration_id": item.get("integration_id"),
                    }
                )

        return result

    def review_threads(
        self,
        number: int,
        *,
        max_pages: int = 10,
    ) -> dict[str, Any]:
        """Collect review-thread resolution state through GitHub GraphQL.

        REST review/comment endpoints do not expose the authoritative
        ``isResolved`` field for review threads. GraphQL is therefore used
        only for this narrow piece of review-state evidence. Authentication
        is required; an unavailable GraphQL collector is reported explicitly
        rather than being interpreted as zero unresolved threads.
        """
        if not self.token:
            return {
                "status": "unavailable",
                "threads": [],
                "error": "GitHub GraphQL review-thread evidence requires GITHUB_TOKEN.",
            }
        if not isinstance(number, int) or number <= 0:
            raise ValueError("number must be a positive integer")
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")

        try:
            owner, repo = self.repo.split("/", 1)
        except ValueError as exc:
            raise GitHubError(f"Invalid GitHub repository: {self.repo!r}") from exc

        query = """
        query($owner: String!, $repo: String!, $number: Int!, $after: String) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $number) {
              reviewThreads(first: 100, after: $after) {
                nodes {
                  id
                  isResolved
                  comments(first: 1) {
                    nodes {
                      createdAt
                      author { login }
                    }
                  }
                }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
        """

        threads: list[dict[str, Any]] = []
        cursor: str | None = None

        for page in range(1, max_pages + 1):
            payload = {
                "query": query,
                "variables": {
                    "owner": owner,
                    "repo": repo,
                    "number": number,
                    "after": cursor,
                },
            }
            url = "https://api.github.com/graphql"
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    **self._headers(),
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                self.calls += 1
                with self._opener(request, timeout=self.timeout) as response:
                    self._update_rate_limit(response.headers)
                    raw = response.read()
                data = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                return {
                    "status": "failed" if not threads else "partial",
                    "threads": threads,
                    "pages_fetched": page - 1,
                    "error": str(exc),
                }

            if not isinstance(data, dict):
                return {
                    "status": "failed" if not threads else "partial",
                    "threads": threads,
                    "pages_fetched": page - 1,
                    "error": "GitHub GraphQL returned a non-object response.",
                }
            if data.get("errors"):
                return {
                    "status": "failed" if not threads else "partial",
                    "threads": threads,
                    "pages_fetched": page - 1,
                    "error": json.dumps(data["errors"], sort_keys=True),
                }

            try:
                connection = (
                    data["data"]["repository"]["pullRequest"]["reviewThreads"]
                )
            except (KeyError, TypeError):
                return {
                    "status": "failed" if not threads else "partial",
                    "threads": threads,
                    "pages_fetched": page - 1,
                    "error": "GitHub GraphQL response omitted reviewThreads.",
                }

            nodes = connection.get("nodes") if isinstance(connection, dict) else None
            if not isinstance(nodes, list):
                return {
                    "status": "failed" if not threads else "partial",
                    "threads": threads,
                    "pages_fetched": page - 1,
                    "error": "GitHub GraphQL reviewThreads.nodes was malformed.",
                }

            for node in nodes:
                if not isinstance(node, dict):
                    continue
                comments = node.get("comments") or {}
                comment_nodes = comments.get("nodes") if isinstance(comments, dict) else []
                first_comment = comment_nodes[0] if comment_nodes and isinstance(comment_nodes[0], dict) else {}
                author = first_comment.get("author") if isinstance(first_comment.get("author"), dict) else {}
                threads.append({
                    "id": node.get("id"),
                    "is_resolved": bool(node.get("isResolved")),
                    "created_at": first_comment.get("createdAt"),
                    "author": author.get("login"),
                })

            page_info = connection.get("pageInfo") if isinstance(connection, dict) else {}
            if not isinstance(page_info, dict) or not page_info.get("hasNextPage"):
                return {
                    "status": "complete",
                    "threads": threads,
                    "pages_fetched": page,
                }
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                return {
                    "status": "failed" if not threads else "partial",
                    "threads": threads,
                    "pages_fetched": page,
                    "error": "GitHub GraphQL pagination omitted endCursor.",
                }

        return {
            "status": "partial",
            "threads": threads,
            "pages_fetched": max_pages,
            "error": f"Review-thread pagination exceeded {max_pages} pages.",
        }

    def required_checks(self, branch: str) -> dict[str, Any]:
        """Collect authoritative required-check evidence for one branch.

        Classic branch protection and the effective branch-rules endpoint are
        collected independently. A missing classic protection is represented
        as ``absent`` rather than as an error; failure to inspect either
        source remains explicit so callers never mistake incomplete policy
        evidence for "no required checks".
        """
        if not isinstance(branch, str) or not branch.strip():
            raise ValueError("branch must be a non-empty string")

        branch_status = "unknown"
        branch_protection: dict[str, Any] | None = None
        branch_error: str | None = None

        try:
            branch_protection = self.branch_protection(branch)
            branch_status = "available"
        except GitHubError as exc:
            message = str(exc)

            # A 404 is deliberately not interpreted as "no branch
            # protection". GitHub can return 404 when the authenticated
            # caller lacks permission to inspect branch protection, so
            # treating it as authoritative absence would allow incomplete
            # policy evidence to masquerade as a complete policy snapshot.
            #
            # The only authoritative "no classic protection" observation
            # is a successful 200 response whose required_status_checks
            # configuration is absent/null.
            if "GitHub HTTP 404:" in message:
                branch_status = "unavailable"
                branch_error = message
            else:
                branch_status = "failed"
                branch_error = message

        rules_status = "unknown"
        branch_rules: list[dict[str, Any]] = []
        rules_error: str | None = None

        try:
            branch_rules = self.branch_rules(branch)
            rules_status = "available"
        except GitHubError as exc:
            message = str(exc)
            if "GitHub HTTP 404:" in message:
                rules_status = "unavailable"
            else:
                rules_status = "failed"
                rules_error = message

        checks = []
        if branch_protection is not None:
            checks.extend(
                self._required_checks_from_branch_protection(
                    branch_protection
                )
            )
        if branch_rules:
            checks.extend(
                self._required_checks_from_branch_rules(branch_rules)
            )

        unique: dict[tuple[Any, ...], dict[str, Any]] = {}
        for check in checks:
            key = (
                check.get("name"),
                check.get("integration_id"),
                check.get("source_type"),
                check.get("ruleset_id"),
            )
            unique[key] = check

        checks = sorted(
            unique.values(),
            key=lambda item: (
                str(item.get("name") or "").casefold(),
                str(item.get("source_type") or ""),
                str(item.get("ruleset_id") or ""),
            ),
        )

        policy_complete = (
            branch_status in {"available", "absent"}
            and rules_status == "available"
        )
        if policy_complete:
            status = "complete"
        elif branch_status == "failed" or rules_status == "failed":
            status = "failed"
        else:
            status = "partial"

        return {
            "status": status,
            "branch": branch,
            "required_checks": checks,
            "required_check_names": sorted(
                {
                    str(item["name"])
                    for item in checks
                    if isinstance(item.get("name"), str)
                },
                key=str.casefold,
            ),
            "sources": {
                "branch_protection": {
                    "status": branch_status,
                    "required_check_count": (
                        len(
                            self._required_checks_from_branch_protection(
                                branch_protection
                            )
                        )
                        if branch_protection is not None
                        else 0
                    ),
                },
                "branch_rules": {
                    "status": rules_status,
                    "rule_count": len(branch_rules),
                    "required_check_count": len(
                        self._required_checks_from_branch_rules(branch_rules)
                    ),
                },
            },
            "branch_protection": branch_protection,
            "branch_rules": branch_rules,
            "errors": {
                key: value
                for key, value in (
                    ("branch_protection", branch_error),
                    ("branch_rules", rules_error),
                )
                if value
            },
        }

    @staticmethod
    def _required_check_policy_keys(
        policy: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Return validated required-check records from collected policy."""
        if not isinstance(policy, dict):
            return []
        values = policy.get("required_checks")
        if not isinstance(values, list):
            return []
        result: list[dict[str, Any]] = []
        for item in values:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            result.append(dict(item))
        return result

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
        """
        Fetch repository source text at a specific ref.

        The Contents API normally provides base64-encoded content for small
        files. For larger supported files, GitHub provides a raw download URL.
        Raw responses must be fetched as bytes/text rather than through the
        JSON API path.
        """
        data = self.content(path, ref)

        if (
            data.get("encoding") == "base64"
            and data.get("content")
        ):
            try:
                decoded = base64.b64decode(
                    data["content"],
                    validate=True,
                )
                if len(decoded) > MAX_RAW_CONTENT_BYTES:
                    raise GitHubError(
                        f"Repository file exceeds the raw-content safety "
                        f"limit of {MAX_RAW_CONTENT_BYTES} bytes: {path}"
                    )

                return decoded.decode(
                    "utf-8",
                    errors="replace",
                )
            except (ValueError, TypeError):
                return None

        download_url = data.get("download_url")

        if isinstance(download_url, str) and download_url:
            if not _is_allowed_raw_host(download_url):
                raise GitHubError(
                    "Refusing to fetch raw content from an unexpected "
                    f"host: {download_url}"
                )
            return self.request_text(
                download_url,
                use_cache=False,
            )

        return None

    def codeowners(
        self,
        ref: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Find CODEOWNERS at the supplied repository ref."""
        candidates = (
            ".github/CODEOWNERS",
            "CODEOWNERS",
            "docs/CODEOWNERS",
        )

        for path in candidates:
            try:
                text = self.raw_content(path, ref)

                if text is not None:
                    return path, text
            except GitHubError:
                continue

        return None, None

    @staticmethod
    def _is_python_file(path: str) -> bool:
        return (
            path.endswith(".py")
            or path.endswith(".pyi")
            or path.endswith(".pyx")
        )

    @staticmethod
    def _is_source_file(path: str) -> bool:
        """Return whether a changed file is source-like review evidence."""
        source_extensions = (
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hh",
            ".hpp",
            ".hxx",
            ".py",
            ".pyi",
            ".pyx",
        )

        return path.endswith(source_extensions)

    def source_file_contents(
        self,
        files: list[dict[str, Any]],
        base_sha: str | None,
        head_sha: str | None,
        errors: dict[str, str] | None = None,
    ) -> dict[str, dict[str, str]]:
        """
        Fetch source versions for the files changed by a pull request.

        Modified files are fetched at both the PR base and head.
        Added files are fetched only at the head.
        Removed files are fetched only at the base.

        Unsupported files are intentionally skipped. Retrieval failures
        are recorded when an error mapping is supplied.
        """
        result: dict[str, dict[str, str]] = {
            "base": {},
            "head": {},
        }

        source_count = 0
        for file_data in files:
            if source_count >= MAX_SOURCE_FILES:
                if errors is not None:
                    errors["source_file_contents"] = (
                        "Source-file retrieval exceeded the safety limit of "
                        f"{MAX_SOURCE_FILES} files; remaining files were not collected."
                    )
                break
            path = file_data.get("filename")

            if not isinstance(path, str):
                continue

            if not self._is_source_file(path):
                continue

            source_count += 1
            status = file_data.get("status")

            refs: list[tuple[str, str | None]] = []

            if status == "added":
                refs.append(("head", head_sha))
            elif status == "removed":
                refs.append(("base", base_sha))
            else:
                refs.append(("base", base_sha))
                refs.append(("head", head_sha))

            for side, ref in refs:
                if not ref:
                    continue

                try:
                    text = self.raw_content(path, ref)

                    if text is not None:
                        result[side][path] = text
                    elif errors is not None:
                        errors[f"{side}_file:{path}"] = (
                            "GitHub returned no readable "
                            f"{side} content."
                        )
                except GitHubError as exc:
                    if errors is not None:
                        errors[f"{side}_file:{path}"] = str(exc)

        return result

    def base_file_contents(
        self,
        files: list[dict[str, Any]],
        base_sha: str | None,
        errors: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """
        Fetch base versions of changed Python files.

        Added files have no base version and are intentionally omitted.
        Retrieval failures are recorded when an error mapping is supplied.
        """
        if not base_sha:
            return {}

        result: dict[str, str] = {}

        for file_data in files:
            path = file_data.get("filename")

            if not isinstance(path, str):
                continue

            if not self._is_python_file(path):
                continue

            status = file_data.get("status")

            if status == "added":
                continue

            try:
                text = self.raw_content(
                    path,
                    base_sha,
                )

                if text is not None:
                    result[path] = text
                elif errors is not None:
                    errors[f"base_file:{path}"] = (
                        "GitHub returned no readable base content."
                    )
            except GitHubError as exc:
                if errors is not None:
                    errors[f"base_file:{path}"] = str(exc)

        return result

    def pull_sample(
        self,
        max_count: int,
        *,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> list[dict[str, Any]]:
        """Fetch a sample of pull requests."""
        if max_count < 1:
            raise ValueError("max_count must be at least 1")

        results: list[dict[str, Any]] = []
        page = 1
        max_pages = max(1, (max_count + max(1, min(per_page, DEFAULT_PER_PAGE)) - 1) // max(1, min(per_page, DEFAULT_PER_PAGE))) + 1

        while len(results) < max_count and page <= max_pages:
            page_size = min(
                per_page,
                max_count - len(results),
                DEFAULT_PER_PAGE,
            )

            path = (
                "/pulls?state=all&sort=created"
                f"&direction=desc&per_page={page_size}"
                f"&page={page}"
            )

            data = self.request(path)

            if not isinstance(data, list) or not data:
                break

            results.extend(
                item
                for item in data
                if isinstance(item, dict)
            )

            page += 1

            if len(data) < page_size:
                break

        return results[:max_count]

    def file_history(
        self,
        path: str,
        base_sha: str | None,
        *,
        max_count: int = 5,
    ) -> list[dict[str, Any]]:
        """Fetch recent commit history for one path at a PR base."""
        if not path or not base_sha or max_count <= 0:
            return []

        page_size = min(max(int(max_count), 1), 100)
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_sha = urllib.parse.quote(
            base_sha,
            safe="",
        )
        data = self.request(
            f"/commits?path={encoded_path}"
            f"&sha={encoded_sha}&per_page={page_size}"
        )

        if not isinstance(data, list):
            raise GitHubError(
                f"Unexpected commit history response for {path!r}"
            )

        history: list[dict[str, Any]] = []
        for commit in data[:page_size]:
            if not isinstance(commit, dict):
                continue

            commit_data = commit.get("commit") or {}
            author = commit_data.get("author") or {}
            history.append(
                {
                    "sha": commit.get("sha"),
                    "message": commit_data.get("message") or "",
                    "author": author.get("name") or author.get("email") or "",
                    "date": author.get("date") or "",
                    "html_url": commit.get("html_url"),
                }
            )

        return history

    def _history_eligible_file(self, file_data: dict[str, Any]) -> bool:
        """Return whether recent path history is useful for this changed file."""
        filename = str(file_data.get("filename") or "").replace("\\", "/")
        if not filename:
            return False

        status = str(file_data.get("status") or "").lower()
        if status in {"added", "removed"}:
            return False

        if filename.startswith(
            (
                "Doc/",
                "Misc/NEWS.d/",
                "Lib/test/",
                "Tools/test/",
            )
        ):
            return False

        if filename in {
            "Parser/parser.c",
            "Python/graminit.c",
            "Python/graminit.h",
        }:
            return False

        return filename.endswith(
            (
                ".c",
                ".h",
                ".cc",
                ".cpp",
                ".m",
                ".py",
                ".pyi",
                ".pyx",
            )
        )

    def _collect_file_histories(
        self,
        files: list[dict[str, Any]],
        base_sha: str | None,
        errors: dict[str, str],
        *,
        max_files: int = DEFAULT_HISTORY_MAX_FILES,
        max_commits: int = DEFAULT_HISTORY_MAX_COMMITS,
    ) -> None:
        """Attach bounded recent history to relevant changed files."""
        if not base_sha:
            return

        file_limit = max(int(max_files), 0)
        commit_limit = max(int(max_commits), 0)

        if file_limit == 0 or commit_limit == 0:
            return

        eligible = [
            file_data
            for file_data in files
            if self._history_eligible_file(file_data)
        ][:file_limit]

        for file_data in eligible:
            filename = str(file_data.get("filename") or "").replace("\\", "/")
            try:
                file_data["history"] = self.file_history(
                    filename,
                    base_sha,
                    max_count=commit_limit,
                )
            except Exception as exc:
                file_data["history"] = []
                errors[f"history:{filename}"] = str(exc)

    def pull_request_evidence(
        self,
        number: int,
        *,
        linked_issue_numbers: list[int]
        | tuple[int, ...]
        | set[int]
        | None = None,
    ) -> dict[str, Any]:
        """Collect a reproducible, provenance-rich evidence package for a PR.

        Collectors are isolated: one endpoint failing does not erase evidence
        already collected from other endpoints. Bounded collectors expose
        their outcome in ``stats["evidence"]`` so downstream analysis can
        distinguish complete, empty, partial, sampled and failed evidence.
        """
        pr = self.pr(number)
        evidence: dict[str, Any] = {"pr": pr}
        errors: dict[str, str] = {}
        evidence_meta: dict[str, dict[str, Any]] = {}

        def record(
            source: str,
            status: str,
            *,
            collected: int | None = None,
            total: int | None = None,
            limit: int | None = None,
            truncated: bool | None = None,
            details: dict[str, Any] | None = None,
            error: str | None = None,
        ) -> None:
            item: dict[str, Any] = {"status": status}
            if collected is not None:
                item["collected"] = collected
            if total is not None:
                item["total"] = total
            if limit is not None:
                item["limit"] = limit
            if truncated is not None:
                item["truncated"] = truncated
            if details:
                item["details"] = details
            if error:
                item["error"] = error
            evidence_meta[source] = item

        record("pr", "complete", collected=1, total=1)

        # Use the public collectors so subclasses/test doubles and future
        # provider implementations remain valid.  ``paginate`` records its
        # bounded outcome, allowing us to preserve a partial prefix if the
        # safety limit is reached.
        collectors = {
            "files": lambda: self.files(number),
            "reviews": lambda: self.reviews(number),
            "review_comments": lambda: self.review_comments(number),
            "issue_comments": lambda: self.issue_comments(number),
            "timeline": lambda: self.timeline(number),
        }
        for name, collector in collectors.items():
            self._last_pagination = {"items": [], "complete": True, "pages_fetched": 0}
            try:
                values = collector()
                pagination = self._last_pagination
                complete = bool(pagination.get("complete", True))
                evidence[name] = values
                record(
                    name,
                    "complete" if complete else "partial",
                    collected=len(values),
                    limit=MAX_PAGINATED_ITEMS,
                    truncated=not complete,
                    details={"pages_fetched": pagination.get("pages_fetched")},
                )
            except Exception as exc:
                pagination = self._last_pagination
                partial_values = pagination.get("items", [])
                if isinstance(partial_values, list) and partial_values:
                    evidence[name] = partial_values
                    errors[name] = (
                        f"{exc}; collected prefix is partial and must not be "
                        "treated as complete."
                    )
                    record(
                        name, "partial", collected=len(partial_values),
                        limit=MAX_PAGINATED_ITEMS, truncated=True,
                        details={"pages_fetched": pagination.get("pages_fetched")},
                        error=str(exc),
                    )
                else:
                    evidence[name] = []
                    errors[name] = str(exc)
                    record(name, "failed", collected=0, error=str(exc))

        try:
            review_threads = self.review_threads(number)
            evidence["review_threads"] = review_threads
            thread_status = str(review_threads.get("status") or "unknown")
            record(
                "review_threads",
                {"complete": "complete", "partial": "partial", "failed": "failed", "unavailable": "unavailable"}.get(thread_status, "failed"),
                collected=len(review_threads.get("threads") or []),
                details={"pages_fetched": review_threads.get("pages_fetched")},
                error=review_threads.get("error"),
            )
            if thread_status in {"failed", "partial"} and review_threads.get("error"):
                errors["review_threads"] = str(review_threads["error"])
        except Exception as exc:
            evidence["review_threads"] = {"status": "failed", "threads": [], "error": str(exc)}
            errors["review_threads"] = str(exc)
            record("review_threads", "failed", collected=0, error=str(exc))

        linked_numbers = [
            number_value
            for number_value in (linked_issue_numbers or [])
            if isinstance(number_value, int) and number_value > 0
        ]
        # Preserve caller order while deduplicating and enforce a hard cap.
        seen_numbers: set[int] = set()
        linked_numbers = [
            n for n in linked_numbers
            if not (n in seen_numbers or seen_numbers.add(n))
        ]
        linked_truncated = len(linked_numbers) > MAX_LINKED_ISSUES
        linked_numbers = linked_numbers[:MAX_LINKED_ISSUES]

        if linked_issue_numbers:
            if linked_truncated:
                errors["linked_issues"] = (
                    f"Linked issue collection capped at {MAX_LINKED_ISSUES}; "
                    "remaining issue numbers were not collected."
                )
                record(
                    "linked_issues", "partial",
                    collected=0, total=len(linked_numbers),
                    limit=MAX_LINKED_ISSUES, truncated=True,
                )
            try:
                linked = self.linked_issues(linked_numbers)
                evidence["linked_issues"] = linked
                if "linked_issues" not in errors:
                    record(
                        "linked_issues",
                        "complete" if linked else "empty",
                        collected=len(linked),
                        total=len(linked_numbers),
                        limit=MAX_LINKED_ISSUES,
                    )
                else:
                    record(
                        "linked_issues", "partial",
                        collected=len(linked),
                        total=len(linked_numbers),
                        limit=MAX_LINKED_ISSUES, truncated=True,
                    )
            except Exception as exc:
                evidence["linked_issues"] = []
                errors["linked_issues"] = str(exc)
                record("linked_issues", "failed", collected=0)
        else:
            evidence["linked_issues"] = []
            record("linked_issues", "empty", collected=0, total=0)

        base_sha = (pr.get("base") or {}).get("sha")
        head_sha = (pr.get("head") or {}).get("sha")
        base_branch = (pr.get("base") or {}).get("ref")

        try:
            head_commit = self.head_commit_evidence(head_sha)
            evidence["head_commit"] = head_commit

            head_commit_status = str(
                head_commit.get("status") or "unknown"
            )

            record(
                "head_commit",
                (
                    "complete"
                    if head_commit_status == "complete"
                    else head_commit_status
                ),
                collected=1 if head_commit_status == "complete" else 0,
                total=1,
                details={
                    "head_sha": head_sha,
                    "author_login": (
                        (head_commit.get("author") or {}).get("login")
                        if isinstance(head_commit.get("author"), dict)
                        else None
                    ),
                    "committer_login": (
                        (head_commit.get("committer") or {}).get("login")
                        if isinstance(head_commit.get("committer"), dict)
                        else None
                    ),
                },
                error=head_commit.get("error"),
            )

            if head_commit_status in {"failed", "unavailable"}:
                errors["head_commit"] = str(
                    head_commit.get("error")
                    or "Head commit identity evidence is unavailable."
                )
        except Exception as exc:
            evidence["head_commit"] = {
                "status": "failed",
                "sha": head_sha,
                "author": None,
                "committer": None,
                "error": str(exc),
            }
            errors["head_commit"] = str(exc)
            record(
                "head_commit",
                "failed",
                collected=0,
                total=1,
                details={"head_sha": head_sha},
                error=str(exc),
            )

        if isinstance(base_branch, str) and base_branch.strip():
            try:
                required_checks = self.required_checks(base_branch)
                evidence["required_checks"] = required_checks
                policy_status = str(required_checks.get("status") or "unknown")
                record(
                    "required_checks",
                    "complete" if policy_status == "complete" else (
                        "failed" if policy_status == "failed" else "partial"
                    ),
                    collected=len(
                        self._required_check_policy_keys(required_checks)
                    ),
                    details={
                        "branch": base_branch,
                        "sources": required_checks.get("sources", {}),
                    },
                    error=(
                        "; ".join(
                            str(value)
                            for value in (required_checks.get("errors") or {}).values()
                            if value
                        )
                        or None
                    ),
                )
                if required_checks.get("errors"):
                    errors["required_checks"] = json.dumps(
                        required_checks["errors"],
                        sort_keys=True,
                    )
            except Exception as exc:
                evidence["required_checks"] = {
                    "status": "failed",
                    "branch": base_branch,
                    "required_checks": [],
                    "required_check_names": [],
                    "errors": {"collector": str(exc)},
                }
                errors["required_checks"] = str(exc)
                record(
                    "required_checks",
                    "failed",
                    collected=0,
                    details={"branch": base_branch},
                    error=str(exc),
                )
        else:
            evidence["required_checks"] = {
                "status": "unavailable",
                "branch": base_branch,
                "required_checks": [],
                "required_check_names": [],
                "errors": {"collector": "PR base branch is unavailable."},
            }
            errors["required_checks"] = "PR base branch is unavailable."
            record(
                "required_checks",
                "unavailable",
                collected=0,
                details={"branch": base_branch},
                error=errors["required_checks"],
            )

        try:
            evidence["codeowners_path"], evidence["codeowners_text"] = self.codeowners(base_sha)
            if evidence["codeowners_path"] and evidence["codeowners_text"] is not None:
                record("codeowners", "complete", collected=1, total=1, details={"ref": base_sha})
            else:
                record("codeowners", "empty", collected=0, total=1, details={"ref": base_sha})
        except Exception as exc:
            evidence["codeowners_path"] = None
            evidence["codeowners_text"] = None
            errors["codeowners"] = str(exc)
            record("codeowners", "failed", collected=0, total=1, details={"ref": base_sha})

        files = evidence.get("files", [])
        eligible_history = [
            f for f in files if isinstance(f, dict) and self._history_eligible_file(f)
        ]
        try:
            self._collect_file_histories(files, base_sha, errors)
            history_collected = sum(
                1 for f in eligible_history if isinstance(f.get("history"), list)
            )
            history_sampled = len(eligible_history) > DEFAULT_HISTORY_MAX_FILES
            history_failed = any(k.startswith("history:") for k in errors)
            if not eligible_history:
                history_status = "empty"
            elif history_sampled or history_failed:
                history_status = "partial" if history_failed else "sampled"
            else:
                # Per-file history is intentionally bounded to recent commits.
                history_status = "sampled"
            record(
                "file_history", history_status,
                collected=history_collected, total=len(eligible_history),
                limit=DEFAULT_HISTORY_MAX_FILES,
                truncated=history_sampled,
                details={"commits_per_file": DEFAULT_HISTORY_MAX_COMMITS},
            )
        except Exception as exc:
            errors["file_history"] = str(exc)
            record("file_history", "failed", collected=0, total=len(eligible_history), limit=DEFAULT_HISTORY_MAX_FILES)

        try:
            evidence["source_file_contents"] = self.source_file_contents(
                files, base_sha, head_sha, errors
            )
            source = evidence["source_file_contents"]
            collected_versions = len(source.get("base", {})) + len(source.get("head", {}))
            expected_versions = sum(
                2 if f.get("status") not in {"added", "removed"} else 1
                for f in files
                if isinstance(f, dict) and self._is_source_file(str(f.get("filename") or ""))
            )
            source_error = "source_file_contents" in errors or any(
                k.startswith(("base_file:", "head_file:")) for k in errors
            )
            source_status = "failed" if source_error and not collected_versions else (
                "partial" if source_error or collected_versions < expected_versions else (
                    "empty" if expected_versions == 0 else "complete"
                )
            )
            record(
                "source_file_contents", source_status,
                collected=collected_versions, total=expected_versions,
                limit=MAX_SOURCE_FILES,
                truncated=len([f for f in files if isinstance(f, dict) and self._is_source_file(str(f.get("filename") or ""))]) > MAX_SOURCE_FILES,
                details={"base_sha": base_sha, "head_sha": head_sha},
            )
        except Exception as exc:
            evidence["source_file_contents"] = {"base": {}, "head": {}}
            errors["source_file_contents"] = str(exc)
            record("source_file_contents", "failed", collected=0, details={"base_sha": base_sha, "head_sha": head_sha})

        try:
            evidence["base_file_contents"] = self.base_file_contents(files, base_sha, errors)
            expected_base = sum(
                1 for f in files
                if isinstance(f, dict)
                and f.get("status") != "added"
                and self._is_python_file(str(f.get("filename") or ""))
            )
            collected_base = len(evidence["base_file_contents"])
            base_error = "base_file_contents" in errors or any(k.startswith("base_file:") for k in errors)
            record(
                "base_file_contents",
                "failed" if base_error and not collected_base else (
                    "partial" if base_error or collected_base < expected_base else (
                        "empty" if expected_base == 0 else "complete"
                    )
                ),
                collected=collected_base, total=expected_base,
                details={"base_sha": base_sha},
            )
        except Exception as exc:
            evidence["base_file_contents"] = {}
            errors["base_file_contents"] = str(exc)
            record("base_file_contents", "failed", collected=0, details={"base_sha": base_sha})

        if head_sha:
            try:
                evidence["check_runs"] = self.check_runs(head_sha)
                checks = evidence["check_runs"]
                count = len(checks.get("check_runs", []))
                total = _safe_int(checks.get("total_count"), count) or count
                record(
                    "check_runs",
                    "complete" if checks.get("pagination_complete", True) else "partial",
                    collected=count, total=total, limit=MAX_PAGINATED_ITEMS,
                    truncated=not checks.get("pagination_complete", True),
                    details={"head_sha": head_sha, "pages_fetched": checks.get("pages_fetched")},
                )
            except Exception as exc:
                evidence["check_runs"] = {"total_count": 0, "check_runs": []}
                errors["check_runs"] = str(exc)
                record("check_runs", "failed", collected=0, details={"head_sha": head_sha})

            try:
                evidence["statuses"] = self.statuses(head_sha)
                record(
                    "statuses",
                    "empty" if not evidence["statuses"] else "complete",
                    collected=len(evidence["statuses"]),
                    details={"head_sha": head_sha},
                )
            except Exception as exc:
                evidence["statuses"] = []
                errors["statuses"] = str(exc)
                record("statuses", "failed", collected=0, details={"head_sha": head_sha})
        else:
            evidence["check_runs"] = {"total_count": 0, "check_runs": []}
            evidence["statuses"] = []
            record("check_runs", "unavailable", collected=0, details={"head_sha": None})
            record("statuses", "unavailable", collected=0, details={"head_sha": None})

        evidence["head_sha"] = head_sha
        evidence["base_sha"] = base_sha

        collection_stats = self.stats()
        collection_stats["evidence"] = evidence_meta
        collection_stats["repository"] = self.repo
        collection_stats["pr_number"] = number
        collection_stats["base_sha"] = base_sha
        collection_stats["head_sha"] = head_sha
        collection_stats["cache_ttl"] = self.cache_ttl
        collection_stats["api_version"] = API_VERSION

        return {
            "evidence": evidence,
            "errors": errors,
            "stats": collection_stats,
        }

    def stats(self) -> dict[str, Any]:
        return {
            "api_calls": self.calls,
            "cache_hits": self.cache_hits,
            "rate_limit_remaining": self.rate_remaining,
            "rate_limit_reset": self.rate_reset,
        }