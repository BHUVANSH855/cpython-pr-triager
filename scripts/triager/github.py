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
        if path_or_url.startswith(("http://", "https://")):
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
        """
        Fetch pages from a GitHub list endpoint.

        GitHub supports at most 100 items per page. The explicit page limit
        protects the triager from an unexpectedly large or non-terminating
        pagination sequence.
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

            result.extend(
                item
                for item in data
                if isinstance(item, dict)
            )

            if len(data) < per_page:
                return result

            page += 1

        raise GitHubError(
            f"GitHub pagination exceeded the safety limit of "
            f"{max_pages} pages: {path}"
        )

    def pr(self, number: int) -> dict[str, Any]:
        data = self.request(f"/pulls/{number}")

        if not isinstance(data, dict):
            raise GitHubError(
                f"Unexpected PR response for #{number}"
            )

        return data

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
            ev.setdefault(
                "kind",
                event.get("event", "unknown"),
            )
            ev.setdefault("login", login)
            ev.setdefault(
                "date",
                event.get("created_at")
                or event.get("submitted_at")
                or "",
            )
            ev.setdefault(
                "body",
                event.get("body") or "",
            )

            if event.get("event") == "reviewed" or event.get("state"):
                ev.setdefault(
                    "state",
                    event.get("state", ""),
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

        while page <= max_pages:
            path = (
                f"/commits/{encoded_sha}/check-runs"
                f"?per_page={per_page}&page={page}"
            )

            data = self.request(path)

            if not isinstance(data, dict):
                raise GitHubError(
                    f"Unexpected check-runs response "
                    f"for commit {sha}"
                )

            page_runs = data.get("check_runs", [])

            if not isinstance(page_runs, list):
                raise GitHubError(
                    f"Invalid check_runs payload "
                    f"for commit {sha}"
                )

            runs.extend(
                item
                for item in page_runs
                if isinstance(item, dict)
            )

            if total_count is None:
                raw_total = data.get("total_count")

                if isinstance(raw_total, int):
                    total_count = raw_total

            if len(page_runs) < per_page:
                break

            page += 1
        else:
            raise GitHubError(
                f"GitHub check-run pagination exceeded the safety "
                f"limit of {max_pages} pages for commit {sha}"
            )

        return {
            "total_count": (
                total_count
                if total_count is not None
                else len(runs)
            ),
            "check_runs": runs,
        }

    def statuses(self, sha: str) -> list[dict[str, Any]]:
        encoded_sha = urllib.parse.quote(
            sha,
            safe="",
        )

        return self.paginate(
            f"/commits/{encoded_sha}/statuses"
        )

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

        for file_data in files:
            path = file_data.get("filename")

            if not isinstance(path, str):
                continue

            if not self._is_source_file(path):
                continue

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

        while len(results) < max_count:
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
        max_files: int = 20,
        max_commits: int = 5,
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
        """
        Collect the core evidence package for one PR.
        """
        pr = self.pr(number)
        evidence: dict[str, Any] = {"pr": pr}
        errors: dict[str, str] = {}

        for name, collector in {
            "files": lambda: self.files(number),
            "reviews": lambda: self.reviews(number),
            "review_comments": lambda: self.review_comments(number),
            "issue_comments": lambda: self.issue_comments(number),
            "timeline": lambda: self.timeline(number),
        }.items():
            try:
                evidence[name] = collector()
            except Exception as exc:
                evidence[name] = []
                errors[name] = str(exc)

        if linked_issue_numbers:
            try:
                evidence["linked_issues"] = self.linked_issues(
                    linked_issue_numbers
                )
            except Exception as exc:
                evidence["linked_issues"] = []
                errors["linked_issues"] = str(exc)
        else:
            evidence["linked_issues"] = []

        base_sha = (pr.get("base") or {}).get("sha")

        try:
            (
                evidence["codeowners_path"],
                evidence["codeowners_text"],
            ) = self.codeowners(base_sha)
        except Exception as exc:
            evidence["codeowners_path"] = None
            evidence["codeowners_text"] = None
            errors["codeowners"] = str(exc)

        files = evidence.get("files", [])

        self._collect_file_histories(
            files,
            base_sha,
            errors,
        )

        try:
            evidence["source_file_contents"] = (
                self.source_file_contents(
                    files,
                    base_sha,
                    (pr.get("head") or {}).get("sha"),
                    errors,
                )
            )
        except Exception as exc:
            evidence["source_file_contents"] = {
                "base": {},
                "head": {},
            }
            errors["source_file_contents"] = str(exc)

        try:
            evidence["base_file_contents"] = (
                self.base_file_contents(
                    files,
                    base_sha,
                    errors,
                )
            )
        except Exception as exc:
            evidence["base_file_contents"] = {}
            errors["base_file_contents"] = str(exc)

        head_sha = (pr.get("head") or {}).get("sha")

        if head_sha:
            try:
                evidence["check_runs"] = self.check_runs(
                    head_sha
                )
            except Exception as exc:
                evidence["check_runs"] = {
                    "total_count": 0,
                    "check_runs": [],
                }
                errors["check_runs"] = str(exc)

            try:
                evidence["statuses"] = self.statuses(
                    head_sha
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

    def stats(self) -> dict[str, Any]:
        return {
            "api_calls": self.calls,
            "cache_hits": self.cache_hits,
            "rate_limit_remaining": self.rate_remaining,
            "rate_limit_reset": self.rate_reset,
        }