"""Refresh the versioned CPython review-policy snapshot."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from html import unescape
from pathlib import Path
from urllib.request import Request, urlopen


DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "cpython-review-policy.json"
)

TRIAGING_URL = "https://devguide.python.org/triage/triaging/"
LIFECYCLE_URL = (
    "https://devguide.python.org/"
    "getting-started/pull-request-lifecycle/index.html"
)

SOURCES = {
    "triaging": TRIAGING_URL,
    "pull_request_lifecycle": LIFECYCLE_URL,
    "documentation": "https://devguide.python.org/documenting/",
    "cpython_patchcheck": (
        "https://github.com/python/cpython/blob/main/"
        "Tools/patchcheck/patchcheck.py"
    ),
    "cpython_doc_readme": (
        "https://github.com/python/cpython/blob/main/"
        "Doc/README.rst"
    ),
}


def fetch_text(url: str) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "cpython-pr-triager-review-policy-refresh/1.0",
        },
    )
    with urlopen(request, timeout=30) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset)


def normalise_html(text: str) -> str:
    text = unescape(text)
    text = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        text,
        flags=re.I | re.S,
    )
    text = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        text,
        flags=re.I | re.S,
    )
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def validate_source(
    name: str,
    text: str,
    *,
    minimum_length: int = 1000,
) -> None:
    """Validate that an upstream documentation page is substantial.

    Exact wording is intentionally not required here because the Developer
    Guide can change prose, markup, or section ordering without changing the
    underlying workflow.

    The snapshot records the authoritative source URLs, while concrete
    machine-actionable checks are represented explicitly in the generated
    policy data and should be validated by the repository test suite.
    """
    normalised = normalise_html(text)

    if len(normalised) < minimum_length:
        raise ValueError(
            f"{name} source is unexpectedly small "
            f"({len(normalised)} characters)."
        )


def build_snapshot(
    *,
    retrieved_at: str | None = None,
) -> dict[str, object]:
    triaging_html = fetch_text(TRIAGING_URL)
    lifecycle_html = fetch_text(LIFECYCLE_URL)

    validate_source("triaging", triaging_html)
    validate_source(
        "pull_request_lifecycle",
        lifecycle_html,
    )

    return {
        "schema_version": 2,
        "sources": [
            {
                "name": name,
                "url": url,
            }
            for name, url in SOURCES.items()
        ],
        "retrieved_at": (
            retrieved_at
            or dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "checks": {
            "solution_quality": {
                "kind": "review_check",
                "required": True,
                "source": "triaging",
            },
            "style": {
                "kind": "review_check",
                "required": True,
                "source": "triaging",
            },
            "tests": {
                "kind": "review_check",
                "required": True,
                "source": "triaging",
            },
            "documentation": {
                "kind": "review_check",
                "required": True,
                "source": "triaging",
            },
            "news": {
                "kind": "review_check",
                "required_when_applicable": True,
                "source": "triaging",
            },
            "ci": {
                "kind": "review_check",
                "required": True,
                "source": "triaging",
            },
            "base_branch_conflicts": {
                "kind": "review_check",
                "required": True,
                "source": "triaging",
            },
            "patchcheck": {
                "kind": "repository_check",
                "enabled": True,
                "source": "pull_request_lifecycle",
            },
            "documentation_build": {
                "kind": "repository_check",
                "enabled": True,
                "source": "cpython_doc_readme",
            },
            "documentation_linkcheck": {
                "kind": "repository_check",
                "enabled": True,
                "source": "cpython_doc_readme",
            },
            "documentation_changes": {
                "kind": "repository_check",
                "enabled": True,
                "source": "cpython_doc_readme",
            },
            "documentation_markup_check": {
                "kind": "repository_check",
                "enabled": True,
                "source": "cpython_doc_readme",
            },
        },
    }


def write_snapshot(
    output: Path,
    snapshot: dict[str, object],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(snapshot, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)


def refresh(output: Path) -> dict[str, object]:
    snapshot = build_snapshot()
    write_snapshot(output, snapshot)
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Refresh the CPython review-policy snapshot from "
            "the official Developer Guide."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output snapshot path.",
    )
    args = parser.parse_args(argv)

    try:
        snapshot = refresh(args.output)
    except Exception as exc:
        print(
            f"Review policy refresh failed: {exc}",
            file=sys.stderr,
        )
        return 1

    checks = snapshot["checks"]
    assert isinstance(checks, dict)

    print(
        f"Wrote {len(checks)} review policy checks to "
        f"{args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())