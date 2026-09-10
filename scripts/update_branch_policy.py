"""Refresh the versioned CPython branch lifecycle policy snapshot."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen


SOURCE_URL = "https://devguide.python.org/versions/"
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1] / "data" / "branch-policy.json"
)

VALID_STATUSES = {
    "feature",
    "prerelease",
    "bugfix",
    "security",
    "end-of-life",
}


class VersionTableParser(HTMLParser):
    """Extract branch/status pairs from the Developer Guide tables."""

    def __init__(self) -> None:
        super().__init__()
        self.in_table = False
        self.in_row = False
        self.in_cell = False
        self.current_cell: list[str] = []
        self.current_row: list[str] = []
        self.rows: list[list[str]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "table":
            self.in_table = True
        elif self.in_table and tag == "tr":
            self.in_row = True
            self.current_row = []
        elif self.in_row and tag in {"td", "th"}:
            self.in_cell = True
            self.current_cell = []

    def handle_endtag(self, tag: str) -> None:
        if self.in_cell and tag in {"td", "th"}:
            self.in_cell = False
            self.current_row.append(" ".join(self.current_cell).strip())
            self.current_cell = []
        elif self.in_row and tag == "tr":
            if self.current_row:
                self.rows.append(self.current_row)
            self.current_row = []
            self.in_row = False
        elif tag == "table":
            self.in_table = False

    def handle_data(self, data: str) -> None:
        if self.in_cell:
            text = " ".join(data.split())
            if text:
                self.current_cell.append(text)


def _normalise_status(value: str) -> str | None:
    value = value.strip().lower()

    aliases = {
        "end of life": "end-of-life",
        "eol": "end-of-life",
    }

    value = aliases.get(value, value)
    return value if value in VALID_STATUSES else None


def parse_branch_statuses(html: str) -> dict[str, str]:
    """Parse CPython branch/status pairs from the Developer Guide tables."""

    parser = VersionTableParser()
    parser.feed(html)

    statuses: dict[str, str] = {}

    for row in parser.rows:
        if len(row) < 3:
            continue

        branch = row[0].strip()
        status = _normalise_status(row[2])

        if status is None:
            continue

        if branch == "main" or branch.startswith("3."):
            statuses[branch] = status

    return statuses


def fetch_source(url: str = SOURCE_URL) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "cpython-pr-triager-branch-policy-refresh/1.0",
        },
    )

    with urlopen(request, timeout=30) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset)


def build_snapshot(
    statuses: dict[str, str],
    *,
    retrieved_at: str | None = None,
) -> dict[str, object]:
    if not statuses:
        raise ValueError("No valid CPython branch statuses were found.")

    invalid = {
        status
        for status in statuses.values()
        if status not in VALID_STATUSES
    }

    if invalid:
        raise ValueError(
            "Invalid branch lifecycle statuses found: "
            + ", ".join(sorted(invalid))
        )

    return {
        "schema_version": 1,
        "source": SOURCE_URL,
        "retrieved_at": (
            retrieved_at
            or dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "statuses": dict(sorted(statuses.items())),
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
    html = fetch_source()
    statuses = parse_branch_statuses(html)

    if "main" not in statuses:
        raise ValueError(
            "The source page was parsed, but the main branch status "
            "was not found. Refusing to overwrite the existing snapshot."
        )

    snapshot = build_snapshot(statuses)
    write_snapshot(output, snapshot)

    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Refresh data/branch-policy.json from the CPython "
            "Developer Guide."
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
            f"Branch policy refresh failed: {exc}",
            file=sys.stderr,
        )
        return 1

    statuses = snapshot["statuses"]
    assert isinstance(statuses, dict)

    print(
        f"Wrote {len(statuses)} branch statuses to "
        f"{args.output}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())