from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


def main() -> int:
    if not WORKFLOW.is_file():
        raise SystemExit(f"Missing workflow: {WORKFLOW}")

    text = WORKFLOW.read_text(encoding="utf-8")

    required_fragments = (
        'actions/checkout@v7',
        'actions/setup-python@v7',
        'allow-prereleases: true',
        'python -m pip install --disable-pip-version-check -e ".[test]"',
        "python -m compileall -q scripts tests",
        "python -m pytest --version",
        "python -m pytest -q",
    )

    for fragment in required_fragments:
        if fragment not in text:
            raise SystemExit(
                f"CI workflow is missing required fragment: {fragment}"
            )

    if "python -m unittest discover" in text:
        raise SystemExit(
            "CI workflow must use pytest rather than unittest discovery"
        )

    print("CI workflow validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())