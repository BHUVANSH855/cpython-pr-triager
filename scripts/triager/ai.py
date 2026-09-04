"""
Optional AI synthesis layer.

The AI is downstream of deterministic evidence.

It is NOT the source of truth.

The AI must:
- use supplied evidence only
- distinguish facts from inference
- expose uncertainty
- avoid maintainer-level authority claims
- return structured JSON
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any


class AISynthesisError(RuntimeError):
    """Raised when AI synthesis cannot be completed."""


def _compact_report(
    report: dict[str, Any],
    limit: int = 120_000,
) -> str:
    """
    Serialize evidence while preventing an accidentally enormous prompt.
    """

    text = json.dumps(
        report,
        ensure_ascii=False,
    )

    if len(text) <= limit:
        return text

    return (
        text[:limit]
        + "\n...[evidence truncated]"
    )


def build_prompt(
    report: dict[str, Any],
) -> str:
    """
    Build the evidence-grounded synthesis prompt.
    """

    evidence = _compact_report(
        report
    )

    return f"""
You are assisting CPython maintainers.

You are NOT a CPython maintainer.

You must never claim to:
- approve a pull request
- reject a pull request
- merge a pull request
- make a final maintainer decision

Use ONLY the supplied evidence.

Evidence hierarchy:

1. OBSERVED
   Directly present in supplied repository/PR evidence.

2. DERIVED
   A deterministic conclusion obtained from observed evidence.

3. HEURISTIC
   A review prompt that may indicate something worth inspecting.

4. INFERENCE
   A reasoned interpretation of available evidence.

5. UNKNOWN
   The supplied evidence does not establish the answer.

Never convert a heuristic into proof.

Never invent:
- tests
- reviewers
- owners
- CPython policy
- historical facts
- bugs
- security vulnerabilities
- compatibility guarantees

Every material risk should identify the relevant evidence.

Return ONLY valid JSON with this structure:

{{
  "triage": "READY_FOR_MAINTAINER_REVIEW|NEEDS_MAINTAINER_ATTENTION|NEEDS_AUTHOR_CHANGES|PROCESS_BLOCKED|HIGH_RISK_REVIEW",
  "confidence": 1,
  "summary": "...",
  "top_risks": [
    {{
      "risk": "...",
      "evidence": "..."
    }}
  ],
  "review_questions": [
    "..."
  ],
  "expert_routing": [
    {{
      "owner": "...",
      "reason": "..."
    }}
  ],
  "process_assessment": "...",
  "test_assessment": "...",
  "backport_assessment": "...",
  "uncertainties": [
    "..."
  ]
}}

The confidence value must be an integer from 1 to 5.

Evidence package:

{evidence}
""".strip()


def synthesize(
    report: dict[str, Any],
    api_key: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """
    Ask Anthropic for evidence-grounded synthesis.
    """

    key = (
        api_key
        or os.environ.get(
            "ANTHROPIC_API_KEY"
        )
    )

    if not key:
        raise AISynthesisError(
            "ANTHROPIC_API_KEY is not set"
        )

    selected_model = (
        model
        or os.environ.get(
            "ANTHROPIC_MODEL",
            "claude-sonnet-4-6",
        )
    )

    payload = {
        "model": selected_model,
        "max_tokens": 3000,
        "system": (
            "You are an evidence-grounded "
            "assistant for CPython maintainers. "
            "Return only valid JSON."
        ),
        "messages": [
            {
                "role": "user",
                "content": build_prompt(
                    report
                ),
            }
        ],
    }

    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(
            payload
        ).encode("utf-8"),
        headers={
            "Content-Type": (
                "application/json"
            ),
            "x-api-key": key,
            "anthropic-version": (
                "2023-06-01"
            ),
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=120,
        ) as response:
            data = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

    except Exception as exc:
        raise AISynthesisError(
            str(exc)
        ) from exc

    raw = "".join(
        item.get(
            "text",
            "",
        )
        for item in data.get(
            "content",
            []
        )
        if item.get(
            "type"
        ) == "text"
    ).strip()

    # Handle accidental markdown JSON fences.
    raw = re.sub(
        r"^```(?:json)?\s*",
        "",
        raw,
    )

    raw = re.sub(
        r"\s*```$",
        "",
        raw,
    )

    try:
        result = json.loads(
            raw
        )

    except json.JSONDecodeError as exc:
        raise AISynthesisError(
            "AI returned invalid JSON"
        ) from exc

    if not isinstance(
        result,
        dict,
    ):
        raise AISynthesisError(
            "AI response must be a JSON object"
        )

    return result