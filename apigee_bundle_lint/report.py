"""Render lint findings as text, JSON, or Markdown."""

from __future__ import annotations

import json

from .loader import Finding


def _summary(findings: list[Finding]) -> dict:
    return {
        "findings": len(findings),
        "errors": sum(1 for item in findings if item.severity == "error"),
        "warnings": sum(1 for item in findings if item.severity == "warning"),
    }


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "No issues found.\n"
    lines: list[str] = []
    for item in findings:
        where = f"{item.file}: " if item.file else ""
        lines.append(f"{item.severity}: {where}[{item.check}] {item.message}")
    summary = _summary(findings)
    lines.append(
        f"\n{summary['findings']} issue(s): "
        f"{summary['errors']} error(s), {summary['warnings']} warning(s)"
    )
    return "\n".join(lines) + "\n"


def to_json(findings: list[Finding]) -> str:
    payload = {
        "summary": _summary(findings),
        "findings": [item.as_dict() for item in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def to_markdown(findings: list[Finding]) -> str:
    summary = _summary(findings)
    lines = [
        f"## apigee-bundle-lint: {summary['findings']} issue(s) "
        f"({summary['errors']} error(s), {summary['warnings']} warning(s))",
        "",
    ]
    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines) + "\n"
    lines.append("| Severity | Check | File | Message |")
    lines.append("| --- | --- | --- | --- |")
    for item in findings:
        lines.append(
            f"| {item.severity} | `{item.check}` | `{item.file}` | "
            f"{item.message} |"
        )
    return "\n".join(lines) + "\n"
