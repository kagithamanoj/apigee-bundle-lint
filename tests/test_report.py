"""Tests for the text, JSON, and Markdown renderers."""

import json

from apigee_bundle_lint.loader import Finding
from apigee_bundle_lint.report import to_json, to_markdown, to_text

SAMPLE = [
    Finding(
        check="missing-api-key-check",
        severity="warning",
        message="no VerifyAPIKey policy in the PreFlow request",
        file="apiproxy/proxies/default.xml",
    ),
    Finding(
        check="target-no-url",
        severity="error",
        message="HTTPTargetConnection has neither a URL nor a LoadBalancer",
        file="apiproxy/targets/default.xml",
    ),
]


def test_text_empty():
    assert to_text([]) == "No issues found.\n"


def test_text_lists_findings_and_summary():
    output = to_text(SAMPLE)
    assert "warning: apiproxy/proxies/default.xml: [missing-api-key-check]" in output
    assert "error: apiproxy/targets/default.xml: [target-no-url]" in output
    assert "2 issue(s): 1 error(s), 1 warning(s)" in output


def test_json_round_trip():
    payload = json.loads(to_json(SAMPLE))
    assert payload["summary"] == {"findings": 2, "errors": 1, "warnings": 1}
    assert payload["findings"][0]["check"] == "missing-api-key-check"
    assert payload["findings"][1]["severity"] == "error"


def test_json_empty():
    payload = json.loads(to_json([]))
    assert payload == {
        "summary": {"findings": 0, "errors": 0, "warnings": 0},
        "findings": [],
    }


def test_markdown_table():
    output = to_markdown(SAMPLE)
    assert output.startswith("## apigee-bundle-lint: 2 issue(s)")
    assert "| warning | `missing-api-key-check` |" in output
    assert "| error | `target-no-url` |" in output


def test_markdown_empty():
    output = to_markdown([])
    assert "0 issue(s)" in output
    assert "No issues found." in output
