"""Tests for the CLI: exit codes, formats, --ignore, --list-checks."""

import json
from pathlib import Path

from apigee_bundle_lint.cli import main
from tests.conftest import write_bundle

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_good_bundle_exits_zero(capsys):
    assert main([str(EXAMPLES / "good-bundle")]) == 0
    assert "No issues found." in capsys.readouterr().out


def test_bad_bundle_exits_one(capsys):
    assert main([str(EXAMPLES / "bad-bundle")]) == 1
    assert "issue(s)" in capsys.readouterr().out


def test_missing_bundle_exits_two(capsys):
    assert main([str(EXAMPLES / "no-such-bundle")]) == 2
    assert "no apiproxy directory" in capsys.readouterr().err


def test_not_a_bundle_file_exits_two(tmp_path, capsys):
    target = tmp_path / "plain.txt"
    target.write_text("hello")
    assert main([str(target)]) == 2


def test_json_format_parses(capsys):
    assert main([str(EXAMPLES / "bad-bundle"), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["errors"] >= 1
    assert payload["summary"]["warnings"] >= 1
    assert all("check" in item for item in payload["findings"])


def test_markdown_format(capsys):
    assert main([str(EXAMPLES / "bad-bundle"), "--format", "markdown"]) == 1
    assert capsys.readouterr().out.startswith("## apigee-bundle-lint:")


def test_ignore_removes_findings(tmp_path, capsys):
    from tests.conftest import minimal_files

    files = minimal_files()
    files["apiproxy/proxies/default.xml"] = files[
        "apiproxy/proxies/default.xml"
    ].replace("<Step><Name>Verify-API-Key</Name></Step>\n      ", "")
    bundle = write_bundle(tmp_path, files)
    assert main([str(bundle)]) == 1
    # Ignoring only the key check still leaves the now-unused policy.
    assert main([str(bundle), "--ignore", "missing-api-key-check"]) == 1
    assert main(
        [str(bundle), "--ignore", "missing-api-key-check,unused-policy"]
    ) == 0


def test_ignore_comma_separated_and_unknown(tmp_path, capsys):
    bundle = write_bundle(tmp_path)
    assert main([str(bundle), "--ignore", "missing-api-key-check,missing-rate-limit"]) == 0
    assert main([str(bundle), "--ignore", "no-such-check"]) == 2
    assert "unknown check(s)" in capsys.readouterr().err


def test_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    listed = capsys.readouterr().out.splitlines()
    assert "missing-api-key-check" in listed
    assert "spike-arrest-invalid" in listed


def test_cli_accepts_apiproxy_dir(capsys):
    assert main([str(EXAMPLES / "good-bundle" / "apiproxy")]) == 0
