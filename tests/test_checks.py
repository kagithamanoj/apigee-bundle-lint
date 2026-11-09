"""Tests for every lint check, plus the example bundles end to end."""

from pathlib import Path

from apigee_bundle_lint.checks import CHECK_NAMES, run_checks
from apigee_bundle_lint.loader import load_bundle
from tests.conftest import minimal_files, write_bundle

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _checks(bundle) -> dict[str, list]:
    found: dict[str, list] = {}
    for item in run_checks(bundle):
        found.setdefault(item.check, []).append(item)
    return found


def test_good_bundle_has_no_findings():
    assert run_checks(load_bundle(EXAMPLES / "good-bundle")) == []


def test_bad_bundle_finds_expected_checks():
    found = _checks(load_bundle(EXAMPLES / "bad-bundle"))
    expected = {
        "xml-parse",
        "dangling-policy",
        "declared-policy-missing",
        "unlisted-policy",
        "unused-policy",
        "policy-name-mismatch",
        "missing-api-key-check",
        "missing-rate-limit",
        "target-no-url",
        "base-path",
        "route-rule-shadow",
        "route-target-missing",
        "fault-rules-missing",
        "raise-fault-no-response",
        "quota-invalid",
        "spike-arrest-invalid",
        "service-callout-hardcoded-url",
        "javascript-resource-missing",
    }
    assert set(found) == expected


def test_bad_bundle_quota_reports_both_problems():
    found = _checks(load_bundle(EXAMPLES / "bad-bundle"))
    messages = [item.message for item in found["quota-invalid"]]
    assert any("Interval '0'" in message for message in messages)
    assert any("TimeUnit 'fortnight'" in message for message in messages)


def test_bad_bundle_missing_key_check_hits_both_proxies():
    found = _checks(load_bundle(EXAMPLES / "bad-bundle"))
    files = {item.file for item in found["missing-api-key-check"]}
    assert files == {
        "apiproxy/proxies/default.xml",
        "apiproxy/proxies/open.xml",
    }


def test_dangling_policy(tmp_path):
    files = minimal_files()
    files["apiproxy/proxies/default.xml"] = files[
        "apiproxy/proxies/default.xml"
    ].replace(
        "<Name>Spike-Arrest</Name>", "<Name>No-Such-Policy</Name>"
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["dangling-policy"]) == 1
    assert "No-Such-Policy" in found["dangling-policy"][0].message
    assert found["dangling-policy"][0].severity == "error"


def test_declared_policy_missing(tmp_path):
    files = minimal_files()
    files["apiproxy/test-api.xml"] = files["apiproxy/test-api.xml"].replace(
        "<Policy>Spike-Arrest</Policy>",
        "<Policy>Spike-Arrest</Policy><Policy>Ghost</Policy>",
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert [item.message for item in found["declared-policy-missing"]] == [
        "policy 'Ghost' is declared in the APIProxy root but "
        "no policies/Ghost.xml exists"
    ]
    assert found["declared-policy-missing"][0].file == "apiproxy/test-api.xml"


def test_unlisted_and_unused_policy(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Orphan.xml"] = (
        '<AssignMessage name="Orphan"><Set/></AssignMessage>'
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["unlisted-policy"]) == 1
    assert "Orphan" in found["unlisted-policy"][0].message
    assert len(found["unused-policy"]) == 1
    assert "Orphan" in found["unused-policy"][0].message


def test_policy_name_mismatch(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = (
        '<SpikeArrest name="Something-Else"><Rate>10ps</Rate></SpikeArrest>'
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["policy-name-mismatch"]) == 1
    assert "Something-Else" in found["policy-name-mismatch"][0].message


def test_oauth_verify_counts_as_api_key_check(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Verify-API-Key.xml"] = (
        '<OAuthV2 name="Verify-API-Key">'
        "<Operation>VerifyAccessToken</Operation>"
        "</OAuthV2>"
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert "missing-api-key-check" not in found


def test_oauth_generate_token_does_not_count(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Verify-API-Key.xml"] = (
        '<OAuthV2 name="Verify-API-Key">'
        "<Operation>GenerateAccessToken</Operation>"
        "</OAuthV2>"
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["missing-api-key-check"]) == 1


def test_quota_satisfies_rate_limit(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = (
        '<Quota name="Spike-Arrest"><Interval>1</Interval>'
        "<TimeUnit>minute</TimeUnit></Quota>"
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert "missing-rate-limit" not in found
    assert "quota-invalid" not in found


def test_quota_missing_interval_and_time_unit(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = (
        '<Quota name="Spike-Arrest"></Quota>'
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["quota-invalid"]) == 2


def test_spike_arrest_rate_formats(tmp_path):
    for rate, valid in (("30ps", True), ("10pm", True), ("30", False),
                        ("30ph", False), ("", False)):
        files = minimal_files()
        files["apiproxy/policies/Spike-Arrest.xml"] = (
            f'<SpikeArrest name="Spike-Arrest"><Rate>{rate}</Rate></SpikeArrest>'
        )
        found = _checks(load_bundle(write_bundle(tmp_path, files)))
        if valid:
            assert "spike-arrest-invalid" not in found, rate
        else:
            assert len(found["spike-arrest-invalid"]) == 1, rate


def test_target_with_load_balancer_is_fine(tmp_path):
    files = minimal_files()
    files["apiproxy/targets/default.xml"] = (
        files["apiproxy/targets/default.xml"]
        .replace(
            "<URL>https://backend.example.com</URL>",
            "<LoadBalancer><Server name=\"backend\"/></LoadBalancer>",
        )
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert "target-no-url" not in found


def test_target_without_connection(tmp_path):
    files = minimal_files()
    files["apiproxy/targets/default.xml"] = (
        '<TargetEndpoint name="default"><PreFlow/></TargetEndpoint>'
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["target-no-url"]) == 1
    assert "no HTTPTargetConnection" in found["target-no-url"][0].message
    assert len(found["fault-rules-missing"]) == 1


def test_base_path_variants(tmp_path):
    files = minimal_files()
    files["apiproxy/proxies/default.xml"] = files[
        "apiproxy/proxies/default.xml"
    ].replace("<BasePath>/v1/api</BasePath>", "<BasePath>v1/api</BasePath>")
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["base-path"]) == 1
    assert "does not start with '/'" in found["base-path"][0].message


def test_route_rule_shadow_only_when_not_last(tmp_path):
    files = minimal_files()
    proxy = files["apiproxy/proxies/default.xml"]
    proxy = proxy.replace(
        """  <RouteRule name="default">
    <TargetEndpoint>default</TargetEndpoint>
  </RouteRule>""",
        """  <RouteRule name="first">
    <TargetEndpoint>default</TargetEndpoint>
  </RouteRule>
  <RouteRule name="second">
    <Condition>proxy.pathsuffix = "/x"</Condition>
    <TargetEndpoint>default</TargetEndpoint>
  </RouteRule>
  <RouteRule name="default">
    <TargetEndpoint>default</TargetEndpoint>
  </RouteRule>""",
    )
    files["apiproxy/proxies/default.xml"] = proxy
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert len(found["route-rule-shadow"]) == 1
    assert "'first'" in found["route-rule-shadow"][0].message


def test_raise_fault_with_status_is_fine(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = (
        '<RaiseFault name="Spike-Arrest"><FaultResponse><Set>'
        "<StatusCode>429</StatusCode></Set></FaultResponse></RaiseFault>"
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert "raise-fault-no-response" not in found


def test_service_callout_variable_url_is_fine(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = (
        '<ServiceCallout name="Spike-Arrest"><HTTPTargetConnection>'
        "<URL>{callout.url}</URL></HTTPTargetConnection></ServiceCallout>"
    )
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert "service-callout-hardcoded-url" not in found


def test_javascript_resource_present_is_fine(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = (
        '<Javascript name="Spike-Arrest">'
        "<ResourceURL>jsc://helper.js</ResourceURL></Javascript>"
    )
    files["apiproxy/resources/jsc/helper.js"] = "var x = 1;"
    found = _checks(load_bundle(write_bundle(tmp_path, files)))
    assert "javascript-resource-missing" not in found


def test_ignore_skips_named_check(tmp_path):
    bundle = load_bundle(write_bundle(tmp_path))
    found = run_checks(bundle, ignore=("missing-api-key-check",))
    assert all(item.check != "missing-api-key-check" for item in found)


def test_check_names_match_checks():
    assert len(CHECK_NAMES) == 17
    assert "missing-api-key-check" in CHECK_NAMES
    assert "xml-parse" not in CHECK_NAMES  # raised by the loader, not a check
