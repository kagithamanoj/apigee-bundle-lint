"""Tests for loading a bundle from disk."""

from pathlib import Path

import pytest

from apigee_bundle_lint.loader import BundleError, load_bundle
from tests.conftest import minimal_files, write_bundle

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_load_minimal_bundle(tmp_path):
    bundle = load_bundle(write_bundle(tmp_path))
    assert bundle.api_name == "test-api"
    assert bundle.declared_policies == ["Verify-API-Key", "Spike-Arrest"]
    assert set(bundle.policies) == {"Verify-API-Key", "Spike-Arrest"}
    assert bundle.policies["Verify-API-Key"].type == "VerifyAPIKey"
    assert bundle.policies["Spike-Arrest"].type == "SpikeArrest"
    assert [endpoint.name for endpoint in bundle.proxy_endpoints] == ["default"]
    assert [endpoint.name for endpoint in bundle.target_endpoints] == ["default"]
    assert bundle.findings == []


def test_load_accepts_apiproxy_dir_directly(tmp_path):
    base = write_bundle(tmp_path)
    bundle = load_bundle(base / "apiproxy")
    assert bundle.api_name == "test-api"
    assert bundle.root == base


def test_load_good_example_bundle_is_clean():
    bundle = load_bundle(EXAMPLES / "good-bundle")
    assert bundle.api_name == "weather-api"
    assert len(bundle.policies) == 6
    assert bundle.resources == {"jsc/transform.js"}
    assert bundle.findings == []


def test_load_missing_apiproxy_dir(tmp_path):
    with pytest.raises(BundleError, match="no apiproxy directory"):
        load_bundle(tmp_path)


def test_load_no_api_proxy_root(tmp_path):
    files = minimal_files()
    files["apiproxy/test-api.xml"] = "<NotAnApiProxy/>"
    write_bundle(tmp_path, files)
    with pytest.raises(BundleError, match="no APIProxy root file"):
        load_bundle(tmp_path)


def test_load_records_xml_parse_error(tmp_path):
    files = minimal_files()
    files["apiproxy/policies/Spike-Arrest.xml"] = "<SpikeArrest><Rate>10ps"
    bundle = load_bundle(write_bundle(tmp_path, files))
    assert len(bundle.findings) == 1
    finding = bundle.findings[0]
    assert finding.check == "xml-parse"
    assert finding.severity == "error"
    assert "Spike-Arrest.xml" in finding.file
    assert bundle.policies["Spike-Arrest"].root is None


def test_attached_policy_names(tmp_path):
    bundle = load_bundle(write_bundle(tmp_path))
    assert bundle.attached_policy_names() == {"Verify-API-Key", "Spike-Arrest"}


def test_attached_policies_of_type(tmp_path):
    bundle = load_bundle(write_bundle(tmp_path))
    assert bundle.attached_policies_of_type("VerifyAPIKey") == {"Verify-API-Key"}
    assert bundle.attached_policies_of_type("Quota") == set()
