"""Load an Apigee API proxy bundle from disk.

A bundle is a directory holding an ``apiproxy`` folder:

    my-api/
      apiproxy/
        my-api.xml            # APIProxy root: policies, proxy and target lists
        policies/
          Verify-API-Key.xml  # one file per policy
        proxies/
          default.xml         # ProxyEndpoint files
        targets/
          default.xml         # TargetEndpoint files
        resources/
          jsc/
            transform.js

The loader accepts either the bundle directory or the ``apiproxy``
directory itself. Files that fail to parse as XML are reported as
``xml-parse`` findings instead of aborting the whole run, so one broken
file does not hide the rest of the bundle.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    """One lint result: a check name, a severity, and where it applies."""

    check: str
    severity: str  # "error" or "warning"
    message: str
    file: str = ""

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
        }


@dataclass
class Policy:
    name: str
    path: Path
    relpath: str
    root: ET.Element | None  # None when the file failed to parse

    @property
    def type(self) -> str | None:
        return self.root.tag if self.root is not None else None


@dataclass
class Endpoint:
    name: str
    path: Path
    relpath: str
    root: ET.Element | None  # None when the file failed to parse
    kind: str  # "proxy" or "target"


@dataclass
class Bundle:
    root: Path
    apiproxy_dir: Path
    api_name: str | None
    api_root_rel: str = ""
    declared_policies: list[str] = field(default_factory=list)
    policies: dict[str, Policy] = field(default_factory=dict)
    proxy_endpoints: list[Endpoint] = field(default_factory=list)
    target_endpoints: list[Endpoint] = field(default_factory=list)
    resources: set[str] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)

    def attached_policy_names(self) -> set[str]:
        """Policy names referenced by a Step in any endpoint flow."""
        names: set[str] = set()
        for endpoint in self.proxy_endpoints + self.target_endpoints:
            if endpoint.root is None:
                continue
            for step in endpoint.root.iter("Step"):
                name_el = step.find("Name")
                if name_el is not None and name_el.text:
                    names.add(name_el.text.strip())
        return names

    def attached_policies_of_type(self, *types: str) -> set[str]:
        """Names of attached policies whose type is one of ``types``."""
        attached = self.attached_policy_names()
        return {
            name
            for name in attached
            if name in self.policies
            and self.policies[name].type in types
        }


class BundleError(Exception):
    """The path is not an Apigee bundle at all."""


def _parse_xml(path: Path, relpath: str, findings: list[Finding]) -> ET.Element | None:
    try:
        return ET.parse(path).getroot()
    except ET.ParseError as exc:
        findings.append(
            Finding(
                check="xml-parse",
                severity="error",
                message=f"not valid XML: {exc}",
                file=relpath,
            )
        )
        return None


def _relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def load_bundle(path: str | Path) -> Bundle:
    """Load the bundle at ``path`` (bundle dir or ``apiproxy`` dir)."""
    given = Path(path)
    if given.name == "apiproxy" and given.is_dir():
        apiproxy_dir = given
        root = given.parent
    else:
        apiproxy_dir = given / "apiproxy"
        root = given
    if not apiproxy_dir.is_dir():
        raise BundleError(f"no apiproxy directory under {given}")

    findings: list[Finding] = []
    bundle = Bundle(root=root, apiproxy_dir=apiproxy_dir, api_name=None)

    root_files = sorted(apiproxy_dir.glob("*.xml"))
    api_root = None
    for candidate in root_files:
        rel = _relpath(candidate, root)
        parsed = _parse_xml(candidate, rel, findings)
        if parsed is not None and parsed.tag == "APIProxy":
            api_root = parsed
            bundle.api_name = parsed.get("name")
            bundle.api_root_rel = rel
    if api_root is None:
        raise BundleError(f"no APIProxy root file in {apiproxy_dir}")

    policies_el = api_root.find("Policies")
    if policies_el is not None:
        bundle.declared_policies = [
            el.text.strip()
            for el in policies_el.findall("Policy")
            if el.text and el.text.strip()
        ]

    policies_dir = apiproxy_dir / "policies"
    if policies_dir.is_dir():
        for policy_file in sorted(policies_dir.glob("*.xml")):
            rel = _relpath(policy_file, root)
            parsed = _parse_xml(policy_file, rel, findings)
            bundle.policies[policy_file.stem] = Policy(
                name=policy_file.stem,
                path=policy_file,
                relpath=rel,
                root=parsed,
            )

    for subdir, kind, target in (
        ("proxies", "proxy", bundle.proxy_endpoints),
        ("targets", "target", bundle.target_endpoints),
    ):
        endpoint_dir = apiproxy_dir / subdir
        if not endpoint_dir.is_dir():
            continue
        for endpoint_file in sorted(endpoint_dir.glob("*.xml")):
            rel = _relpath(endpoint_file, root)
            parsed = _parse_xml(endpoint_file, rel, findings)
            name = endpoint_file.stem
            if parsed is not None and parsed.get("name"):
                name = parsed.get("name")
            target.append(
                Endpoint(
                    name=name,
                    path=endpoint_file,
                    relpath=rel,
                    root=parsed,
                    kind=kind,
                )
            )

    resources_dir = apiproxy_dir / "resources"
    if resources_dir.is_dir():
        for resource_file in sorted(resources_dir.rglob("*")):
            if resource_file.is_file():
                bundle.resources.add(_relpath(resource_file, resources_dir))

    bundle.findings = findings
    return bundle
