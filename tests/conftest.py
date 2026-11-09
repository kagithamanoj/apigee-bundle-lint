"""Shared helpers for building small bundles under tmp_path."""

from pathlib import Path

API_ROOT = """<APIProxy name="test-api">
  <Policies>
    <Policy>Verify-API-Key</Policy>
    <Policy>Spike-Arrest</Policy>
  </Policies>
  <ProxyEndpoints>
    <ProxyEndpoint>default</ProxyEndpoint>
  </ProxyEndpoints>
  <TargetEndpoints>
    <TargetEndpoint>default</TargetEndpoint>
  </TargetEndpoints>
</APIProxy>
"""

VERIFY_KEY = """<VerifyAPIKey name="Verify-API-Key">
  <APIKey ref="request.queryparam.apikey"/>
</VerifyAPIKey>
"""

SPIKE_ARREST = """<SpikeArrest name="Spike-Arrest">
  <Rate>10ps</Rate>
</SpikeArrest>
"""

PROXY = """<ProxyEndpoint name="default">
  <PreFlow name="PreFlow">
    <Request>
      <Step><Name>Verify-API-Key</Name></Step>
      <Step><Name>Spike-Arrest</Name></Step>
    </Request>
    <Response/>
  </PreFlow>
  <HTTPProxyConnection>
    <BasePath>/v1/api</BasePath>
  </HTTPProxyConnection>
  <RouteRule name="default">
    <TargetEndpoint>default</TargetEndpoint>
  </RouteRule>
</ProxyEndpoint>
"""

TARGET = """<TargetEndpoint name="default">
  <PreFlow name="PreFlow">
    <Request/>
    <Response/>
  </PreFlow>
  <HTTPTargetConnection>
    <URL>https://backend.example.com</URL>
  </HTTPTargetConnection>
  <FaultRules>
    <FaultRule name="default">
      <Step><Name>Spike-Arrest</Name></Step>
    </FaultRule>
  </FaultRules>
</TargetEndpoint>
"""


def minimal_files() -> dict[str, str]:
    return {
        "apiproxy/test-api.xml": API_ROOT,
        "apiproxy/policies/Verify-API-Key.xml": VERIFY_KEY,
        "apiproxy/policies/Spike-Arrest.xml": SPIKE_ARREST,
        "apiproxy/proxies/default.xml": PROXY,
        "apiproxy/targets/default.xml": TARGET,
    }


def write_bundle(base: Path, files: dict[str, str] | None = None) -> Path:
    """Write ``files`` under ``base`` and return the bundle directory."""
    for rel, content in (files if files is not None else minimal_files()).items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return base
