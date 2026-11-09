"""Checks over a loaded Apigee bundle.

Each check is a small function returning a list of findings. Checks are
registered in ``CHECKS`` so the CLI can list them and ``--ignore`` can
skip them by name.
"""

from __future__ import annotations

import re

from .loader import Bundle, Endpoint, Finding

RATE_RE = re.compile(r"^\d+(ps|pm)$")
TIME_UNITS = {"minute", "hour", "day", "week", "month"}
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _endpoint_steps(endpoint: Endpoint) -> list[str]:
    """Policy names referenced by Steps in one endpoint, in order."""
    names: list[str] = []
    if endpoint.root is None:
        return names
    for step in endpoint.root.iter("Step"):
        name_el = step.find("Name")
        if name_el is not None and name_el.text:
            names.append(name_el.text.strip())
    return names


def _preflow_request_steps(endpoint: Endpoint) -> list[str]:
    """Policy names in the PreFlow Request section of one endpoint."""
    names: list[str] = []
    if endpoint.root is None:
        return names
    preflow = endpoint.root.find("PreFlow")
    if preflow is None:
        return names
    request = preflow.find("Request")
    if request is None:
        return names
    for step in request.findall("Step"):
        name_el = step.find("Name")
        if name_el is not None and name_el.text:
            names.append(name_el.text.strip())
    return names


def _is_oauth_verify(policy_root) -> bool:
    if policy_root is None or policy_root.tag != "OAuthV2":
        return False
    operation = policy_root.find("Operation")
    return operation is not None and operation.text == "VerifyAccessToken"


def check_dangling_policy(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.proxy_endpoints + bundle.target_endpoints:
        for name in _endpoint_steps(endpoint):
            if name not in bundle.policies:
                findings.append(
                    Finding(
                        check="dangling-policy",
                        severity="error",
                        message=(
                            f"step references policy '{name}' but no "
                            f"policies/{name}.xml exists"
                        ),
                        file=endpoint.relpath,
                    )
                )
    return findings


def check_declared_policy_missing(bundle: Bundle) -> list[Finding]:
    return [
        Finding(
            check="declared-policy-missing",
            severity="error",
            message=(
                f"policy '{name}' is declared in the APIProxy root but "
                f"no policies/{name}.xml exists"
            ),
            file=bundle.api_root_rel,
        )
        for name in bundle.declared_policies
        if name not in bundle.policies
    ]


def check_unlisted_policy(bundle: Bundle) -> list[Finding]:
    return [
        Finding(
            check="unlisted-policy",
            severity="warning",
            message=(
                f"policy '{name}' exists on disk but is not declared in "
                "the APIProxy root <Policies> list"
            ),
            file=policy.relpath,
        )
        for name, policy in bundle.policies.items()
        if name not in bundle.declared_policies
    ]


def check_unused_policy(bundle: Bundle) -> list[Finding]:
    attached = bundle.attached_policy_names()
    return [
        Finding(
            check="unused-policy",
            severity="warning",
            message=f"policy '{name}' is never attached to any endpoint",
            file=policy.relpath,
        )
        for name, policy in bundle.policies.items()
        if name not in attached
    ]


def check_policy_name_mismatch(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for name, policy in bundle.policies.items():
        if policy.root is None:
            continue
        declared = policy.root.get("name")
        if declared is not None and declared != name:
            findings.append(
                Finding(
                    check="policy-name-mismatch",
                    severity="warning",
                    message=(
                        f"file is named {name}.xml but the policy inside "
                        f"is named '{declared}'"
                    ),
                    file=policy.relpath,
                )
            )
    return findings


def check_missing_api_key_check(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.proxy_endpoints:
        steps = _preflow_request_steps(endpoint)
        protected = False
        for name in steps:
            policy = bundle.policies.get(name)
            if policy is None or policy.root is None:
                continue
            if policy.type == "VerifyAPIKey" or _is_oauth_verify(policy.root):
                protected = True
                break
        if not protected:
            findings.append(
                Finding(
                    check="missing-api-key-check",
                    severity="warning",
                    message=(
                        "no VerifyAPIKey or OAuthV2 VerifyAccessToken "
                        "policy in the PreFlow request: the proxy accepts "
                        "unauthenticated calls"
                    ),
                    file=endpoint.relpath,
                )
            )
    return findings


def check_missing_rate_limit(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.proxy_endpoints:
        steps = _preflow_request_steps(endpoint)
        limited = any(
            bundle.policies.get(name) is not None
            and bundle.policies[name].type in ("SpikeArrest", "Quota")
            for name in steps
        )
        if not limited:
            findings.append(
                Finding(
                    check="missing-rate-limit",
                    severity="warning",
                    message=(
                        "no SpikeArrest or Quota policy in the PreFlow "
                        "request: the proxy has no rate limiting"
                    ),
                    file=endpoint.relpath,
                )
            )
    return findings


def check_target_no_url(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.target_endpoints:
        if endpoint.root is None:
            continue
        connection = endpoint.root.find("HTTPTargetConnection")
        if connection is None:
            findings.append(
                Finding(
                    check="target-no-url",
                    severity="error",
                    message="target endpoint has no HTTPTargetConnection",
                    file=endpoint.relpath,
                )
            )
            continue
        url = connection.find("URL")
        load_balancer = connection.find("LoadBalancer")
        has_url = url is not None and url.text and url.text.strip()
        has_lb = load_balancer is not None
        if not has_url and not has_lb:
            findings.append(
                Finding(
                    check="target-no-url",
                    severity="error",
                    message=(
                        "HTTPTargetConnection has neither a URL nor a "
                        "LoadBalancer: the target goes nowhere"
                    ),
                    file=endpoint.relpath,
                )
            )
    return findings


def check_base_path(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.proxy_endpoints:
        if endpoint.root is None:
            continue
        connection = endpoint.root.find("HTTPProxyConnection")
        if connection is None:
            findings.append(
                Finding(
                    check="base-path",
                    severity="warning",
                    message="proxy endpoint has no HTTPProxyConnection",
                    file=endpoint.relpath,
                )
            )
            continue
        base_path = connection.find("BasePath")
        if base_path is None or not base_path.text or not base_path.text.strip():
            findings.append(
                Finding(
                    check="base-path",
                    severity="warning",
                    message="proxy endpoint has no BasePath",
                    file=endpoint.relpath,
                )
            )
        elif not base_path.text.strip().startswith("/"):
            findings.append(
                Finding(
                    check="base-path",
                    severity="warning",
                    message=(
                        f"BasePath '{base_path.text.strip()}' does not "
                        "start with '/'"
                    ),
                    file=endpoint.relpath,
                )
            )
    return findings


def check_route_rule_shadow(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.proxy_endpoints:
        if endpoint.root is None:
            continue
        rules = endpoint.root.findall("RouteRule")
        for index, rule in enumerate(rules):
            if rule.find("Condition") is None and index < len(rules) - 1:
                findings.append(
                    Finding(
                        check="route-rule-shadow",
                        severity="warning",
                        message=(
                            f"RouteRule '{rule.get('name')}' has no "
                            "Condition and is not the last rule, so it "
                            "shadows every rule after it"
                        ),
                        file=endpoint.relpath,
                    )
                )
    return findings


def check_route_target_missing(bundle: Bundle) -> list[Finding]:
    known = {endpoint.name for endpoint in bundle.target_endpoints}
    findings: list[Finding] = []
    for endpoint in bundle.proxy_endpoints:
        if endpoint.root is None:
            continue
        for rule in endpoint.root.findall("RouteRule"):
            target_el = rule.find("TargetEndpoint")
            if target_el is not None and target_el.text:
                target = target_el.text.strip()
                if target not in known:
                    findings.append(
                        Finding(
                            check="route-target-missing",
                            severity="error",
                            message=(
                                f"RouteRule '{rule.get('name')}' routes to "
                                f"target endpoint '{target}' which does "
                                "not exist"
                            ),
                            file=endpoint.relpath,
                        )
                    )
    return findings


def check_fault_rules_missing(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in bundle.target_endpoints:
        if endpoint.root is None:
            continue
        if endpoint.root.find("FaultRules") is None:
            findings.append(
                Finding(
                    check="fault-rules-missing",
                    severity="warning",
                    message=(
                        "target endpoint has no FaultRules: backend "
                        "errors surface to callers unhandled"
                    ),
                    file=endpoint.relpath,
                )
            )
    return findings


def check_raise_fault_no_response(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for name, policy in bundle.policies.items():
        if policy.root is None or policy.type != "RaiseFault":
            continue
        fault_response = policy.root.find("FaultResponse")
        status = None
        if fault_response is not None:
            set_el = fault_response.find("Set")
            if set_el is not None:
                status_el = set_el.find("StatusCode")
                if status_el is not None and status_el.text:
                    status = status_el.text.strip()
        if status is None:
            findings.append(
                Finding(
                    check="raise-fault-no-response",
                    severity="warning",
                    message=(
                        f"RaiseFault policy '{name}' sets no fault "
                        "response status code, so callers get a bare "
                        "500 with no body"
                    ),
                    file=policy.relpath,
                )
            )
    return findings


def check_quota_invalid(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for name, policy in bundle.policies.items():
        if policy.root is None or policy.type != "Quota":
            continue
        interval = policy.root.find("Interval")
        time_unit = policy.root.find("TimeUnit")
        if interval is None or not interval.text or not interval.text.strip():
            findings.append(
                Finding(
                    check="quota-invalid",
                    severity="error",
                    message=f"Quota policy '{name}' has no Interval",
                    file=policy.relpath,
                )
            )
        else:
            try:
                value = int(interval.text.strip())
            except ValueError:
                value = 0
            if value <= 0:
                findings.append(
                    Finding(
                        check="quota-invalid",
                        severity="error",
                        message=(
                            f"Quota policy '{name}' has Interval "
                            f"'{interval.text.strip()}', which is not a "
                            "positive number"
                        ),
                        file=policy.relpath,
                    )
                )
        if time_unit is None or not time_unit.text or not time_unit.text.strip():
            findings.append(
                Finding(
                    check="quota-invalid",
                    severity="error",
                    message=f"Quota policy '{name}' has no TimeUnit",
                    file=policy.relpath,
                )
            )
        elif time_unit.text.strip() not in TIME_UNITS:
            findings.append(
                Finding(
                    check="quota-invalid",
                    severity="error",
                    message=(
                        f"Quota policy '{name}' has TimeUnit "
                        f"'{time_unit.text.strip()}', which Apigee does "
                        "not accept (minute, hour, day, week, month)"
                    ),
                    file=policy.relpath,
                )
            )
    return findings


def check_spike_arrest_invalid(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for name, policy in bundle.policies.items():
        if policy.root is None or policy.type != "SpikeArrest":
            continue
        rate = policy.root.find("Rate")
        if rate is None or not rate.text or not rate.text.strip():
            findings.append(
                Finding(
                    check="spike-arrest-invalid",
                    severity="error",
                    message=f"SpikeArrest policy '{name}' has no Rate",
                    file=policy.relpath,
                )
            )
        elif not RATE_RE.match(rate.text.strip()):
            findings.append(
                Finding(
                    check="spike-arrest-invalid",
                    severity="error",
                    message=(
                        f"SpikeArrest policy '{name}' has Rate "
                        f"'{rate.text.strip()}', expected a number "
                        "followed by ps (per second) or pm (per minute)"
                    ),
                    file=policy.relpath,
                )
            )
    return findings


def check_service_callout_hardcoded_url(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for name, policy in bundle.policies.items():
        if policy.root is None or policy.type != "ServiceCallout":
            continue
        connection = policy.root.find("HTTPTargetConnection")
        if connection is None:
            continue
        url = connection.find("URL")
        if url is not None and url.text and URL_RE.match(url.text.strip()):
            findings.append(
                Finding(
                    check="service-callout-hardcoded-url",
                    severity="warning",
                    message=(
                        f"ServiceCallout policy '{name}' hardcodes "
                        f"'{url.text.strip()}': use a target server or "
                        "a flow variable so the URL is not baked into "
                        "the bundle"
                    ),
                    file=policy.relpath,
                )
            )
    return findings


def check_javascript_resource_missing(bundle: Bundle) -> list[Finding]:
    findings: list[Finding] = []
    for name, policy in bundle.policies.items():
        if policy.root is None or policy.type != "Javascript":
            continue
        resource = policy.root.find("ResourceURL")
        if resource is None or not resource.text:
            continue
        ref = resource.text.strip()
        if not ref.startswith("jsc://"):
            continue
        filename = ref[len("jsc://"):]
        if f"jsc/{filename}" not in bundle.resources:
            findings.append(
                Finding(
                    check="javascript-resource-missing",
                    severity="error",
                    message=(
                        f"Javascript policy '{name}' references "
                        f"jsc://{filename} but no such file exists "
                        "under apiproxy/resources/jsc/"
                    ),
                    file=policy.relpath,
                )
            )
    return findings


CHECKS = (
    check_dangling_policy,
    check_declared_policy_missing,
    check_unlisted_policy,
    check_unused_policy,
    check_policy_name_mismatch,
    check_missing_api_key_check,
    check_missing_rate_limit,
    check_target_no_url,
    check_base_path,
    check_route_rule_shadow,
    check_route_target_missing,
    check_fault_rules_missing,
    check_raise_fault_no_response,
    check_quota_invalid,
    check_spike_arrest_invalid,
    check_service_callout_hardcoded_url,
    check_javascript_resource_missing,
)

def _check_name(check) -> str:
    return check.__name__[len("check_"):].replace("_", "-")


CHECK_NAMES = tuple(_check_name(check) for check in CHECKS)


def run_checks(bundle: Bundle, ignore: tuple[str, ...] = ()) -> list[Finding]:
    """Run every check over the bundle, skipping any named in ``ignore``."""
    ignored = set(ignore)
    findings = list(bundle.findings)
    for check in CHECKS:
        if _check_name(check) in ignored:
            continue
        findings.extend(check(bundle))
    findings.sort(key=lambda item: (item.file, item.check, item.message))
    return findings
