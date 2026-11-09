# apigee-bundle-lint

Lint an Apigee API proxy bundle for common policy mistakes, before it
reaches an environment. A bundle that deploys fine can still be wrong:
a proxy with no API key check, a route rule that shadows the rest, a
quota that never fires because its time unit is misspelled. This tool
reads the bundle XML and reports those problems with file locations.

## Install

```bash
pip install apigee-bundle-lint
```

Or from source:

```bash
pip install -e .
```

## Use

```bash
apigee-bundle-lint path/to/my-api
apigee-bundle-lint path/to/my-api/apiproxy
apigee-bundle-lint --format json path/to/my-api
apigee-bundle-lint --ignore unused-policy,unlisted-policy path/to/my-api
```

Exit code is 0 when the bundle is clean, 1 when findings are reported,
and 2 on usage errors such as a missing directory or an unknown check
name. That makes it usable as a CI gate on proxy bundles.

## Example

`examples/good-bundle` is a small weather API that passes cleanly.
`examples/bad-bundle` is the same shape with mistakes planted in it.
Running the tool on the bad bundle prints:

```
error: apiproxy/broken-api.xml: [declared-policy-missing] policy 'Verify-API-Key' is declared in the APIProxy root but no policies/Verify-API-Key.xml exists
error: apiproxy/policies/Broken-Quota.xml: [quota-invalid] Quota policy 'Broken-Quota' has Interval '0', which is not a positive number
error: apiproxy/policies/Broken-Quota.xml: [quota-invalid] Quota policy 'Broken-Quota' has TimeUnit 'fortnight', which Apigee does not accept (minute, hour, day, week, month)
error: apiproxy/policies/Spike-Arrest.xml: [spike-arrest-invalid] SpikeArrest policy 'Spike-Arrest' has Rate 'fast', expected a number followed by ps (per second) or pm (per minute)
error: apiproxy/policies/Missing-Script.xml: [javascript-resource-missing] Javascript policy 'Missing-Script' references jsc://missing.js but no such file exists under apiproxy/resources/jsc/
error: apiproxy/proxies/default.xml: [dangling-policy] step references policy 'Ghost-Policy' but no policies/Ghost-Policy.xml exists
error: apiproxy/proxies/default.xml: [route-target-missing] RouteRule 'catch-all' routes to target endpoint 'nowhere' which does not exist
error: apiproxy/targets/broken.xml: [xml-parse] not valid XML: no element found: line 4, column 0
error: apiproxy/targets/default.xml: [target-no-url] HTTPTargetConnection has neither a URL nor a LoadBalancer: the target goes nowhere
warning: apiproxy/proxies/default.xml: [missing-api-key-check] no VerifyAPIKey or OAuthV2 VerifyAccessToken policy in the PreFlow request: the proxy accepts unauthenticated calls
warning: apiproxy/proxies/default.xml: [route-rule-shadow] RouteRule 'catch-all' has no Condition and is not the last rule, so it shadows every rule after it
warning: apiproxy/proxies/open.xml: [missing-rate-limit] no SpikeArrest or Quota policy in the PreFlow request: the proxy has no rate limiting
...

27 issue(s): 9 error(s), 18 warning(s)
```

## Checks

| Check | Severity | What it catches |
| --- | --- | --- |
| `xml-parse` | error | Any bundle XML file that is not valid XML |
| `dangling-policy` | error | A flow Step naming a policy with no file in `policies/` |
| `declared-policy-missing` | error | A policy declared in the APIProxy root with no file on disk |
| `unlisted-policy` | warning | A policy file not declared in the APIProxy root `<Policies>` list |
| `unused-policy` | warning | A policy file never attached to any endpoint flow |
| `policy-name-mismatch` | warning | The policy name inside the file differs from the file name |
| `missing-api-key-check` | warning | A proxy endpoint with no VerifyAPIKey or OAuthV2 VerifyAccessToken step in its PreFlow request |
| `missing-rate-limit` | warning | A proxy endpoint with no SpikeArrest or Quota step in its PreFlow request |
| `target-no-url` | error | A target endpoint whose connection has neither a URL nor a LoadBalancer |
| `base-path` | warning | A proxy endpoint with a missing BasePath, or one that does not start with `/` |
| `route-rule-shadow` | warning | A RouteRule with no Condition that is not the last rule, so it shadows the rules after it |
| `route-target-missing` | error | A RouteRule pointing at a target endpoint that does not exist |
| `fault-rules-missing` | warning | A target endpoint with no FaultRules, so backend errors surface unhandled |
| `raise-fault-no-response` | warning | A RaiseFault policy that sets no fault response status code |
| `quota-invalid` | error | A Quota policy with a missing or non-positive Interval, or a missing or invalid TimeUnit |
| `spike-arrest-invalid` | error | A SpikeArrest policy with a missing Rate, or one that is not a number followed by `ps` or `pm` |
| `service-callout-hardcoded-url` | warning | A ServiceCallout with a literal `http(s)` URL instead of a target server or flow variable |
| `javascript-resource-missing` | error | A Javascript policy whose `jsc://` resource file is not in `apiproxy/resources/jsc/` |

Run `apigee-bundle-lint --list-checks` to print the check names.

## Options

| Flag | Meaning |
| --- | --- |
| `--format text\|json\|markdown` | Output format (default text). JSON is a `summary` plus a `findings` list; Markdown is a table meant for a PR comment |
| `--ignore CHECK` | Check name to skip (repeatable, or comma-separated) |
| `--list-checks` | Print the check names and exit |

## Notes

- The bundle argument can be the bundle directory (the one holding
  `apiproxy/`) or the `apiproxy/` directory itself.
- A file that fails to parse still counts as one `xml-parse` error; the
  rest of the bundle is linted normally, so one broken file does not
  hide the other findings.
- OAuthV2 counts as an API key check only when its operation is
  `VerifyAccessToken`. A token-generation policy does not protect a
  proxy.
