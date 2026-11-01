# cedar-auth-engine

A portable MoonBit authorization library and native CLI for a documented
subset of Cedar. Given a principal, action, resource, context and entity graph,
it returns a decision, determining policy IDs and per-policy errors.

```cedar
permit(principal in Group::"editors", action == Action::"view", resource)
when { context.authenticated && resource.owner == principal };
```

The host application supplies the request and entity data. Policy evaluation
does not access the filesystem, network, clock, identity provider or database.

## Run from source

With MoonBit `moon 0.1.20261028` / `moonc v0.10.18` and Python 3.8 or newer:

```sh
moon build cmd/cedar-auth-engine --target native
moon install ./cmd/cedar-auth-engine
moon run cmd/cedar-auth-engine --target native -- check examples/tenant/policy.cedar
moon run cmd/cedar-auth-engine --target native -- test examples/tenant/policy.cedar examples/tenant/entities.json examples/tenant/requests.json --format json
moon run cmd/cedar-auth-engine --target native -- test examples/sharing/policy.cedar examples/sharing/entities.json examples/sharing/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/admin/policy.cedar examples/admin/entities.json examples/admin/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/risk/policy.cedar examples/risk/entities.json examples/risk/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/classified/policy.cedar examples/classified/entities.json examples/classified/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/invoices/policy.cedar examples/invoices/entities.json examples/invoices/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/quota/policy.cedar examples/quota/entities.json examples/quota/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/network/policy.cedar examples/network/entities.json examples/network/requests.json
python scripts/smoke.py
```

`check POLICY` checks the supported syntax. With `--format json`, it also
returns each policy ID, effect and annotations. `authorize POLICY ENTITIES REQUEST`
evaluates one request. `test POLICY ENTITIES CASES` evaluates an array of
objects containing `request` and expected `decision` fields. Each command
accepts `--format json`; text is the default. An authorization decision of
`Deny` is a normal result and exits 0. The test command exits 1 for a decision
mismatch or any evaluation error; malformed input or usage exits 2.

The request uses `principal`, `action` and `resource` objects with `type` and
`id`, plus a `context` object. Entities are an array of `uid`, `attrs`, and
`parents`; entity-valued attributes use `{"__entity":{"type":"User","id":"alice"}}`.
See [examples](examples/) for complete inputs. Duplicate JSON keys, unsupported
extension values other than IP, nulls, invalid integers and malformed input are
rejected. IP input uses `{"__extn":{"fn":"ip","arg":"10.1.2.3"}}` in
entity attributes or request context. For client source addresses, the host
must supply a trustworthy individual IP address; forwarded headers require
validation by the application or proxy.

## Use the library

The module has not been published to Mooncakes. To consume a checkout, add it
to a local MoonBit workspace and import `shen-E/cedar-auth-engine/engine`.

```moonbit
let policies = @engine.parse_policies(
  "permit(principal, action == Action::\"read\", resource);",
)
let request = @engine.Request::{
  principal: { kind: "User", id: "alice" },
  action: { kind: "Action", id: "read" },
  resource: { kind: "File", id: "report" },
  context: {},
}
let response = @engine.authorize(policies, request, [])
```

`parse_json`, `request_from_json`, `entities_from_json` and `response_to_json`
provide the JSON boundary. Use `parse_json` for text input to detect duplicate
keys; duplicate keys are already lost if a caller supplies an independently
parsed `Json` value. The caller can alternatively construct typed values,
including `@engine.IpValue(@engine.IpAddress::parse("2001:db8::1"))`.
`policies.metadata()` returns IDs, effects and independent copies of annotation
maps in policy order. Use the IDs in `reasons` and `errors` to find the
corresponding metadata.

## Supported policy profile

- Static `permit` and `forbid` policies, scope equality and entity ancestry,
  principal and resource type restrictions (`is`, optionally with `in`),
  `when` and `unless`. Annotations appear before the policy effect. As in the
  Cedar CLI, `@id("name")` sets the policy ID; otherwise IDs are `policy0`,
  `policy1`, and so on. Duplicate annotations or policy IDs are rejected.
  Annotations are metadata and do not change authorization decisions.
- Principal, action, resource and context; entity attributes and parent links;
  boolean, signed 64-bit integer, string, entity, set and record values.
- `==`, `!=`, `in`, `has`, `!`, `&&`, `||`, integer ordering (`<`, `<=`, `>`,
  `>=`), attribute access, set and record literals. Sets compare without regard
  to order and duplicate members.
- Signed 64-bit addition, subtraction, multiplication and unary negation.
  Overflow and incompatible operands cause evaluation errors. Division is not supported.
- Set methods `.contains(value)`, `.containsAll(set)`, `.containsAny(set)` and
  `.isEmpty()`. Incorrect operand types produce policy evaluation errors.
- Cedar `ip(string)` values for IPv4 and IPv6 addresses and CIDR ranges,
  `.isIpv4()`, `.isIpv6()`, `.isLoopback()`, `.isMulticast()` and
  `.isInRange(ip)`. Classification and range inclusion require
  the entire receiver range to fit; different address families do not match.
  IPv6 uses hexadecimal groups; dotted IPv4-in-IPv6 notation is rejected.
  Invalid addresses and incorrect operand types produce policy errors.
- Entity type tests, `if ... then ... else ...` expressions, quoted `has`
  attributes and string-literal indexing such as `context["tenant-id"]`.
  Conditional expressions evaluate only the selected branch.
- String `like` patterns with `*` matching any sequence and `\*` matching a
  literal asterisk. Matching is case-sensitive and uses literal Unicode values;
  it does not normalize strings or interpret paths or URLs.
- Cedar string escapes include `\"`, `\\`, `\n`, `\r`, `\t`, `\0`, ASCII
  `\xHH` and Unicode `\u{...}`. JSON-only escapes such as `\u0041` are rejected
  in policies; JSON input retains standard JSON escaping.
- Default deny, forbid overrides permit, and evaluation errors skip the
  affected policy while appearing in `errors`, as in Cedar. Applications that
  require a decision with no evaluation errors must inspect `errors` before
  enforcing an `Allow` result.

Unsupported policy syntax is rejected rather than ignored. The profile does
not implement Cedar schema validation, templates, or extension types besides
IP. Policy checks are syntax/profile checks, not schema validation.
The CLI reads UTF-8 regular files up to 1 MiB; the parser limits input to
2,048 tokens, expression nesting to 128, arithmetic chains to 128 operators,
JSON nesting to 64, and authorization to 4,096 entities and 65,536 parent
links. Limits raise errors instead of
returning a partial decision.

## Verify

```sh
moon check --target all
moon test --target all
moon fmt --check
moon info --target all
moon build cmd/cedar-auth-engine --target native
python scripts/smoke.py
python scripts/verify.py --cedar /path/to/cedar --engine /path/to/cedar-auth-engine
```

The reference script requires `cedar-policy-cli 4.13.0`. It compares the
decision, determining policy IDs and error policy IDs with the official CLI,
including selected [upstream fixtures](fixtures/cedar/README.md), local
examples and error/condition cases. It reports mismatches and exits nonzero.
IP range cases are also checked against Python `ipaddress` with a fixed seed.
The MoonBit tests also compare wildcard matching against an independent
exhaustive oracle over 41,261 short pattern/input pairs per backend.
On Windows, the checked toolchain was `moon 0.1.20261028` / `moonc v0.10.18`;
the current comparison ran 433 requests and 24 invalid-syntax cases with no
mismatches. This is evidence for the selected cases, not a claim of full Cedar
conformance.

Apache-2.0. The upstream fixtures retain their own license and attribution.
