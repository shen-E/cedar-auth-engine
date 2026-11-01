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
python scripts/smoke.py
```

`check POLICY` checks the supported syntax. `authorize POLICY ENTITIES REQUEST`
evaluates one request. `test POLICY ENTITIES CASES` evaluates an array of
objects containing `request` and expected `decision` fields. Each command
accepts `--format json`; text is the default. An authorization decision of
`Deny` is a normal result and exits 0. The test command exits 1 for a decision
mismatch or any evaluation error; malformed input or usage exits 2.

The request uses `principal`, `action` and `resource` objects with `type` and
`id`, plus a `context` object. Entities are an array of `uid`, `attrs`, and
`parents`; entity-valued attributes use `{"__entity":{"type":"User","id":"alice"}}`.
See [examples](examples/) for complete inputs. Duplicate JSON keys, unsupported
extension values, nulls, invalid integers and malformed input are rejected.

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
parsed `Json` value. The caller can alternatively construct typed values.

## Supported policy profile

- Static `permit` and `forbid` policies, scope equality and entity ancestry,
  principal and resource type restrictions (`is`, optionally with `in`),
  `when` and `unless`, with policy IDs `policy0`, `policy1`, and so on.
- Principal, action, resource and context; entity attributes and parent links;
  boolean, signed 64-bit integer, string, entity, set and record values.
- `==`, `!=`, `in`, `has`, `!`, `&&`, `||`, integer ordering (`<`, `<=`, `>`,
  `>=`), attribute access, set and record literals. Sets compare without regard
  to order and duplicate members.
- Set methods `.contains(value)`, `.containsAll(set)`, `.containsAny(set)` and
  `.isEmpty()`. Incorrect operand types produce policy evaluation errors.
- Entity type tests, `if ... then ... else ...` expressions, quoted `has`
  attributes and string-literal indexing such as `context["tenant-id"]`.
  Conditional expressions evaluate only the selected branch.
- Default deny, forbid overrides permit, and evaluation errors skip the
  affected policy while appearing in `errors`, as in Cedar. Applications that
  require a decision with no evaluation errors must inspect `errors` before
  enforcing an `Allow` result.

Unsupported policy syntax is rejected rather than ignored. The profile does
not implement Cedar schema validation, templates, annotations, arithmetic,
extension types or full Cedar string
escaping. Policy checks are syntax/profile checks, not schema validation.
The CLI reads UTF-8 regular files up to 1 MiB; the parser limits input to
2,048 tokens, expression nesting to 128, JSON nesting to 64, and authorization
to 4,096 entities and 65,536 parent links. Limits raise errors instead of
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
On Windows, the checked toolchain was `moon 0.1.20261028` / `moonc v0.10.18`;
the current comparison ran 109 requests with no mismatches. This is evidence
for the selected cases, not a claim of full Cedar conformance.

Apache-2.0. The upstream fixtures retain their own license and attribution.
