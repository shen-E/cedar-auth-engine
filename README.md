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
moon run cmd/cedar-auth-engine --target native -- test examples/tags/policy.cedar examples/tags/entities.json examples/tags/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/diagnostics/policy.cedar examples/diagnostics/entities.json examples/diagnostics/requests.json
moon run cmd/cedar-auth-engine --target native -- batch examples/diagnostics/policy.cedar examples/diagnostics/entities.json examples/diagnostics/batch.json --format json
moon run cmd/cedar-auth-engine --target native -- test examples/device/policy.cedar examples/device/entities.json examples/device/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/approvals/policy.cedar examples/approvals/entities.json examples/approvals/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/session/policy.cedar examples/session/entities.json examples/session/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/access-window/policy.cedar examples/access-window/entities.json examples/access-window/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/template-sharing/policy.cedar examples/template-sharing/entities.json examples/template-sharing/requests.json --template examples/template-sharing/template.cedar --links examples/template-sharing/links.json
python scripts/smoke.py
```

`check POLICY` checks the supported syntax. With `--format json`, it also
returns each policy ID, effect and annotations. `authorize POLICY ENTITIES REQUEST`
evaluates one request. `batch POLICY ENTITIES REQUESTS` evaluates an array of
requests against the same policy set and entity graph, returning one response
per request in input order. It validates all input before producing output,
including the entity graph when the request array is empty.

Add `--strict` to `authorize` or `batch` to exit 1 when any policy evaluation
error occurs. Output still contains every Cedar decision and its diagnostics;
strict mode does not convert an `Allow` into a `Deny`. Without `--strict`,
both `Allow` and `Deny` exit 0. Malformed input or usage exits 2. Each command
accepts `--format json`; text is the default.

`test POLICY ENTITIES CASES` evaluates an array of objects with `request` and
expected `decision` fields. Optional `reasons` and `errors` fields contain
arrays of policy IDs. Reasons are compared only when specified; errors must
match exactly and default to an empty list. The comparisons ignore order and
reject duplicate IDs. JSON output includes a per-case `checks` object; its
`reasons` value is `null` when that comparison was omitted. A mismatched case
makes the command exit 1. The [diagnostics example](examples/diagnostics/)
includes a deliberate policy error and its expected ID.

For `authorize`, `batch` and `test`, add `--template TEMPLATE --links LINKS`
to evaluate static policies together with links from one template. The links
file is an array such as:

```json
[{"id":"share-1","principal":{"type":"User","id":"alice"},"resource":{"type":"File","id":"report"}}]
```

Each link supplies exactly the slots used by the template and a unique policy
ID; omit an unused slot. All links and their IDs are checked before any result
is produced. A linked policy's ID appears in authorization reasons and errors.
See [template sharing](examples/template-sharing/) for complete inputs.

The request uses `principal`, `action` and `resource` objects with `type` and
`id`, plus a `context` object. Entities are an array of `uid`, `attrs`,
`parents`, and optional `tags`; entity-valued attributes use
`{"__entity":{"type":"User","id":"alice"}}`.
See [examples](examples/) for complete inputs. Entity type names in requests,
entity data and template bindings must use valid Cedar identifiers and
namespaces; entity IDs may be arbitrary strings. Duplicate JSON keys, unsupported
extension values other than IP, decimal, duration and datetime, nulls, invalid
integers and malformed input are rejected. Extension values in entity
attributes or request context use `{"__extn":{"fn":"decimal","arg":"125.4500"}}`,
`{"__extn":{"fn":"duration","arg":"1h30m"}}`,
`{"__extn":{"fn":"datetime","arg":"2026-11-01T12:00:00Z"}}`, or
`{"__extn":{"fn":"ip","arg":"10.1.2.3"}}`. The host must derive the
session age used by the [session example](examples/session/) from trusted
session state and supply the current time used by the
[access-window example](examples/access-window/) from a trusted clock. For client source addresses, the host must supply a trustworthy
individual IP address; forwarded headers require validation by the application
or proxy.

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

`parse_json`, `request_from_json`, `tagged_entities_from_json` and
`response_to_json` provide the JSON boundary. Pass tagged entities to
`authorize_with_tags`. For multiple requests, `authorize_batch` and
`authorize_batch_with_tags` validate and index the shared entity graph once and
return responses in input order. `validate_entities` checks graph limits, duplicate IDs
and cycles independently of policy evaluation. When constructing typed request
and entity values directly, call `EntityId::validate()` on each identifier to
validate its type name; JSON inputs and template bindings perform this check.
The original `authorize` and `entities_from_json` accept entities without
tags; `entities_from_json` rejects nonempty tags to prevent silently discarding
them. Use `parse_json` for text input to detect
duplicate keys; duplicate keys are already lost if a caller supplies an
independently parsed `Json` value. The caller can alternatively construct typed
values, including `@engine.IpValue(@engine.IpAddress::parse("2001:db8::1"))`,
`@engine.DecimalValue(@engine.Decimal::parse("125.4500"))`,
`@engine.DurationValue(@engine.Duration::parse("1h30m"))`, and
`@engine.DateTimeValue(@engine.DateTime::parse("2026-11-01T12:00:00Z"))`.
`policies.metadata()` returns IDs, effects and independent copies of annotation
maps in policy order. Use the IDs in `reasons` and `errors` to find the
corresponding metadata. For entity JSON that contains tags:

```moonbit
let entities = @engine.tagged_entities_from_json(@engine.parse_json(entity_text))
let response = @engine.authorize_with_tags(policies, request, entities)
```

A reusable policy template can be linked to a policy set in memory:

```moonbit
let template = @engine.parse_template(
  "permit(principal == ?principal, action == Action::\"read\", resource == ?resource);",
)
let linked = policies.link(template, "share-1", {
  principal: Some(request.principal),
  resource: Some(request.resource),
})
let response = @engine.authorize(linked, request, [])
```

`template.slots()` lists the required slots. Linking returns a new policy set;
the original remains unchanged. Each link captures the parsed template at link
time. When a template changes, parse it and rebuild its links to apply the
change. The application owns template storage and the mapping from template
versions to links.

For services that make authorization calls over time, construct a reusable
entity snapshot and pass a policy set to each call:

```moonbit
let store = @engine.EntityStore::new_with_tags(entities)
let response = store.authorize(policies, request)
let responses = store.authorize_batch(policies, [request])
```

`EntityStore::new` accepts entities without tags. Both constructors validate the
hierarchy and copy the parent links, attributes and tags, including nested sets
and records. Later mutations to the input entities do not change the snapshot;
construct a new store to apply entity updates. Requests and policy sets remain
separate from the store. The snapshot is used in memory and performs no I/O.

## Supported policy profile

- Static and template-linked `permit` and `forbid` policies, scope equality and entity ancestry,
  principal and resource type restrictions (`is`, optionally with `in`),
  `when` and `unless`. Entity hierarchies must be acyclic; missing parent
  entities and repeated parent links are allowed. Duplicate entity IDs are
  rejected even for identical entries, a stricter rule than Cedar.
  Annotations appear before the policy effect. As in the Cedar CLI, `@id("name")` sets the policy ID; otherwise IDs are `policy0`,
  `policy1`, and so on. Duplicate annotations or policy IDs are rejected.
  Annotations are metadata and do not change authorization decisions.
  Templates support `?principal` and `?resource` only on the corresponding
  scope operand of `==` or `in`, including `is Type in`. Linking requires all
  and only the template slots. The CLI loads one template at a time.
- Principal, action, resource and context; entity attributes and parent links;
  boolean, signed 64-bit integer, string, entity, set and record values.
- Entity tags via `.hasTag(key)` and `.getTag(key)`, where `key` can be any
  expression yielding a string. Tags belong to the individual entity and are
  not inherited from parents. A missing tag causes a `getTag` evaluation error;
  use `hasTag` to guard access.
- `==`, `!=`, `in`, `has`, `!`, `&&`, `||`, ordering (`<`, `<=`, `>`,
  `>=`), attribute access, set and record literals. Sets compare without regard
  to order and duplicate members.
- Signed 64-bit addition, subtraction, multiplication and unary negation.
  Overflow and incompatible operands cause evaluation errors. Division is not supported.
- Set methods `.contains(value)`, `.containsAll(set)`, `.containsAny(set)` and
  `.isEmpty()`. Incorrect operand types produce policy evaluation errors.
- Cedar fixed-point `decimal(string)` values for amounts and other precise
  quantities. Values range from `-922337203685477.5808` to
  `922337203685477.5807`, with one to four fractional digits. Use
  `.lessThan()`, `.lessThanOrEqual()`, `.greaterThan()` and
  `.greaterThanOrEqual()` to compare decimals. Equality compares their values,
  not their textual formatting. Invalid strings and incorrect operand types
  cause policy errors; decimal values are distinct from integers.
- Cedar `datetime(string)` values accept a calendar date or a timestamp with
  UTC `Z` or a numeric timezone offset. Timestamps may include exactly three
  fractional digits. Comparisons use UTC instants. `.offset(duration)` and
  `.durationSince(datetime)` support time arithmetic; `.toDate()` and
  `.toTime()` extract the UTC date and time. Invalid calendar dates, timestamps
  and arithmetic overflow produce policy errors. The engine uses no clock.
- Cedar `duration(string)` values represent signed milliseconds. Components
  use `d`, `h`, `m`, `s` and `ms` in descending order, each at most once;
  `duration("1h30m")` and `duration("90m")` compare equal. Durations support
  `==`, `!=`, `<`, `<=`, `>` and `>=`, plus `.toMilliseconds()`,
  `.toSeconds()`, `.toMinutes()`, `.toHours()` and `.toDays()`. Conversions
  to whole units truncate toward zero. Invalid formats and overflow cause
  policy errors; durations are distinct from integers.
- Cedar `ip(string)` values for IPv4 and IPv6 addresses and CIDR ranges,
  `.isIpv4()`, `.isIpv6()`, `.isLoopback()`, `.isMulticast()` and
  `.isInRange(ip)`. Classification and range inclusion require
  the entire receiver range to fit; different address families do not match.
  IPv6 uses hexadecimal groups; dotted IPv4-in-IPv6 notation is rejected.
  Invalid addresses and incorrect operand types produce policy errors.
- Entity type tests, `if ... then ... else ...` expressions, quoted `has`
  attributes and string-literal indexing such as `context["tenant-id"]`.
  A nested `has` path such as `context has device.posture.managed` checks
  each identifier in order: a missing segment returns false, while an
  intermediate value that is neither an entity nor a record causes an error.
  A quoted `has` attribute names a single field, including any dots.
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
not implement Cedar schema validation or extension types besides IP, decimal,
duration and datetime. Policy checks are syntax/profile checks,
not schema validation.
The CLI reads UTF-8 regular files up to 1 MiB; the parser limits input to
2,048 tokens, expression nesting to 128, arithmetic chains to 128 operators,
postfix chains and `has` paths to 128 segments, JSON nesting to 64, and
authorization to 4,096 entities and 65,536 parent links. Batch authorization
is limited to 4,096 requests; a policy set, including links, is limited to
1,024 policies. A reusable `EntityStore` additionally limits
entity attribute and tag values to 131,072 total nodes and 64 nested levels;
this also rejects cyclic values constructed through the typed API. Limits raise
errors instead of returning a partial decision.

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
examples and error/condition cases, including batch responses compared with
individual reference decisions, and links compared with Cedar template-linked
policies. It reports mismatches and exits nonzero.
IP range cases are also checked against Python `ipaddress` with a fixed seed.
Hierarchy cases are checked against an independent reachability walk, cyclic
inputs are checked against Cedar, and generated timestamps are checked against
Python calendar arithmetic. The MoonBit tests also compare all
512 three-entity graphs with a transitive-closure oracle on each backend.
The MoonBit tests also compare wildcard matching against an independent
exhaustive oracle over 41,261 short pattern/input pairs per backend.
On Windows, the checked toolchain was `moon 0.1.20261028` / `moonc v0.10.18`;
the current comparison ran 774 requests, 36 invalid-syntax cases and 5 invalid
entity-graph cases with no mismatches. Another 41 checks compare accepted and
rejected entity type names in entity data, requests and template bindings. These
results cover the selected cases, rather than all Cedar behavior.

Apache-2.0. The upstream fixtures retain their own license and attribution.
