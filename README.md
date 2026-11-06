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
moon run cmd/cedar-auth-engine --target native -- enforce-batch examples/diagnostics/policy.cedar examples/diagnostics/entities.json examples/diagnostics/batch.json --format json
moon run cmd/cedar-auth-engine --target native -- test examples/device/policy.cedar examples/device/entities.json examples/device/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/approvals/policy.cedar examples/approvals/entities.json examples/approvals/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/session/policy.cedar examples/session/entities.json examples/session/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/access-window/policy.cedar examples/access-window/entities.json examples/access-window/requests.json
moon run cmd/cedar-auth-engine --target native -- test examples/template-sharing/policy.cedar examples/template-sharing/entities.json examples/template-sharing/requests.json --template examples/template-sharing/template.cedar --links examples/template-sharing/links.json
moon run cmd/cedar-auth-engine --target native -- test examples/multi-template/policy.cedar examples/multi-template/entities.json examples/multi-template/requests.json --template examples/multi-template/direct.cedar --links examples/multi-template/direct-links.json --template examples/multi-template/team.cedar --links examples/multi-template/team-links.json
moon run cmd/cedar-auth-engine --target native -- test examples/multi-template/policy.cedar examples/multi-template/entities.json examples/policy-update/requests.json --add-policies examples/policy-update/additional.cedar --template examples/multi-template/direct.cedar --links examples/multi-template/direct-links.json --template examples/multi-template/team.cedar --links examples/multi-template/team-links.json --replace-policies examples/policy-update/replacements.cedar
moon run cmd/cedar-auth-engine --target native -- compare examples/multi-template/policy.cedar examples/policy-comparison/after.cedar examples/multi-template/entities.json examples/policy-comparison/requests.json --before-template examples/multi-template/direct.cedar --before-links examples/multi-template/direct-links.json --before-template examples/multi-template/team.cedar --before-links examples/multi-template/team-links.json --after-template examples/policy-comparison/direct.cedar --after-links examples/multi-template/direct-links.json --after-template examples/multi-template/team.cedar --after-links examples/multi-template/team-links.json --format json
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

`enforce POLICY ENTITIES REQUEST` provides a fail-closed result: it allows
only when Cedar returns `Allow` and there are no policy evaluation errors.
`enforce-batch POLICY ENTITIES REQUESTS` applies the same rule to each request
and preserves input order. JSON output contains an `allowed` boolean and the
complete original Cedar `response` for each request. The underlying decision,
reasons and errors remain available even when enforcement denies an `Allow`
with errors. Text output shows both the enforcement result and Cedar decision.

These commands exit 0 when every request is allowed, 1 when any request is
denied, and 2 for invalid input or usage. An empty valid batch exits 0. They
accept `--format json`, `--template` and `--links`; `--strict` is for the
`authorize` and `batch` commands. A policy error, including a comparison-limit
error, prevents enforcement from allowing the request.

`compare BEFORE AFTER ENTITIES REQUESTS` evaluates two policy sets against an
array of requests. By default both sides use `ENTITIES`; add
`--after-entities FILE` to evaluate the after side with a separate entity
snapshot. Both snapshots are validated, even when the request array is empty.
JSON output includes both full responses and flags for changes to the Cedar
decision, fail-closed enforcement, determining policy IDs, and errors. Error comparisons include policy IDs and
messages; reasons and errors are compared without regard to order. The summary
counts requests in each category. A request can count in multiple categories.
It also counts grants and revocations for Cedar decisions and for fail-closed
enforcement separately; each case includes the corresponding direction flags.

`--fail-on-change` exits 1 when any decision, reason or error changes. For
selective checks, use `--fail-on-decision-grant`, `--fail-on-decision-revoke`,
`--fail-on-enforcement-grant` or `--fail-on-enforcement-revoke`. Each exits 1
when at least one request has that transition. `--fail-on-after-error` exits 1
if the after side has any evaluation errors, even when those errors are unchanged;
`after_error_requests` counts affected requests. Combine options to check several
conditions. With no matching condition, the command exits 0; invalid input exits 2
without a partial report. A decision grant means Cedar changed from Deny to
Allow even if evaluation errors remain. An enforcement grant requires the after
response to be Allow with no errors; an enforcement revocation includes an
Allow response that gains errors. Choose the check that matches how the host
uses the response. The command compares up to 4,096 requests and uses the
`EntityStore` snapshot limits described below.

Use `--before-template TEMPLATE --before-links LINKS` and the corresponding
`--after-template` / `--after-links` options for linked policies. Repeat pairs
as needed; each side pairs templates and link files by their respective order
of appearance, with up to 1,024 pairs per side. Each side starts from its own
static policy file. Each side also accepts `--before-add-policies FILE`,
`--before-replace-policies FILE` and `--before-remove-policy ID`, or the
corresponding `--after-*` options. They can be repeated up to 1,024 times per
option and side. As with the authorization commands below, each side loads its
base file, additions, template links, replacements and removals in that order;
file order is preserved within additions and within replacements. Duplicate or
unknown IDs and invalid input fail the entire comparison before output.

For example, evaluate the existing sharing policies before and after applying
the [policy update](examples/policy-update/):

```sh
moon run cmd/cedar-auth-engine --target native -- compare examples/multi-template/policy.cedar examples/multi-template/policy.cedar examples/multi-template/entities.json examples/policy-comparison/requests.json --before-template examples/multi-template/direct.cedar --before-links examples/multi-template/direct-links.json --before-template examples/multi-template/team.cedar --before-links examples/multi-template/team-links.json --after-template examples/multi-template/direct.cedar --after-links examples/multi-template/direct-links.json --after-template examples/multi-template/team.cedar --after-links examples/multi-template/team-links.json --before-remove-policy carol-report --after-add-policies examples/policy-update/additional.cedar --after-replace-policies examples/policy-update/replacements.cedar --after-remove-policy design-team --format json
```

See [policy comparison](examples/policy-comparison/) for a case where an
evaluation error changes enforcement while Cedar still returns `Allow`. The
[entity comparison](examples/entity-comparison/) uses the same policy on both
sides to inspect team membership and resource hierarchy changes:

```sh
moon run cmd/cedar-auth-engine --target native -- compare examples/multi-template/policy.cedar examples/multi-template/policy.cedar examples/multi-template/entities.json examples/entity-comparison/requests.json --before-template examples/multi-template/team.cedar --before-links examples/multi-template/team-links.json --after-template examples/multi-template/team.cedar --after-links examples/multi-template/team-links.json --after-entities examples/entity-comparison/after-entities.json --format json
```

Comparisons cover the supplied requests and entity snapshots; they do not
modify policy files, update entity storage or deploy changes.

`test POLICY ENTITIES CASES` evaluates an array of objects with `request` and
expected `decision` fields. Optional `reasons` and `errors` fields contain
arrays of policy IDs. Reasons are compared only when specified; errors must
match exactly and default to an empty list. The comparisons ignore order and
reject duplicate IDs. JSON output includes a per-case `checks` object; its
`reasons` value is `null` when that comparison was omitted. A mismatched case
makes the command exit 1. The [diagnostics example](examples/diagnostics/)
includes a deliberate policy error and its expected ID. The command validates
all cases before printing results and evaluates them in chunks of up to 4,096
requests, sharing one entity graph within each chunk. Empty input still checks
the entity graph.

For `authorize`, `batch`, `enforce`, `enforce-batch` and `test`, add
`--template TEMPLATE --links LINKS` to evaluate static policies together with
template links. Repeat the two options to load multiple templates. Templates
and links files are paired in their respective order of appearance; their counts
must match. The CLI accepts up to 1024 pairs. Each links file is an array such as:

```json
[{"id":"share-1","principal":{"type":"User","id":"alice"},"resource":{"type":"File","id":"report"}}]
```

Each link supplies exactly the slots used by its template and a policy ID
unique across the static policies and all links; omit an unused slot. All groups
are checked before any result is produced. A linked policy's ID appears in
authorization reasons and errors. See [template sharing](examples/template-sharing/)
and [multiple templates](examples/multi-template/) for complete inputs.

The same commands also accept `--add-policies FILE` to append a Cedar policy
file and `--replace-policies FILE` to replace existing policies by ID. Both
options can be repeated, with up to 1,024 files per option. Each added ID must
be new, and each replacement ID must already exist. Use explicit `@id` values
when composing files: automatically assigned IDs start from `policy0` in each
file. The [policy update example](examples/policy-update/) combines an emergency
rule with replacements for a static rule and a linked share. The host must set
`authenticated`, `mfa`, `emergency` and `override` from trusted application
state; accepting these flags directly from an untrusted caller would let that
caller affect authorization.

Updates are applied in this order, regardless of option order: the main file,
added policy files in their given order, template links, replacement files in
their given order, then removals. A later replacement file can replace an ID
from an earlier one. Invalid updates fail before any authorization output.

The same commands accept `--remove-policy ID` to evaluate without that policy.
Repeat it for multiple IDs. Removal happens after all templates are linked and
only affects that invocation; the input files are unchanged. IDs must exist and
must not be repeated. Removing a `forbid` policy may allow requests previously
denied by it.

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
let allowed = response.is_authorized()
```

`response.is_authorized()` returns true only for `Allow` without policy errors.
It does not alter the Cedar response, which remains available for diagnostics.

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

To add several links to the same template in one operation, use `link_batch`:

```moonbit
let links : Array[@engine.TemplateLink] = [
  { id: "share-1", bindings: {
    principal: Some(request.principal), resource: Some(request.resource),
  } },
]
let linked = policies.link_batch(template, links)
```

`template.slots()` lists the required slots. Both linking methods return a new
policy set; the original remains unchanged. `link_batch` validates every link
before returning and preserves their order. Call it again to link another
template. Each link captures the parsed template at link
time. When a template changes, parse it and rebuild its links to apply the
change. The application owns template storage and the mapping from template
versions to links.

Combine or update parsed policy sets in memory:

```moonbit
let additional = @engine.parse_policies(
  "@id(\"guard\") forbid(principal, action, resource) when { context.suspended };",
)
let combined = policies.merge(additional)
let replacement = @engine.parse_policies(
  "@id(\"guard\") forbid(principal, action, resource) when { context.blocked };",
)
let updated = combined.replace(replacement)
```

`merge` appends policies with distinct IDs; `replace` requires every supplied
ID to exist and retains the original policy order. Either input can contain
static or linked policies. Both methods return a new set or raise an error
without changing either input. Replacement changes the whole policy, including
its effect, condition and annotations. The 1,024-policy limit applies to the
merged result. Applications control when to publish a new snapshot to their
workers.

Revoke a policy by ID when an application updates access:

```moonbit
let without_share = linked.remove("share-1")
```

`remove_batch(["share-1", "share-2"])` removes several IDs at once. Both
methods return a new policy set and leave the original unchanged. Batch removal
requires distinct, existing IDs and fails as a whole on invalid input.
Remaining policies retain their order and annotations. Static policies and
linked policies can both be removed; removing a `forbid` can expose a matching
`permit`. The host must use the returned set for subsequent authorization calls
and distribute any update to its own policy storage or other workers.

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
For a set of representative requests, compare two policy snapshots against the
same store before switching the active set:

```moonbit
let comparisons = store.compare(policies, updated, [request])
let changed = comparisons[0].changed()
let enforcement_changed = comparisons[0].enforcement_changed()
```

Each comparison retains both responses. The `decision_changed`,
`reasons_changed` and `errors_changed` methods expose individual differences;
`enforcement_changed` uses `Response::is_authorized()` on both sides.
`decision_granted` and `decision_revoked` identify changes in the raw Cedar
decision; `enforcement_granted` and `enforcement_revoked` identify changes in
fail-closed access. When entity data also changes, create a second store and
compare both snapshots:

```moonbit
let next_store = @engine.EntityStore::new_with_tags(updated_entities)
let comparisons = store.compare_with_entities(next_store, policies, updated, [request])
```

The before policy uses the original store and the after policy uses `next_store`.
Both stores are validated snapshots, and each comparison accepts at most 4,096
requests. The host chooses the requests and controls when the new policy set
and entity data are activated.

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
  and only the template slots. The CLI accepts multiple template/link pairs.
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
1,024 policies. A removal operation accepts at most 1,024 policy IDs. A reusable
`EntityStore` additionally limits entity attribute
and tag values to 131,072 total nodes and 64 nested levels. Input and graph
limits raise errors instead of returning a partial decision.

Each policy evaluation allows at most 1,000,000 value-comparison steps and 128
nested comparison levels. These limits also stop cyclic values constructed
through the typed API. Exceeding a comparison limit records a policy error and
skips that policy under Cedar's error semantics. Applications should inspect
`errors` before enforcing a decision; CLI callers can use `--strict`.

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
individual reference decisions, fail-closed enforcement results, test-command
responses, links from single and multiple templates, policy removal, and
policy updates and both independently composed sides of comparison reports,
including different entity snapshots and directional checks, against the
corresponding Cedar inputs. It reports mismatches and exits nonzero.
IP range cases are also checked against Python `ipaddress` with a fixed seed.
Hierarchy cases are checked against an independent reachability walk, cyclic
entity graphs are checked against Cedar, generated timestamps are checked
against Python calendar arithmetic, and small sets against Python sets. The MoonBit tests also compare all
512 three-entity graphs with a transitive-closure oracle on each backend.
The MoonBit tests also compare wildcard matching against an independent
exhaustive oracle over 41,261 short pattern/input pairs per backend.
A [GitHub Actions reference run](https://github.com/shen-E/cedar-auth-engine/actions/runs/42235564376/job/127952120898)
completed 1,082 comparisons, 36 invalid syntax cases, 5 invalid entity graphs
and 41 entity type name checks without mismatches. These checks cover the
selected cases, rather than all Cedar behavior. CI pins `moonc v0.10.18+6c83a7f62`
for portable tests and formatting; native builds also run with the latest
available toolchain on Linux, macOS and Windows.

Apache-2.0. The upstream fixtures retain their own license and attribution.
