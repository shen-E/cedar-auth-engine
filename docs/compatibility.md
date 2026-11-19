# Cedar compatibility

The target is compatibility with Cedar 4.13.0 authorization and policy
validation. This project currently implements a subset; the target has not
been met. The reference is [Cedar 4.13.0](https://github.com/cedar-policy/cedar/releases/tag/v4.13.0)
at commit `324d3c09fc94ab91464ec340eb81e4b167deb6f5`.

| Capability | Current state |
| --- | --- |
| Text policies, templates and expression evaluation | Supported profile documented in the README; full language coverage unverified. |
| Policy JSON | Not supported as a policy input. |
| Schema-guided entity and request parsing | Not supported; implicit entity references may be interpreted as records. |
| Duplicate entities | Equivalent entries are coalesced; conflicting entries are rejected. Comparison and input limits still apply. |
| Cedar and JSON schemas, policy and request validation | Not supported. Syntax and input checks are not schema validation. |
| IP, decimal, duration and datetime extensions | Supported as documented; completeness against 4.13.0 is unverified. |
| Partial authorization | Not implemented. |
| Authorization diagnostics | Decision, determining policy IDs and policy error IDs are compared in the integration baseline. Error categories and text are not yet compared. |
| Input and evaluation limits | Explicit limits apply and can reject inputs accepted by Cedar. |

## Handwritten integration baseline

The baseline runs every handwritten request in
[`cedar-integration-tests`](https://github.com/cedar-policy/cedar-integration-tests/tree/f64ff16c8a5c2473e0db9391997d10ceae9bb2f2)
at commit `f64ff16c8a5c2473e0db9391997d10ceae9bb2f2`. This is a historical
fixture snapshot: its Cedar submodule points to `bcb8bd93a292b59ae8f1dcf53b9b4176a2d3405d`,
not to 4.13.0. Every fixture is re-evaluated using Cedar 4.13.0 with the
fixture's schema; fixture expectations and reference results are checked
separately. The engine currently runs without a schema.

The baseline run for the existing engine evaluated 24 scenarios and 78
requests: 63 matched the reference, 13 differed, and two use unsupported JSON
policy input. All 24 schema validation scenarios are unsupported by the
engine. These counts cover this handwritten snapshot, not the full Cedar test
corpus or every language feature. The 13 differences include policies that
depend on schema-guided entity references. A match does not establish that
schema validation or all error details are compatible.

To reproduce, check out the fixture revision and run:

```sh
git clone https://github.com/cedar-policy/cedar-integration-tests.git cedar-fixtures
git -C cedar-fixtures checkout --detach f64ff16c8a5c2473e0db9391997d10ceae9bb2f2
moon build cmd/cedar-auth-engine --target native
python scripts/integration_baseline.py --fixtures cedar-fixtures --cedar /path/to/cedar-4.13.0 --engine /path/to/cedar-auth-engine
```

The JSON report records each fixture and request status, plus independent
schema-validation coverage. It does not store local paths. Add
`--require-complete` to exit nonzero until every request matches, every schema
check is implemented and the reference agrees with the fixture expectations.
CI uploads this report as `cedar-integration-baseline`. The generated corpus
and other official test sources are not yet measured by this runner.

## Related MoonBit implementation

[MoonCedar](https://github.com/jaredzhou/mooncedar/tree/69725fb799ba48f66507d3d8cc7b9a0b055952a5)
is another MoonBit Cedar implementation. Its documentation describes parsing,
evaluation, authorization and partial evaluation. This project's module
manifest does not declare a MoonCedar dependency; this project provides a
native CLI, batch operations, policy comparisons and per-stage explanations.
These descriptions do not establish which capabilities MoonCedar lacks. A
shared-input comparison remains to be completed. MoonCedar's module metadata
declares Apache-2.0.
