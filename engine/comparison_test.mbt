///|
test "compare decisions and fail-closed enforcement independently" {
  let before = @engine.parse_policies(
    "@id(\"allow\") permit(principal, action, resource); @id(\"guard\") forbid(principal, action, resource) when { false };",
  )
  let after = @engine.parse_policies(
    "@id(\"allow\") permit(principal, action, resource); @id(\"guard\") forbid(principal, action, resource) when { context.blocked };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let deny = { ..request, context: { "blocked": @engine.BoolValue(true) }, }
  let unchanged = {
    ..request,
    context: { "blocked": @engine.BoolValue(false) },
  }
  let store = @engine.EntityStore::new([])
  let items = store.compare(before, after, [request, deny, unchanged])
  assert_true(items.length() == 3)
  assert_true(
    items[0].before.decision == @engine.Allow &&
    items[0].after.decision == @engine.Allow,
  )
  assert_false(items[0].decision_changed())
  assert_true(
    items[0].enforcement_changed() &&
    items[0].errors_changed() &&
    items[0].changed(),
  )
  assert_false(items[0].reasons_changed())
  assert_true(items[1].decision_changed() && items[1].enforcement_changed())
  assert_true(items[1].reasons_changed() && !items[1].errors_changed())
  assert_false(items[2].changed())
  assert_true(items[2].before.is_authorized() && items[2].after.is_authorized())
  assert_true(store.compare(before, after, []).is_empty())
}

///|
test "comparison ignores ordering but detects error messages and multiplicity" {
  let base = @engine.Response::{
    decision: @engine.Allow,
    reasons: ["a", "b"],
    errors: [
      { policy_id: "x", message: "one", },
      { policy_id: "y", message: "two", },
    ],
  }
  let reordered = @engine.Response::{
    ..base,
    reasons: ["b", "a"],
    errors: [
      { policy_id: "y", message: "two", },
      { policy_id: "x", message: "one", },
    ],
  }
  let item = @engine.AuthorizationComparison::{
    before: base,
    after: reordered,
  }
  assert_false(item.changed())
  let changed_message = {
    ..reordered,
    errors: [
      { policy_id: "x", message: "different", },
      { policy_id: "y", message: "two", },
    ],
  }
  assert_true(
    @engine.AuthorizationComparison::{ before: base, after: changed_message, }.errors_changed(),
  )
  let repeated = { ..base, reasons: ["a", "a"], }
  assert_true(
    @engine.AuthorizationComparison::{ before: base, after: repeated, }.reasons_changed(),
  )
  let collisions_a = { ..base, errors: [{ policy_id: "a", message: "bc", }], }
  let collisions_b = { ..base, errors: [{ policy_id: "ab", message: "c", }], }
  assert_true(
    @engine.AuthorizationComparison::{
      before: collisions_a,
      after: collisions_b,
    }.errors_changed(),
  )
}

///|
test "comparison batch limit is enforced before returning results" {
  let store = @engine.EntityStore::new([])
  let empty = @engine.parse_policies("")
  let request = @engine.Request::{
    principal: { kind: "User", id: "a", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "r", },
    context: {},
  }
  let requests = Array::make(4096, request)
  assert_true(store.compare(empty, empty, requests).length() == 4096)
  requests.push(request)
  let rejected = try {
    let _ = store.compare(empty, empty, requests)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "compare team memberships across independent entity snapshots" {
  let policy = @engine.parse_policies(
    "@id(\"team\") permit(principal in Group::\"editors\", action == Action::\"read\", resource);",
  )
  let alice = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let bob = { ..alice, principal: { kind: "User", id: "bob", }, }
  let before_entities : Array[@engine.Entity] = [
    {
      uid: alice.principal,
      attrs: {},
      parents: [{ kind: "Group", id: "editors", }],
    },
    { uid: bob.principal, attrs: {}, parents: [], },
  ]
  let after_entities : Array[@engine.Entity] = [
    { uid: alice.principal, attrs: {}, parents: [], },
    {
      uid: bob.principal,
      attrs: {},
      parents: [{ kind: "Group", id: "editors", }],
    },
  ]
  let before = @engine.EntityStore::new(before_entities)
  let after = @engine.EntityStore::new(after_entities)
  let cases = before.compare_with_entities(after, policy, policy, [alice, bob])
  assert_true(
    cases[0].before.decision == @engine.Allow &&
    cases[0].after.decision == @engine.Deny,
  )
  assert_true(
    cases[1].before.decision == @engine.Deny &&
    cases[1].after.decision == @engine.Allow,
  )
  assert_true(cases[0].decision_changed() && cases[1].enforcement_changed())
  assert_true(
    before.compare_with_entities(after, policy, policy, []).is_empty(),
  )
  let same = before.compare_with_entities(before, policy, policy, [alice, bob])
  let existing = before.compare(policy, policy, [alice, bob])
  assert_false(same[0].changed() || same[1].changed())
  assert_true(
    @engine.response_to_json(same[0].before).stringify() ==
    @engine.response_to_json(existing[0].before).stringify(),
  )
  after_entities[1].parents.clear()
  assert_true(
    before.compare_with_entities(after, policy, policy, [bob])[0].after.decision ==
    @engine.Allow,
  )
}

///|
test "entity attribute changes can alter enforcement without changing Cedar decision" {
  let policies = @engine.parse_policies(
    "@id(\"allow\") permit(principal, action, resource); @id(\"guard\") forbid(principal, action, resource) when { resource.locked };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let before = @engine.EntityStore::new([
    {
      uid: request.resource,
      attrs: { "locked": @engine.BoolValue(false) },
      parents: [],
    },
  ])
  let after = @engine.EntityStore::new([
    { uid: request.resource, attrs: {}, parents: [], },
  ])
  let result = before.compare_with_entities(after, policies, policies, [request])[0]
  assert_true(
    result.before.decision == @engine.Allow &&
    result.after.decision == @engine.Allow,
  )
  assert_false(result.decision_changed())
  assert_true(result.errors_changed() && result.enforcement_changed())
  assert_true(result.after.errors[0].policy_id == "guard")
}

///|
test "different entity comparison respects the request batch limit" {
  let empty = @engine.parse_policies("")
  let before = @engine.EntityStore::new([])
  let after = @engine.EntityStore::new([])
  let request = @engine.Request::{
    principal: { kind: "User", id: "a", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "r", },
    context: {},
  }
  let requests = Array::make(4096, request)
  assert_true(
    before.compare_with_entities(after, empty, empty, requests).length() == 4096,
  )
  requests.push(request)
  let rejected = try {
    let _ = before.compare_with_entities(after, empty, empty, requests)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "direction distinguishes Cedar decisions from fail-closed enforcement" {
  let diagnostic = @engine.Diagnostic::{
    policy_id: "guard",
    message: "missing attribute",
  }
  let deny = @engine.Response::{
    decision: @engine.Deny,
    reasons: [],
    errors: [],
  }
  let allow = @engine.Response::{
    decision: @engine.Allow,
    reasons: ["permit"],
    errors: [],
  }
  let deny_error = { ..deny, errors: [diagnostic], }
  let allow_error = { ..allow, errors: [diagnostic], }
  let cases : Array[
    (@engine.Response, @engine.Response, Bool, Bool, Bool, Bool),
  ] = [
    (deny, allow, true, false, true, false),
    (allow, deny, false, true, false, true),
    (deny, allow_error, true, false, false, false),
    (allow_error, allow, false, false, true, false),
    (allow, allow_error, false, false, false, true),
    (allow_error, deny, false, true, false, false),
    (deny_error, allow, true, false, true, false),
    (allow, deny_error, false, true, false, true),
    (allow, allow, false, false, false, false),
    (deny_error, deny, false, false, false, false),
  ]
  for
    (
      before,
      after,
      decision_grant,
      decision_revoke,
      enforcement_grant,
      enforcement_revoke,
    ) in cases {
    let result = @engine.AuthorizationComparison::{ before, after, }
    assert_true(result.decision_granted() == decision_grant)
    assert_true(result.decision_revoked() == decision_revoke)
    assert_true(result.enforcement_granted() == enforcement_grant)
    assert_true(result.enforcement_revoked() == enforcement_revoke)
    assert_true(
      result.decision_changed() == (decision_grant || decision_revoke),
    )
    assert_true(
      result.enforcement_changed() == (enforcement_grant || enforcement_revoke),
    )
  }
}
