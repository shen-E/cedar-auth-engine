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
