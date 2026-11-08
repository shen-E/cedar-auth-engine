///|
test "authorization summaries distinguish Cedar results from enforcement" {
  let policies = @engine.parse_policies(
    "@id(\"allow\") permit(principal, action, resource);" +
    "@id(\"blocked\") forbid(principal, action, resource) when { context.blocked };" +
    "@id(\"guard\") forbid(principal, action, resource) when { context.fail };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {
      "blocked": @engine.BoolValue(false),
      "fail": @engine.BoolValue(false),
    },
  }
  let blocked = {
    ..request,
    context: {
      "blocked": @engine.BoolValue(true),
      "fail": @engine.BoolValue(false),
    },
  }
  let missing = { ..request, context: { "fail": @engine.BoolValue(false) }, }
  let blocked_error = {
    ..request,
    context: { "blocked": @engine.BoolValue(true) },
  }
  let requests = [request, blocked, missing, blocked_error]
  let store = @engine.EntityStore::new([])
  let expected = @engine.AuthorizationSummary::{
    total: 4,
    cedar_allowed: 2,
    cedar_denied: 2,
    error_requests: 2,
    enforcement_allowed: 1,
    enforcement_denied: 3,
  }
  assert_true(store.authorize_batch_summary(policies, requests) == expected)
  assert_true(
    store.authorize_batch_summary_checked(policies, requests) == expected,
  )
  assert_true(
    @engine.authorize_batch_summary_with_tags(policies, requests, []) ==
    expected,
  )
  let results = store.authorize_batch(policies, requests)
  assert_true(results[0].is_authorized())
  assert_true(
    results[1].decision == @engine.Deny && results[1].errors.is_empty(),
  )
  assert_true(
    results[2].decision == @engine.Allow && !results[2].errors.is_empty(),
  )
  assert_true(
    results[3].decision == @engine.Deny && !results[3].errors.is_empty(),
  )
  let empty = store.authorize_batch_summary(policies, [])
  assert_true(empty.total == 0 && empty.enforcement_denied == 0)
}

///|
test "authorization summary validates the graph and batch boundaries" {
  let policies = @engine.parse_policies("")
  let store = @engine.EntityStore::new([])
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let requests = Array::make(32768, request)
  assert_true(
    store.authorize_batch_summary(policies, requests).cedar_denied == 32768,
  )
  assert_true(
    store.authorize_batch_summary_checked(policies, requests).total == 32768,
  )
  requests[32767] = {
    ..request,
    principal: { kind: "invalid type", id: "x", },
  }
  let invalid = try {
    let _ = store.authorize_batch_summary_checked(policies, requests)
    false
  } catch {
    _ => true
  }
  assert_true(invalid)
  requests.push(request)
  let oversized = try {
    let _ = store.authorize_batch_summary(policies, requests)
    false
  } catch {
    _ => true
  }
  assert_true(oversized)
  let uid : @engine.EntityId = { kind: "Group", id: "loop", }
  let cycle : Array[@engine.TaggedEntity] = [
    { entity: { uid, attrs: {}, parents: [uid], }, tags: {}, },
  ]
  let invalid_graph = try {
    let _ = @engine.authorize_batch_summary_with_tags(policies, [], cycle)
    false
  } catch {
    _ => true
  }
  assert_true(invalid_graph)
}
