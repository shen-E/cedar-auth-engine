///|
test "trace records matches, misses and errors without changing the decision" {
  let policies = parse_policies(
    "@id(\"allow\") permit(principal, action, resource) when { context.allow };" +
    "@id(\"block\") forbid(principal, action, resource) when { context.blocked };" +
    "@id(\"error\") forbid(principal, action, resource) when { context.missing };" +
    "@id(\"other\") permit(principal, action, resource == File::\"other\");",
  )
  let request = {
    ..sample_request(),
    context: { "allow": BoolValue(true), "blocked": BoolValue(true) },
  }
  let store = EntityStore::new([])
  let trace = store.authorize_trace_checked(policies, request)
  assert_true(
    response_to_json(trace.response).stringify() ==
    response_to_json(store.authorize(policies, request)).stringify(),
  )
  assert_true(
    trace.response.decision == Deny && trace.response.reasons == ["block"],
  )
  assert_true(
    trace.response.errors.length() == 1 &&
    trace.response.errors[0].policy_id == "error",
  )
  assert_true(trace.policies.length() == 4)
  assert_true(
    trace.policies[0].outcome == Matched && trace.policies[0].effect == "permit",
  )
  assert_true(
    trace.policies[1].outcome == Matched && trace.policies[1].effect == "forbid",
  )
  assert_true(trace.policies[2].outcome is EvaluationFailed(_))
  assert_true(trace.policies[3].outcome == NotMatched)
  let plain = store.authorize_trace(parse_policies(""), request)
  assert_true(plain.response.decision == Deny && plain.policies.is_empty())
  let invalid = { ..request, principal: { kind: "bad type", id: "a", }, }
  let rejected = try {
    let _ = store.authorize_trace_checked(policies, invalid)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "tracing agrees with indexed authorization across scopes and errors" {
  let source = StringBuilder()
  for i in 0..<96 {
    source.write_string("@id(\"p\{i}\") ")
    if i % 4 == 0 {
      source.write_string(
        "forbid(principal, action, resource == File::\"f\{i % 7}\") when { context.missing };\n",
      )
    } else if i % 4 == 1 {
      source.write_string(
        "permit(principal == User::\"u\{i % 5}\", action, resource);\n",
      )
    } else if i % 4 == 2 {
      source.write_string(
        "permit(principal, action == Action::\"a\{i % 3}\", resource);\n",
      )
    } else {
      source.write_string(
        "forbid(principal in Group::\"team\", action, resource) when { context.blocked };\n",
      )
    }
  }
  let policies = parse_policies(source.to_string())
  let alice : EntityId = { kind: "User", id: "u0", }
  let team : EntityId = { kind: "Group", id: "team", }
  let store = EntityStore::new([{ uid: alice, attrs: {}, parents: [team], }])
  let mut seed = 2026
  for i in 0..<150 {
    seed = (seed * 37 + 17) % 9973
    let request : Request = {
      principal: { kind: "User", id: "u\{i % 6}", },
      action: { kind: "Action", id: "a\{seed % 4}", },
      resource: { kind: "File", id: "f\{(seed / 4) % 8}", },
      context: if i % 2 == 0 {
        { "blocked": BoolValue(true) }
      } else {
        {}
      },
    }
    let trace = store.authorize_trace(policies, request)
    let response = store.authorize(policies, request)
    assert_true(
      response_to_json(trace.response).stringify() ==
      response_to_json(response).stringify(),
    )
    assert_true(trace.policies.length() == 96)
    for j in 0..<trace.policies.length() {
      assert_true(trace.policies[j].policy_id == "p\{j}")
    }
  }
}

///|
test "trace respects linked policies, updates and graph validation" {
  let template = parse_template(
    "permit(principal, action, resource == ?resource);",
  )
  let file : EntityId = { kind: "File", id: "report", }
  let linked = parse_policies("").link(template, "linked", {
    principal: None,
    resource: Some(file),
  })
  let store = EntityStore::new([])
  let request = { ..sample_request(), resource: file, }
  assert_true(
    store.authorize_trace(linked, request).policies[0].outcome == Matched,
  )
  let removed = linked.remove("linked")
  assert_true(store.authorize_trace(removed, request).policies.is_empty())
  let uid : EntityId = { kind: "Group", id: "loop", }
  let cyclic = [{ entity: { uid, attrs: {}, parents: [uid], }, tags: {}, }]
  let rejected = try {
    let _ = authorize_trace_with_tags(linked, request, cyclic)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "trace preserves policy order at the policy count limit" {
  let source = StringBuilder()
  for i in 0..<4096 {
    source.write_string("@id(\"p\{i}\") permit(principal, action, resource);\n")
  }
  let policies = parse_policies(source.to_string())
  let trace = EntityStore::new([]).authorize_trace(policies, sample_request())
  assert_true(
    trace.policies.length() == 4096 && trace.response.reasons.length() == 4096,
  )
  assert_true(trace.policies[0].policy_id == "p0")
  assert_true(trace.policies[4095].policy_id == "p4095")
  assert_true(trace.policies[4095].outcome == Matched)
}
