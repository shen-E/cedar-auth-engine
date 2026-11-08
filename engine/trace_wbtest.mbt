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
    let details = store.authorize_details(policies, request)
    let response = store.authorize(policies, request)
    assert_true(
      response_to_json(trace.response).stringify() ==
      response_to_json(response).stringify(),
    )
    assert_true(trace.policies.length() == 96)
    for j in 0..<trace.policies.length() {
      assert_true(trace.policies[j].policy_id == "p\{j}")
      assert_true(details.policies[j].outcome == trace.policies[j].outcome)
    }
    assert_true(
      response_to_json(details.response).stringify() ==
      response_to_json(response).stringify(),
    )
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
  assert_true(
    store.authorize_details(linked, request).policies[0].stages[2].outcome ==
    StagePassed,
  )
  assert_true(
    store.authorize_details(linked, {
      ..request,
      resource: { kind: "File", id: "other", },
    }).policies[0].stages[2].outcome ==
    StageFailed,
  )
  let removed = linked.remove("linked")
  assert_true(store.authorize_trace(removed, request).policies.is_empty())
  assert_true(store.authorize_details(removed, request).policies.is_empty())
  let uid : EntityId = { kind: "Group", id: "loop", }
  let cyclic = [{ entity: { uid, attrs: {}, parents: [uid], }, tags: {}, }]
  let rejected = try {
    let _ = authorize_trace_with_tags(linked, request, cyclic)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let details_rejected = try {
    let _ = authorize_details_with_tags(linked, request, cyclic)
    false
  } catch {
    _ => true
  }
  assert_true(details_rejected)
}

///|
test "details report scope and condition stages in short-circuit order" {
  let policies = parse_policies(
    "permit(principal == User::\"alice\", action == Action::\"read\", resource == File::\"report\") when { context.active } unless { context.blocked } when { context.missing };",
  )
  let store = EntityStore::new([])
  let request : Request = {
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: { "active": BoolValue(true), "blocked": BoolValue(false) },
  }
  let cases = [
    (
      { ..request, principal: { kind: "User", id: "bob", }, },
      [
        StageFailed,
        StageSkipped,
        StageSkipped,
        StageSkipped,
        StageSkipped,
        StageSkipped,
      ],
    ),
    (
      { ..request, action: { kind: "Action", id: "write", }, },
      [
        StagePassed,
        StageFailed,
        StageSkipped,
        StageSkipped,
        StageSkipped,
        StageSkipped,
      ],
    ),
    (
      { ..request, resource: { kind: "File", id: "other", }, },
      [
        StagePassed,
        StagePassed,
        StageFailed,
        StageSkipped,
        StageSkipped,
        StageSkipped,
      ],
    ),
    (
      { ..request, context: { "active": BoolValue(false) }, },
      [
        StagePassed,
        StagePassed,
        StagePassed,
        StageFailed,
        StageSkipped,
        StageSkipped,
      ],
    ),
    (
      {
        ..request,
        context: { "active": BoolValue(true), "blocked": BoolValue(true) },
      },
      [
        StagePassed,
        StagePassed,
        StagePassed,
        StagePassed,
        StageFailed,
        StageSkipped,
      ],
    ),
  ]
  for (case, expected) in cases {
    let detail = store.authorize_details(policies, case)
    for i in 0..<expected.length() {
      assert_true(detail.policies[0].stages[i].outcome == expected[i])
    }
    assert_true(
      response_to_json(detail.response).stringify() ==
      response_to_json(store.authorize(policies, case)).stringify(),
    )
  }
  let detail = store.authorize_details_checked(policies, request)
  assert_true(
    detail.policies[0].stages.map(stage => stage.kind) ==
    ["principal", "action", "resource", "when", "unless", "when"],
  )
  assert_true(detail.policies[0].stages[4].outcome == StagePassed)
  assert_true(detail.policies[0].stages[5].outcome is StageError(_))
  assert_true(detail.policies[0].outcome is EvaluationFailed(_))
  assert_true(
    response_to_json(detail.response).stringify() ==
    response_to_json(store.authorize(policies, request)).stringify(),
  )
  let invalid = { ..request, principal: { kind: "bad type", id: "a", }, }
  let rejected = try {
    let _ = store.authorize_details_checked(policies, invalid)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "details share the comparison budget across conditions" {
  let left = []
  let right = []
  for i in 0..<1100 {
    left.push(LongValue(i.to_int64()))
    right.push(LongValue((1099 - i).to_int64()))
  }
  let request = {
    ..sample_request(),
    context: { "left": SetValue(left), "right": SetValue(right) },
  }
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.left == context.right } when { context.left == context.right } when { true };",
  )
  let store = EntityStore::new([])
  let detail = store.authorize_details(policy, request)
  assert_true(detail.policies[0].stages[3].outcome == StagePassed)
  assert_true(
    detail.policies[0].stages[4].outcome ==
    StageError("value comparison budget exceeded"),
  )
  assert_true(detail.policies[0].stages[5].outcome == StageSkipped)
  assert_true(
    response_to_json(detail.response).stringify() ==
    response_to_json(store.authorize(policy, request)).stringify(),
  )
}

///|
test "trace preserves policy order at the policy count limit" {
  let source = StringBuilder()
  for i in 0..<4096 {
    source.write_string("@id(\"p\{i}\") permit(principal, action, resource);\n")
  }
  let policies = parse_policies(source.to_string())
  let store = EntityStore::new([])
  let trace = store.authorize_trace(policies, sample_request())
  assert_true(
    trace.policies.length() == 4096 && trace.response.reasons.length() == 4096,
  )
  assert_true(trace.policies[0].policy_id == "p0")
  assert_true(trace.policies[4095].policy_id == "p4095")
  assert_true(trace.policies[4095].outcome == Matched)
  let details = store.authorize_details(policies, sample_request())
  assert_true(details.policies.length() == 4096)
  assert_true(details.policies[4095].stages.length() == 3)
  assert_true(
    response_to_json(details.response).stringify() ==
    response_to_json(trace.response).stringify(),
  )
}
