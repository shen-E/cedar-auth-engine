///|
test "action index preserves full-scan decisions and diagnostics" {
  let source = StringBuilder()
  for i in 0..<96 {
    source.write_string("@id(\"p\{i}\") ")
    if i % 7 == 0 {
      source.write_string(
        "forbid(principal, action == Action::\"a\{i % 11}\", resource) when { context.missing };\n",
      )
    } else if i % 5 == 0 {
      source.write_string(
        "permit(principal == User::\"alice\", action == Action::\"a\{i % 11}\", resource);\n",
      )
    } else if i % 3 == 0 {
      source.write_string(
        "forbid(principal, action == Action::\"a\{i % 11}\", resource);\n",
      )
    } else {
      source.write_string(
        "permit(principal, action == Action::\"a\{i % 11}\", resource);\n",
      )
    }
  }
  source.write_string(
    "@id(\"fallback-error\") permit(principal, action, resource) when { context.missing };\n",
  )
  source.write_string(
    "@id(\"membership\") permit(principal, action in [Action::\"a1\", Action::\"a3\"], resource);\n",
  )
  let policies = parse_policies(source.to_string())
  assert_true(
    policies.action_index.length() > 0 && policies.fallback.length() > 0,
  )
  let graph = build_entity_graph([])
  let mut seed = 2026
  for i in 0..<200 {
    seed = (seed * 37 + 17) % 9973
    let request = {
      ..sample_request(),
      principal: { kind: "User", id: if i % 2 == 0 { "alice" } else { "bob" }, },
      action: { kind: "Action", id: "a\{seed % 13}", },
    }
    let indexed = authorize_selected(
      policies,
      request,
      EvaluationContext::new(graph),
      true,
    )
    let scan = authorize_selected(
      policies,
      request,
      EvaluationContext::new(graph),
      false,
    )
    assert_true(
      response_to_json(indexed).stringify() ==
      response_to_json(scan).stringify(),
    )
  }
}

///|
test "policy set changes rebuild the action index" {
  let first = parse_policies(
    "@id(\"one\") permit(principal, action == Action::\"read\", resource);",
  )
  let add = parse_policies(
    "@id(\"two\") forbid(principal, action == Action::\"write\", resource);",
  )
  let replacement = parse_policies(
    "@id(\"one\") permit(principal, action == Action::\"write\", resource);",
  )
  let combined = first.merge(add)
  let changed = combined.replace(replacement)
  let removed = changed.remove("two")
  let template = parse_template(
    "permit(principal, action == Action::\"read\", resource == ?resource);",
  )
  let linked = removed.link(template, "link", {
    principal: None,
    resource: Some({ kind: "File", id: "report", }),
  })
  let graph = build_entity_graph([])
  for set in [first, combined, changed, removed, linked] {
    for action in ["read", "write", "other"] {
      let request = {
        ..sample_request(),
        action: { kind: "Action", id: action, },
      }
      let indexed = authorize_selected(
        set,
        request,
        EvaluationContext::new(graph),
        true,
      )
      let scan = authorize_selected(
        set,
        request,
        EvaluationContext::new(graph),
        false,
      )
      assert_true(
        response_to_json(indexed).stringify() ==
        response_to_json(scan).stringify(),
      )
    }
  }
}

///|
test "parser accepts policy boundary and rejects the next policy" {
  let source = StringBuilder()
  for i in 0..<4096 {
    source.write_string("@id(\"p\{i}\") permit(principal, action, resource);\n")
  }
  let text = source.to_string()
  assert_true(parse_policies(text).metadata().length() == 4096)
  let rejected = try {
    let _ = parse_policies(
      text + "@id(\"overflow\") permit(principal, action, resource);",
    )
    false
  } catch {
    error => error.to_string() == "policy count limit exceeded"
  }
  assert_true(rejected)
}

///|
test "principal and action indexes preserve scan order and errors" {
  let policies = parse_policies(
    "@id(\"p0\") permit(principal == User::\"alice\", action, resource);" +
    "@id(\"a0\") permit(principal, action == Action::\"read\", resource);" +
    "@id(\"p1\") forbid(principal == User::\"alice\", action, resource) when { context.missing };" +
    "@id(\"fallback\") forbid(principal, action, resource) when { context.other };" +
    "@id(\"p2\") permit(principal == User::\"bob\", action, resource) when { context.missing };" +
    "@id(\"a1\") permit(principal, action == Action::\"write\", resource);",
  )
  assert_true(policies.principal_index.length() == 2)
  assert_true(policies.action_index.length() == 2)
  assert_true(policies.fallback.length() == 1)
  let graph = build_entity_graph([])
  for principal in ["alice", "bob", "other"] {
    for action in ["read", "write", "other"] {
      let request = {
        ..sample_request(),
        principal: { kind: "User", id: principal, },
        action: { kind: "Action", id: action, },
      }
      let indexed = authorize_selected(
        policies,
        request,
        EvaluationContext::new(graph),
        true,
      )
      let scan = authorize_selected(
        policies,
        request,
        EvaluationContext::new(graph),
        false,
      )
      assert_true(
        response_to_json(indexed).stringify() ==
        response_to_json(scan).stringify(),
      )
      if principal == "alice" && action == "read" {
        assert_true(indexed.reasons == ["p0", "a0"])
        assert_true(indexed.errors.length() == 2)
        assert_true(indexed.errors[0].policy_id == "p1")
        assert_true(indexed.errors[1].policy_id == "fallback")
      }
    }
  }
}

///|
test "principal template bindings and policy changes rebuild indexes" {
  let template = parse_template(
    "permit(principal == ?principal, action == Action::\"read\", resource == ?resource);",
  )
  let original = parse_policies("")
  let alice = { kind: "User", id: "alice", }
  let bob = { kind: "User", id: "bob", }
  let report = { kind: "File", id: "report", }
  let linked = original.link_batch(template, [
    {
      id: "alice",
      bindings: { principal: Some(alice), resource: Some(report), },
    },
    { id: "bob", bindings: { principal: Some(bob), resource: Some(report), }, },
  ])
  assert_true(original.principal_index.length() == 0)
  assert_true(linked.principal_index.length() == 2)
  let replacement = parse_policies(
    "@id(\"alice\") forbid(principal == User::\"carol\", action, resource);",
  )
  let changed = linked.replace(replacement)
  let removed = changed.remove("bob")
  let extra = parse_policies(
    "@id(\"extra\") permit(principal == User::\"dave\", action, resource);",
  )
  let merged = removed.merge(extra)
  let graph = build_entity_graph([])
  for set in [original, linked, changed, removed, merged] {
    for name in ["alice", "bob", "carol", "dave", "unknown"] {
      let request = {
        ..sample_request(),
        principal: { kind: "User", id: name, },
      }
      let indexed = authorize_selected(
        set,
        request,
        EvaluationContext::new(graph),
        true,
      )
      let scan = authorize_selected(
        set,
        request,
        EvaluationContext::new(graph),
        false,
      )
      assert_true(
        response_to_json(indexed).stringify() ==
        response_to_json(scan).stringify(),
      )
    }
  }
  let request = {
    ..sample_request(),
    principal: alice,
    resource: report,
    action: { kind: "Action", id: "read", },
  }
  assert_true(authorize(linked, request, []).reasons == ["alice"])
  assert_true(authorize(changed, request, []).decision == Deny)
}

///|
test "resource index preserves scan order and diagnostics" {
  let policies = parse_policies(
    "@id(\"first\") permit(principal, action == Action::\"read\", resource == File::\"report\");" +
    "@id(\"user\") permit(principal == User::\"alice\", action, resource);" +
    "@id(\"guard\") forbid(principal, action, resource == File::\"report\") when { context.missing };" +
    "@id(\"action\") permit(principal, action == Action::\"read\", resource);" +
    "@id(\"fallback\") permit(principal in Group::\"team\", action, resource == File::\"other\") when { context.unknown };" +
    "@id(\"deny\") forbid(principal, action, resource == File::\"report\") when { context.blocked };",
  )
  assert_true(policies.resource_index.length() == 1)
  assert_true(policies.principal_index.length() == 1)
  assert_true(policies.action_index.length() == 1)
  assert_true(policies.fallback.length() == 1)
  let graph = build_entity_graph([])
  for principal in ["alice", "bob"] {
    for action in ["read", "write"] {
      for resource in ["report", "other", "absent"] {
        for blocked in [true, false] {
          let request : Request = {
            principal: { kind: "User", id: principal, },
            action: { kind: "Action", id: action, },
            resource: { kind: "File", id: resource, },
            context: { "blocked": BoolValue(blocked) },
          }
          let indexed = authorize_selected(
            policies,
            request,
            EvaluationContext::new(graph),
            true,
          )
          let scan = authorize_selected(
            policies,
            request,
            EvaluationContext::new(graph),
            false,
          )
          assert_true(
            response_to_json(indexed).stringify() ==
            response_to_json(scan).stringify(),
          )
          if principal == "alice" && action == "read" && resource == "report" {
            assert_true(indexed.errors.length() == 1)
            assert_true(indexed.errors[0].policy_id == "guard")
            if blocked {
              assert_true(
                indexed.decision == Deny && indexed.reasons == ["deny"],
              )
            } else {
              assert_true(indexed.reasons == ["first", "user", "action"])
            }
          }
        }
      }
    }
  }
}

///|
test "resource template links and updates rebuild the index" {
  let template = parse_template(
    "permit(principal, action == Action::\"read\", resource == ?resource);",
  )
  let a : EntityId = { kind: "File", id: "a", }
  let b : EntityId = { kind: "File", id: "b", }
  let initial = parse_policies("")
  let linked = initial.link_batch(template, [
    { id: "a", bindings: { principal: None, resource: Some(a), }, },
    { id: "b", bindings: { principal: None, resource: Some(b), }, },
  ])
  assert_true(linked.resource_index.length() == 2)
  let changed = linked.replace(
    parse_policies(
      "@id(\"a\") forbid(principal, action, resource == File::\"b\");",
    ),
  )
  let removed = changed.remove("b")
  let added = removed.merge(
    parse_policies(
      "@id(\"c\") permit(principal, action, resource == File::\"c\");",
    ),
  )
  let graph = build_entity_graph([])
  for set in [initial, linked, changed, removed, added] {
    for id in ["a", "b", "c", "none"] {
      let request = { ..sample_request(), resource: { kind: "File", id, }, }
      let indexed = authorize_selected(
        set,
        request,
        EvaluationContext::new(graph),
        true,
      )
      let scan = authorize_selected(
        set,
        request,
        EvaluationContext::new(graph),
        false,
      )
      assert_true(
        response_to_json(indexed).stringify() ==
        response_to_json(scan).stringify(),
      )
    }
  }
}
