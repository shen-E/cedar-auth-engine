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
