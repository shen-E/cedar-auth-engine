///|
test "reserved words are rejected in entity type paths and bare attributes" {
  for
    name in [
      "if", "then", "else", "in", "is", "has", "like", "true", "false", "__cedar",
    ] {
    for
      expression in [
        "Namespace::" + name + "::\"id\" == Namespace::\"id\"",
        name + "::\"id\" == Namespace::\"id\"",
        "{" + name + ": 1}[\"value\"] == 1",
        "context." + name + " == 1",
        "context has " + name,
      ] {
      let rejected = try {
        let _ = parse_policies(
          "permit(principal, action, resource) when { " + expression + " };",
        )
        false
      } catch {
        _ => true
      }
      assert_true(rejected, msg=expression)
    }
  }
}

///|
test "quoted reserved attributes remain accessible" {
  let request = {
    ..sample_request(),
    context: {
      "if": LongValue(7L),
      "true": StringValue("yes"),
      "__cedar": BoolValue(true),
    },
  }
  let policies = parse_policies(
    "permit(principal, action, resource) when { context has \"if\" && context[\"if\"] == 7 && context[\"true\"] == \"yes\" && context[\"__cedar\"] && {\"then\": 1}[\"then\"] == 1 };",
  )
  assert_true(authorize(policies, request, []).is_authorized())
}

///|
test "request variable names are also valid entity type names" {
  for kind in ["principal", "action", "resource", "context"] {
    let request = {
      ..sample_request(),
      principal: { kind, id: "alice", },
      context: { "principal": StringValue("read") },
    }
    request.principal.validate()
    let source = "permit(principal == " +
      kind +
      "::\"alice\", action, resource) when { principal == " +
      kind +
      "::\"alice\" && context.principal == \"read\" };"
    let policy = parse_policies(source)
    assert_true(authorize(policy, request, []).is_authorized(), msg=kind)
  }
}

///|
test "contextual identifiers remain usable as unquoted attributes and namespaces" {
  for
    name in [
      "principal", "action", "resource", "context", "permit", "forbid", "when", "unless",
      "ip",
    ] {
    let source = "permit(principal, action, resource) when { {" +
      name +
      ": 1}." +
      name +
      " == 1 && " +
      name +
      "::User::\"id\" == " +
      name +
      "::User::\"id\" };"
    assert_true(
      authorize(parse_policies(source), sample_request(), []).is_authorized(),
      msg=name,
    )
  }
}
