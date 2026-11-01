///|
fn sample_request() -> Request {
  {
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: { "authenticated": BoolValue(true) },
  }
}

///|
test "default deny and forbid overrides permit" {
  let empty = parse_policies("")
  assert_true(authorize(empty, sample_request(), []).decision == Deny)
  let policies = parse_policies(
    "permit(principal, action, resource); forbid(principal, action, resource);",
  )
  let result = authorize(policies, sample_request(), [])
  assert_true(result.decision == Deny)
  assert_true(result.reasons == ["policy1"])
}

///|
test "entity ancestry, attribute, and short circuit" {
  let policy = parse_policies(
    "permit(principal in Group::\"team\", action == Action::\"read\", resource) when { context.authenticated && resource.owner == principal };",
  )
  let entities = [
    {
      uid: { kind: "User", id: "alice", },
      attrs: {},
      parents: [{ kind: "Group", id: "staff", }],
    },
    {
      uid: { kind: "Group", id: "staff", },
      attrs: {},
      parents: [{ kind: "Group", id: "team", }],
    },
    {
      uid: { kind: "File", id: "report", },
      attrs: { "owner": EntityValue({ kind: "User", id: "alice", }) },
      parents: [],
    },
  ]
  let result = authorize(policy, sample_request(), entities)
  assert_true(result.decision == Allow)
  assert_true(result.errors.is_empty())
}

///|
test "evaluation errors are reported and policies skipped" {
  let policy = parse_policies(
    "permit(principal, action, resource); forbid(principal, action, resource) when { resource.missing == true };",
  )
  let result = authorize(policy, sample_request(), [])
  assert_true(result.decision == Allow)
  assert_true(result.reasons == ["policy0"])
  assert_true(result.errors.length() == 1)
  assert_true(result.errors[0].policy_id == "policy1")
}

///|
test "set equality and int64 values" {
  let policy = parse_policies(
    "permit(principal, action, resource) when { [1, 2, 1] == [2, 1] && 9223372036854775807 == 9223372036854775807 };",
  )
  assert_true(authorize(policy, sample_request(), []).decision == Allow)
}

///|
test "reject invalid syntax and unsupported operator" {
  let invalid = [
    "permit(principal, action, resource) when { context.x + 1 > 1 };", "permit(principal, action, resource)",
    "permit(principal, action, resource) when { context.x == };", "permit(principal, action, resource) when { 9223372036854775808 == 1 };",
  ]
  for text in invalid {
    let rejected = try {
      let _ = parse_policies(text)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "JSON integer and entity values" {
  let json = @json.parse(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{\"count\":9223372036854775807,\"owner\":{\"__entity\":{\"type\":\"User\",\"id\":\"alice\"}}},\"parents\":[]}]",
  )
  let entities = entities_from_json(json)
  let policies = parse_policies(
    "permit(principal, action, resource) when { resource.count == 9223372036854775807 && resource.owner == principal };",
  )
  assert_true(authorize(policies, sample_request(), entities).decision == Allow)
}

///|
test "duplicate JSON keys and unsupported values are rejected" {
  let duplicate = try {
    let _ = parse_json("{\"name\":1,\"na\\u006de\":2}")
    false
  } catch {
    _ => true
  }
  assert_true(duplicate)
  let extension = parse_json(
    "[{\"uid\":{\"type\":\"X\",\"id\":\"x\"},\"attrs\":{\"x\":{\"__extn\":{}}},\"parents\":[]}]",
  )
  let rejected = try {
    let _ = entities_from_json(extension)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "condition operators and short circuit" {
  let policy = parse_policies(
    "permit(principal, action, resource) when { context has authenticated && (context.authenticated || resource.absent) && {name: \"ok\"}.name == \"ok\" };",
  )
  let result = authorize(policy, sample_request(), [])
  assert_true(result.decision == Allow)
  assert_true(result.errors.is_empty())
}

///|
test "duplicate entities are rejected" {
  let entity : Entity = {
    uid: { kind: "User", id: "alice", },
    attrs: {},
    parents: [],
  }
  let rejected = try {
    let _ = authorize(parse_policies(""), sample_request(), [entity, entity])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
fn evaluate_condition(expression : String) -> Response raise PolicyError {
  let source = "permit(principal, action, resource) when { " +
    expression +
    " };"
  authorize(parse_policies(source), sample_request(), [])
}

///|
test "set methods compare values and handle empty sets" {
  let yes = [
    "[1, 2, 2].contains(2)", "[1, 2].containsAll([2, 1, 1])", "[1, 2].containsAll([])",
    "[1, 2].containsAny([9, 2])", "[].isEmpty()", "[[1, 2], {name: 1}].contains([2, 1])",
    "[1, \"x\"].contains(\"x\")",
  ]
  for condition in yes {
    let response = evaluate_condition(condition)
    assert_true(response.decision == Allow)
    assert_true(response.errors.is_empty())
  }
  let no = [
    "[].contains(1)", "[1].containsAll([1, 2])", "[1].containsAny([])", "[1].isEmpty()",
    "[1].contains(\"1\")",
  ]
  for condition in no {
    let response = evaluate_condition(condition)
    assert_true(response.decision == Deny)
    assert_true(response.errors.is_empty())
  }
}

///|
test "integer comparisons retain signed 64 bit boundaries" {
  let yes = [
    "-9223372036854775808 < 9223372036854775807", "9223372036854775807 >= 9223372036854775807",
    "-5 <= -5", "0 > -1", "1 < 2 && 4 >= 4",
  ]
  for condition in yes {
    assert_true(evaluate_condition(condition).decision == Allow)
  }
  for condition in ["1 < 1", "2 <= 1", "1 > 1", "1 >= 2"] {
    let response = evaluate_condition(condition)
    assert_true(response.decision == Deny)
    assert_true(response.errors.is_empty())
  }
}

///|
test "invalid operand types produce policy diagnostics" {
  for
    condition in [
      "\"x\".contains(\"x\")", "[1].containsAll(1)", "[1].containsAny(1)", "1.isEmpty()",
      "1 < \"2\"",
    ] {
    let response = evaluate_condition(condition)
    assert_true(response.decision == Deny)
    assert_true(response.errors.length() == 1)
    assert_true(response.errors[0].policy_id == "policy0")
  }
}

///|
test "set method syntax rejects unknown methods and wrong argument counts" {
  for
    condition in [
      "[1].contains()", "[1].contains(1, 2)", "[1].isEmpty(1)", "[1].unknown(1)",
    ] {
    let source = "permit(principal, action, resource) when { " +
      condition +
      " };"
    let rejected = try {
      let _ = parse_policies(source)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "nested set calls respect parser depth limits" {
  let builder = StringBuilder()
  builder.write_string("permit(principal, action, resource) when { ")
  for _ in 0..<130 {
    builder.write_string("[true].contains(")
  }
  builder.write_string("true")
  for _ in 0..<130 {
    builder.write_string(")")
  }
  builder.write_string(" };")
  let rejected = try {
    let _ = parse_policies(builder.to_string())
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
