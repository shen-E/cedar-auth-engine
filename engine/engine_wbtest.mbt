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
    "permit(principal, action, resource) when { context.x > 1 };", "permit(principal, action, resource)",
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
