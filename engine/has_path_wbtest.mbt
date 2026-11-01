///|
fn nested_request() -> Request {
  {
    ..sample_request(),
    context: {
      "profile": RecordValue({
        "team": RecordValue({
          "name": StringValue("security"),
          "active": BoolValue(false),
        }),
        "flag": LongValue(1L),
      }),
      "profile.team": StringValue("literal"),
      "link": EntityValue({ kind: "User", id: "manager", }),
      "missingLink": EntityValue({ kind: "User", id: "unknown", }),
    },
  }
}

///|
fn nested_entities() -> Array[Entity] {
  [
    {
      uid: { kind: "User", id: "manager", },
      attrs: { "access": RecordValue({ "level": LongValue(3L) }) },
      parents: [],
    },
    {
      uid: { kind: "File", id: "report", },
      attrs: { "owner": EntityValue({ kind: "User", id: "manager", }) },
      parents: [],
    },
  ]
}

///|
fn nested_condition(condition : String) -> Response raise PolicyError {
  let source = "permit(principal, action, resource) when { " + condition + " };"
  authorize(parse_policies(source), nested_request(), nested_entities())
}

///|
test "nested has checks all segments without missing attribute errors" {
  for
    condition in [
      "context has profile.team.name", "context has profile.team.active", "context has \"profile.team\"",
      "context has link.access.level", "resource has owner.access.level", "context.profile has team.name",
      "context has profile.team && context.profile.team.name == \"security\"", "(context has profile.team.name) == true",
      "!(context has profile.missing.name)", "!(context has missing.team.name)",
      "!(context has missingLink.name)",
    ] {
    let result = nested_condition(condition)
    assert_true(
      result.decision == Allow && result.errors.is_empty(),
      msg=condition,
    )
  }
  for
    condition in [
      "context has missing.team", "context has profile.missing.name", "context has profile.team.missing",
      "context has missingLink.name", "resource has owner.access.missing", "resource has absent.more",
    ] {
    let result = nested_condition(condition)
    assert_true(
      result.decision == Deny && result.errors.is_empty(),
      msg=condition,
    )
  }
}

///|
test "nested has reports invalid types and evaluates its base normally" {
  for
    condition in [
      "context has profile.flag.name", "context has profile.team.name.more", "1 has name",
      "context.missing has team.name", "resource.absent has team.name",
    ] {
    let result = nested_condition(condition)
    assert_true(
      result.decision == Deny && result.errors.length() == 1,
      msg=condition,
    )
  }
  let ignored = nested_condition("true || (context has profile.flag.name)")
  assert_true(ignored.decision == Allow && ignored.errors.is_empty())
  let short = nested_condition(
    "context has missing.flag.name && context.missing.flag.name == 1",
  )
  assert_true(short.decision == Deny && short.errors.is_empty())
}

///|
test "nested has syntax is limited to identifier paths or one quoted attribute" {
  for
    condition in [
      "context has \"profile\".team", "context has profile.\"team\"", "context has profile[\"team\"]",
      "context has profile.team()", "context has profile.true", "context has profile.if",
      "context has true", "context has __cedar", "context has profile.", "context has profile..name",
      "context has profile.1", "context has profile.team == true",
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
    assert_true(rejected, msg=condition)
  }
}

///|
test "has and attribute paths enforce their segment limits" {
  let prefix = "permit(principal, action, resource) when { "
  let path = StringBuilder()
  path.write_string(prefix + "context has a")
  for _ in 0..<127 {
    path.write_string(".a")
  }
  path.write_string(" };")
  let _ = parse_policies(path.to_string())
  let too_long = StringBuilder()
  too_long.write_string(prefix + "context has a")
  for _ in 0..<128 {
    too_long.write_string(".a")
  }
  too_long.write_string(" };")
  let rejected = try {
    let _ = parse_policies(too_long.to_string())
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let access = StringBuilder()
  access.write_string(prefix + "context")
  for _ in 0..<128 {
    access.write_string(".a")
  }
  access.write_string(" == true };")
  let _ = parse_policies(access.to_string())
  let access_long = StringBuilder()
  access_long.write_string(prefix + "context")
  for _ in 0..<129 {
    access_long.write_string(".a")
  }
  access_long.write_string(" == true };")
  let rejected = try {
    let _ = parse_policies(access_long.to_string())
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
