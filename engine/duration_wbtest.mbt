///|
test "duration parsing preserves sign, precision and bounds" {
  for
    item in [
      ("0ms", 0L),
      ("-0ms", 0L),
      ("1d2h3m4s5ms", 93784005L),
      ("-1h30m", -5400000L),
      ("00h001m", 60000L),
      ("1h60m", 7200000L),
      ("9223372036854775807ms", 9223372036854775807L),
      ("-9223372036854775808ms", -9223372036854775808L),
      ("00000000000000000000001ms", 1L),
    ] {
    let (text, expected) = item
    assert_true(Duration::parse(text).milliseconds == expected, msg=text)
  }
  for
    text in [
      "", "-", "0", "ms", "1", "+1h", "--1h", "1h-1m", "1m1h", "1s1s", "1ms1s", "1h ",
      " 1h", "1.5h", "1H", "１h", "9223372036854775808ms", "-9223372036854775809ms",
      "106751991168d", "1d9223372036854775807ms",
    ] {
    let rejected = try {
      let _ = Duration::parse(text)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "duration comparison and conversion use signed milliseconds" {
  for
    item in [
      ("duration(\"1h30m\") == duration(\"90m\")", Allow, 0),
      ("duration(\"-1ms\") < duration(\"0ms\")", Allow, 0),
      ("duration(\"1h\") <= duration(\"60m\")", Allow, 0),
      ("duration(\"2h\") > duration(\"1h\")", Allow, 0),
      ("duration(\"1h\") >= duration(\"60m\")", Allow, 0),
      ("duration(\"1h\") < duration(\"60m\")", Deny, 0),
      ("duration(\"1h\") == 3600000", Deny, 0),
      ("duration(\"1h\") < 3600000", Deny, 1),
      ("duration(\"4s100ms\").toMilliseconds() == 4100", Allow, 0),
      ("duration(\"-1500ms\").toSeconds() == -1", Allow, 0),
      ("duration(\"-1ms\").toSeconds() == 0", Allow, 0),
      ("duration(\"4m70s\").toMinutes() == 5", Allow, 0),
      ("duration(\"4h70m\").toHours() == 5", Allow, 0),
      ("duration(\"4d30h\").toDays() == 5", Allow, 0),
      (
        "duration(\"-9223372036854775808ms\").toMilliseconds() == -9223372036854775808",
        Allow,
        0,
      ),
      ("duration(1) == duration(\"1s\")", Deny, 1),
      ("duration(\"1s1h\") == duration(\"1h1s\")", Deny, 1),
      ("1.toSeconds() == 1", Deny, 1),
      ("true || duration(\"bad\") == duration(\"0ms\")", Allow, 0),
    ] {
    let (expression, decision, errors) = item
    let policies = parse_policies(
      "permit(principal, action, resource) when { " + expression + " };",
    )
    let response = authorize(policies, sample_request(), [])
    assert_true(
      response.decision == decision && response.errors.length() == errors,
      msg=expression,
    )
  }
}

///|
test "duration JSON values support context attributes tags and snapshots" {
  let request = request_from_json(
    parse_json(
      "{\"principal\":{\"type\":\"User\",\"id\":\"alice\"},\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"report\"},\"context\":{\"age\":{\"__extn\":{\"fn\":\"duration\",\"arg\":\"30m\"}}}}",
    ),
  )
  let entities = tagged_entities_from_json(
    parse_json(
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{\"limit\":{\"__extn\":{\"fn\":\"duration\",\"arg\":\"1h\"}}},\"parents\":[],\"tags\":{\"minimum\":{\"__extn\":{\"fn\":\"duration\",\"arg\":\"1m\"}}}}]",
    ),
  )
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.age <= resource.limit && context.age >= resource.getTag(\"minimum\") };",
  )
  assert_true(authorize_with_tags(policy, request, entities).decision == Allow)
  assert_true(
    EntityStore::new_with_tags(entities).authorize(policy, request).decision ==
    Allow,
  )
  for invalid in ["1", "1s1h", "9223372036854775808ms"] {
    let json = "{\"__extn\":{\"fn\":\"duration\",\"arg\":\"" + invalid + "\"}}"
    let rejected = try {
      let _ = json_value(parse_json(json), 0)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "duration calls reject invalid arity" {
  for
    expression in [
      "duration()", "duration(\"1s\", \"2s\")", "duration(\"1s\").toSeconds(1)",
    ] {
    let rejected = try {
      let _ = parse_policies(
        "permit(principal, action, resource) when { " + expression + " };",
      )
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}
