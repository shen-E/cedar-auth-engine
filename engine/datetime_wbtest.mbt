///|
test "datetime parsing validates dates, offsets and epoch milliseconds" {
  for
    item in [
      ("1970-01-01", 0L),
      ("1970-01-01T00:00:00Z", 0L),
      ("1969-12-31T23:59:59.999Z", -1L),
      ("1970-01-01T01:00:00+0100", 0L),
      ("1969-12-31T19:00:00-0500", 0L),
      ("1970-01-01T01:00:00.001+0100", 1L),
      ("2000-02-29", 951782400000L),
      ("0000-01-01", -62167219200000L),
      ("9999-12-31T23:59:59.999Z", 253402300799999L),
    ] {
    let (text, expected) = item
    assert_true(DateTime::parse(text).milliseconds == expected, msg=text)
  }
  for
    text in [
      "", "1970-1-01", "01970-01-01", "1970-00-01", "1970-13-01", "1970-01-00", "1900-02-29",
      "2023-02-29", "2024-04-31", "2024-01-01Z", "2024-01-01 ", "2024-01-01T00:00:00",
      "2024-01-01t00:00:00z", "2024-01-01T24:00:00Z", "2024-01-01T00:60:00Z", "2016-12-31T23:59:60Z",
      "2024-01-01T00:00:00.1Z", "2024-01-01T00:00:00.0000Z", "2024-01-01T00:00:00+00:00",
      "2024-01-01T00:00:00+2400", "2024-01-01T00:00:00+0060",
    ] {
    let rejected = try {
      let _ = DateTime::parse(text)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "datetime comparisons offsets and UTC extraction" {
  for
    item in [
      (
        "datetime(\"1970-01-01\") == datetime(\"1969-12-31T19:00:00-0500\")",
        Allow,
        0,
      ),
      ("datetime(\"1970-01-01\") < datetime(\"1970-01-02\")", Allow, 0),
      ("datetime(\"1970-01-01\") <= datetime(\"1970-01-01\")", Allow, 0),
      ("datetime(\"1970-01-02\") > datetime(\"1970-01-01\")", Allow, 0),
      ("datetime(\"1970-01-01\") >= datetime(\"1970-01-01\")", Allow, 0),
      ("datetime(\"1970-01-01\") == 0", Deny, 0),
      ("datetime(\"1970-01-01\") < 0", Deny, 1),
      (
        "datetime(\"2024-10-15\").offset(duration(\"1h\")) == datetime(\"2024-10-15T01:00:00Z\")",
        Allow,
        0,
      ),
      (
        "datetime(\"2024-10-15T01:00:00Z\").durationSince(datetime(\"2024-10-15\")) == duration(\"1h\")",
        Allow,
        0,
      ),
      (
        "datetime(\"1969-12-31T23:59:59.999Z\").toDate() == datetime(\"1969-12-31\")",
        Allow,
        0,
      ),
      (
        "datetime(\"1969-12-31T23:59:59.999Z\").toTime() == duration(\"23h59m59s999ms\")",
        Allow,
        0,
      ),
      (
        "datetime(\"2025-02-20T22:00:00-0500\").toDate() == datetime(\"2025-02-21\")",
        Allow,
        0,
      ),
      (
        "datetime(\"2025-02-20T22:00:00-0500\").toTime() == duration(\"3h\")",
        Allow,
        0,
      ),
      (
        "datetime(\"1970-01-01\").offset(duration(\"9223372036854775807ms\")).offset(duration(\"1ms\")) == datetime(\"1970-01-01\")",
        Deny,
        1,
      ),
      (
        "datetime(\"1970-01-01\").offset(duration(\"-9223372036854775808ms\")).toDate() == datetime(\"1970-01-01\")",
        Deny,
        1,
      ),
      (
        "datetime(\"1970-01-01\").offset(duration(\"-9223372036854775808ms\")).toTime() >= duration(\"0ms\")",
        Allow,
        0,
      ),
      (
        "datetime(\"1970-01-01\").durationSince(datetime(\"1970-01-01\").offset(duration(\"-9223372036854775808ms\"))) == duration(\"0ms\")",
        Deny,
        1,
      ),
      ("datetime(1) == datetime(\"1970-01-01\")", Deny, 1),
      (
        "datetime(\"1970-01-01\").offset(1) == datetime(\"1970-01-01\")",
        Deny,
        1,
      ),
      ("duration(\"1h\").toDate() == datetime(\"1970-01-01\")", Deny, 1),
      ("true || datetime(\"bad\") == datetime(\"1970-01-01\")", Allow, 0),
    ] {
    let (expression, decision, errors) = item
    let policy = parse_policies(
      "permit(principal, action, resource) when { " + expression + " };",
    )
    let result = authorize(policy, sample_request(), [])
    assert_true(
      result.decision == decision && result.errors.length() == errors,
      msg=expression,
    )
  }
}

///|
test "datetime JSON values work in context, attributes, tags and snapshots" {
  let request = request_from_json(
    parse_json(
      "{\"principal\":{\"type\":\"User\",\"id\":\"alice\"},\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"report\"},\"context\":{\"now\":{\"__extn\":{\"fn\":\"datetime\",\"arg\":\"2026-11-01T12:00:00Z\"}}}}",
    ),
  )
  let entities = tagged_entities_from_json(
    parse_json(
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{\"expires\":{\"__extn\":{\"fn\":\"datetime\",\"arg\":\"2026-11-02\"}}},\"parents\":[],\"tags\":{\"starts\":{\"__extn\":{\"fn\":\"datetime\",\"arg\":\"2026-11-01\"}}}}]",
    ),
  )
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.now < resource.expires && context.now >= resource.getTag(\"starts\") };",
  )
  assert_true(authorize_with_tags(policy, request, entities).decision == Allow)
  assert_true(
    EntityStore::new_with_tags(entities).authorize(policy, request).decision ==
    Allow,
  )
  for invalid in ["2023-02-29", "2026-11-01T00:00:00", "2026-11-01T24:00:00Z"] {
    let json = "{\"__extn\":{\"fn\":\"datetime\",\"arg\":\"" + invalid + "\"}}"
    let rejected = try {
      let _ = json_value(parse_json(json), 0, Ref(0))
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "datetime calls reject invalid arity" {
  for
    expression in [
      "datetime()", "datetime(\"2024-01-01\", \"2024-01-02\")", "datetime(\"2024-01-01\").offset()",
      "datetime(\"2024-01-01\").toDate(1)",
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
