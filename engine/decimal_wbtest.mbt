///|
test "decimal parsing uses exact signed fixed-point values" {
  for
    item in [
      ("0.0", 0L),
      ("-0.0000", 0L),
      ("00.0001", 1L),
      ("1.1", 11000L),
      ("-0.0012", -12L),
      ("123.45", 1234500L),
      ("922337203685477.5807", 9223372036854775807L),
      ("-922337203685477.5808", -9223372036854775808L),
      ("00000000000000000000000001.0", 10000L),
    ] {
    let (text, expected) = item
    assert_true(Decimal::parse(text).scaled == expected, msg=text)
  }
  for
    text in [
      "", "0", ".0", "1.", "-.0", "+1.0", "--1.0", "1.2.3", "1.00000", " 1.0", "1.0 ",
      "1e1.0", "-922337203685477.5809", "922337203685477.5808", "1000000000000000.0",
      "-1000000000000000.0", "１２.０",
    ] {
    let rejected = try {
      let _ = Decimal::parse(text)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "decimal expressions support comparisons and error skipping" {
  let conditions = [
    ("decimal(\"1.00\") == decimal(\"01.0\")", Allow, 0),
    ("decimal(\"-0.0001\").lessThan(decimal(\"0.0\"))", Allow, 0),
    ("decimal(\"1.0\").lessThan(decimal(\"1.0\"))", Deny, 0),
    ("decimal(\"1.0\").lessThanOrEqual(decimal(\"1.0\"))", Allow, 0),
    ("decimal(\"2.0\").greaterThan(decimal(\"1.0\"))", Allow, 0),
    ("decimal(\"1.0\").greaterThanOrEqual(decimal(\"1.0\"))", Allow, 0),
    ("decimal(\"1.0\") == 1", Deny, 0),
    ("[decimal(\"1.0\")].contains(decimal(\"1.0000\"))", Allow, 0),
    ("decimal(1) == decimal(\"1.0\")", Deny, 1),
    ("decimal(\"1.00000\") == decimal(\"1.0\")", Deny, 1),
    ("decimal(\"1.0\").lessThan(1)", Deny, 1),
    ("1.greaterThan(decimal(\"1.0\"))", Deny, 1),
    ("false && decimal(\"bad\") == decimal(\"1.0\")", Deny, 0),
  ]
  for item in conditions {
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
test "decimal values work in context entity attributes and tags" {
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.amount.lessThanOrEqual(resource.limit) && resource.getTag(\"floor\").lessThan(context.amount) };",
  )
  let request = request_from_json(
    parse_json(
      "{\"principal\":{\"type\":\"User\",\"id\":\"alice\"},\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"report\"},\"context\":{\"amount\":{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"9.9999\"}}}}",
    ),
  )
  let entities = tagged_entities_from_json(
    parse_json(
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{\"limit\":{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"10.0\"}}},\"parents\":[],\"tags\":{\"floor\":{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"0.0\"}}}}]",
    ),
  )
  let direct = authorize_with_tags(policy, request, entities)
  assert_true(direct.decision == Allow && direct.errors.is_empty())
  let store = EntityStore::new_with_tags(entities)
  assert_true(store.authorize(policy, request).decision == Allow)
  for invalid in ["1", "1.00001", "922337203685477.5808"] {
    let json = "{\"principal\":{\"type\":\"User\",\"id\":\"a\"},\"action\":{\"type\":\"Action\",\"id\":\"a\"},\"resource\":{\"type\":\"File\",\"id\":\"f\"},\"context\":{\"x\":{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"" +
      invalid +
      "\"}}}}"
    let rejected = try {
      let _ = request_from_json(parse_json(json))
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "decimal calls enforce their syntax and arity" {
  for
    expression in [
      "decimal()", "decimal(\"1.0\", \"2.0\")", "decimal(\"1.0\").lessThan()", "decimal(\"1.0\").lessThan(decimal(\"2.0\"), decimal(\"3.0\"))",
      "decimal(\"1.0\").greaterThanOrEqual()",
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
