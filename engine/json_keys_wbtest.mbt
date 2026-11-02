///|
test "duplicate JSON keys are scoped to their own object" {
  let valid = parse_json(
    "{\"name\":1,\"nested\":{\"name\":2},\"items\":[{\"name\":3},{\"name\":4}],\"text\":\"name: {\\\"name\\\": 1}\"}",
  )
  assert_true(valid is Object(_))
  for
    text in [
      "{\"name\":1,\"na\\u006de\":2}", "{\"outer\":{\"x\":1,\"\\u0078\":2}}", "[{\"x\":1},{\"x\":1,\"x\":2}]",
      "{\"😀\":1,\"\\ud83d\\ude00\":2}",
    ] {
    let rejected = try {
      let _ = parse_json(text)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "wide JSON objects retain duplicate-key detection" {
  let builder = StringBuilder()
  builder.write_char('{')
  for i in 0..<12000 {
    if i > 0 {
      builder.write_char(',')
    }
    builder.write_string("\"key")
    builder.write_string(i.to_string())
    builder.write_string("\":0")
  }
  let prefix = builder.to_string()
  assert_true(parse_json(prefix + "}") is Object(_))
  let rejected = try {
    let _ = parse_json(prefix + ",\"key0\":1}")
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
