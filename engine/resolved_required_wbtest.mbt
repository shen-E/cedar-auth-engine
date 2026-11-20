///|
test "resolved records enforce required and optional fields recursively" {
  let spec = parse_json(
    "{\"type\":\"Record\",\"attributes\":{\"name\":{\"type\":\"String\"},\"nickname\":{\"type\":\"String\",\"required\":false},\"nested\":{\"type\":\"Record\",\"attributes\":{\"enabled\":{\"type\":\"Bool\",\"required\":true}}}}}",
  )
  let good = parse_json("{\"name\":\"a\",\"nested\":{\"enabled\":true}}")
  let decoded = decode_resolved_value(good, spec, 0, Ref(0), Ref(1000000))
  assert_true(decoded is RecordValue(_))
  for
    text in [
      "{\"nested\":{\"enabled\":true}}", "{\"name\":\"a\",\"nested\":{}}", "{\"name\":\"a\",\"nested\":{\"enabled\":true},\"nickname\":null}",
    ] {
    let rejected = try {
      let _ = decode_resolved_value(
        parse_json(text),
        spec,
        0,
        Ref(0),
        Ref(1000000),
      )
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "resolved record field checks have bounded work" {
  let spec = parse_json(
    "{\"type\":\"Record\",\"attributes\":{\"a\":{\"type\":\"Bool\",\"required\":false},\"b\":{\"type\":\"Bool\",\"required\":false}}}",
  )
  let rejected = try {
    let _ = decode_resolved_value(parse_json("{}"), spec, 0, Ref(0), Ref(1))
    false
  } catch {
    PolicyError(message) =>
      message == "resolved schema field work limit exceeded"
  }
  assert_true(rejected)
}
