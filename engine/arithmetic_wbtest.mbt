///|
test "arithmetic precedence, signed literals and associativity" {
  for
    condition in [
      "1+2*3 == 7", "(1+2)*3 == 9", "10-3-2 == 5", "1--2 == 3", "1*-2 == -2", "--1 == 1",
      "- -1 == 1", "- 1 == -1", "-9223372036854775808 + 1 == -9223372036854775807",
      "9223372036854775807 - 1 == 9223372036854775806", "(-3037000499 * -3037000499) == 9223372030926249001",
      "(-9223372036854775808 * 0) == 0", "0 - -9223372036854775807 == 9223372036854775807",
      "true || (9223372036854775807 + 1 > 0)", "if true then true else (9223372036854775807 + 1 > 0)",
    ] {
    let result = evaluate_condition(condition)
    assert_true(
      result.decision == Allow && result.errors.is_empty(),
      msg=condition,
    )
  }
}

///|
test "integer overflow and type errors skip the affected policy" {
  for
    condition in [
      "9223372036854775807 + 1 > 0", "-9223372036854775808 + -1 < 0", "-9223372036854775808 - 1 < 0",
      "9223372036854775807 - -1 > 0", "-(-9223372036854775808) > 0", "- -9223372036854775808 > 0",
      "9223372036854775807 * 2 > 0", "-9223372036854775808 * -1 > 0", "-1 * -9223372036854775808 > 0",
      "-9223372036854775808 * 2 > 0", "2 * -9223372036854775808 > 0", "3037000500 * 3037000500 > 0",
      "true + 1 == 2", "1 * false == 0", "-true == 1",
    ] {
    let result = evaluate_condition(condition)
    assert_true(
      result.decision == Deny && result.errors.length() == 1,
      msg=condition,
    )
  }
  let source = "permit(principal, action, resource); forbid(principal, action, resource) when { 9223372036854775807 + 1 > 0 };"
  let response = authorize(parse_policies(source), sample_request(), [])
  assert_true(response.decision == Allow && response.reasons == ["policy0"])
  assert_true(
    response.errors.length() == 1 && response.errors[0].policy_id == "policy1",
  )
}

///|
test "arithmetic syntax and resource limits" {
  for
    condition in [
      "1 / 2 == 0", "9223372036854775808 == 0", "0 - 9223372036854775808 == 0", "-(9223372036854775808) == 0",
      "-----1 == 0", "!-1 == 0", "-!true == 0",
    ] {
    let rejected = try {
      let _ = parse_policies(
        "permit(principal, action, resource) when { " + condition + " };",
      )
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=condition)
  }
  let builder = StringBuilder()
  builder.write_string("permit(principal, action, resource) when { 1")
  for _ in 0..<129 {
    builder.write_string(" + 1")
  }
  builder.write_string(" == 1 };")
  let rejected = try {
    let _ = parse_policies(builder.to_string())
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
