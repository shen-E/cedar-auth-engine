///|
test "IP ranges compare complete IPv4 and IPv6 networks" {
  for
    condition in [
      "ip(\"192.168.1.42\").isInRange(ip(\"192.168.1.99/24\"))", "ip(\"192.168.1.42/25\").isInRange(ip(\"192.168.1.0/24\"))",
      "ip(\"203.0.113.2\").isInRange(ip(\"0.0.0.0/0\"))", "ip(\"2001:db8:abcd::1\").isInRange(ip(\"2001:db8:abcd::/48\"))",
      "ip(\"2001:db8:abcd::/48\").isInRange(ip(\"2001:db8::/32\"))", "ip(\"::1\") == ip(\"0:0:0:0:0:0:0:1/128\")",
      "ip(\"127.0.0.1\") == ip(\"127.0.0.1/32\")", "ip(\"127.0.0.1\").isIpv4() && ip(\"::1\").isIpv6()",
      "ip(if true then \"10.0.0.1\" else \"bad\").isIpv4()", "[ip(\"::1\")].contains(ip(\"0:0:0:0:0:0:0:1\"))",
    ] {
    let result = evaluate_condition(condition)
    assert_true(
      result.decision == Allow && result.errors.is_empty(),
      msg=condition,
    )
  }
  for
    condition in [
      "ip(\"192.168.1.128\").isInRange(ip(\"192.168.1.0/25\"))", "ip(\"192.168.1.0/24\").isInRange(ip(\"192.168.1.0/25\"))",
      "ip(\"2001:db9::1\").isInRange(ip(\"2001:db8::/32\"))", "ip(\"::1\").isInRange(ip(\"0.0.0.0/0\"))",
      "ip(\"192.168.1.5/24\") == ip(\"192.168.1.0/24\")",
    ] {
    let result = evaluate_condition(condition)
    assert_true(
      result.decision == Deny && result.errors.is_empty(),
      msg=condition,
    )
  }
}

///|
test "invalid IP values and types raise evaluation errors" {
  for
    value in [
      "", "1.2.3", "1.2.3.256", "01.2.3.4", "1.2.3.4/033", "1.2.3.4/33", "1.2.3.4/",
      "1.2.3.4/8/16", ":::", "1::2::3", "::1/129", "::ffff:192.0.2.1", "1:2:3:4:5:6:7:8:9",
      "1:2:3:4:5:6:7", "12345::", "fe80::1%eth0",
    ] {
    let expression = "ip(\"" + value + "\").isIpv4()"
    let result = evaluate_condition(expression)
    assert_true(
      result.decision == Deny && result.errors.length() == 1,
      msg=expression,
    )
  }
  for condition in ["ip(1).isIpv4()", "1.isIpv4()", "ip(\"::1\").isInRange(1)"] {
    let result = evaluate_condition(condition)
    assert_true(
      result.decision == Deny && result.errors.length() == 1,
      msg=condition,
    )
  }
}

///|
test "IP extension JSON values and typed library inputs" {
  let json = parse_json(
    "{\"principal\":{\"type\":\"User\",\"id\":\"alice\"},\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"report\"},\"context\":{\"source\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"2001:db8::1\"}}}}",
  )
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.source.isInRange(ip(\"2001:db8::/32\")) };",
  )
  let result = authorize(policy, request_from_json(json), [])
  assert_true(result.decision == Allow && result.errors.is_empty())
  let typed = {
    ..sample_request(),
    context: { "source": IpValue(IpAddress::parse("2001:db8::1")) },
  }
  assert_true(authorize(policy, typed, []).decision == Allow)
  for
    text in [
      "{\"__extn\":{\"fn\":\"ip\",\"arg\":\"bad\"}}", "{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"1.0\"}}",
      "{\"__extn\":{\"fn\":\"ip\",\"arg\":\"1.2.3.4\",\"extra\":1}}", "{\"__extn\":{\"fn\":\"ip\",\"arg\":1}}",
    ] {
    let rejected = try {
      let _ = json_value(parse_json(text), 0)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "IP function and method arity and depth are bounded" {
  for
    condition in [
      "ip()", "ip(\"::1\", \"::2\")", "ip(\"::1\").isIpv4(1)", "ip(\"::1\").isInRange()",
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
  builder.write_string("permit(principal, action, resource) when { ")
  for _ in 0..<130 {
    builder.write_string("ip(")
  }
  builder.write_string("\"1.2.3.4\"")
  for _ in 0..<130 {
    builder.write_string(")")
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
