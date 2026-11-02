///|
fn tiny_set(code : Int32) -> Array[Value] {
  let result = []
  let mut n = code
  for _ in 0..<3 {
    let digit = n % 4
    if digit < 3 {
      result.push(LongValue(digit.to_int64()))
    }
    n /= 4
  }
  result
}

///|
test "set equality ignores order and duplicates" {
  for left in 0..<64 {
    for right in 0..<64 {
      let a = tiny_set(left)
      let b = tiny_set(right)
      let mut expected = true
      for value in 0..<3 {
        let item = LongValue(value.to_int64())
        if a.contains(item) != b.contains(item) {
          expected = false
        }
      }
      assert_true(
        same_value(SetValue(a), SetValue(b), Ref(1000), 0) == expected,
      )
    }
  }
  let a = SetValue([
    RecordValue({ "nested": SetValue([LongValue(1L), LongValue(2L)]) }),
  ])
  let b = SetValue([
    RecordValue({
      "nested": SetValue([LongValue(2L), LongValue(1L), LongValue(1L)]),
    }),
  ])
  assert_true(same_value(a, b, Ref(1000), 0))
}

///|
test "deep nested sets compare without repeated exponential work" {
  let mut left : Value = StringValue("leaf")
  let mut right : Value = StringValue("leaf")
  for _ in 0..<100 {
    left = SetValue([left, LongValue(0L)])
    right = SetValue([LongValue(0L), right])
  }
  assert_true(same_value(left, right, Ref(1000), 0))
  assert_true(same_value(right, left, Ref(1000), 0))
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.left == context.right };",
  )
  let request = {
    ..sample_request(),
    context: { "left": left, "right": right },
  }
  let response = authorize(policy, request, [])
  assert_true(response.decision == Allow && response.errors.is_empty())
}

///|
test "cyclic values cause a policy diagnostic instead of recursion overflow" {
  let left : Array[Value] = []
  let right : Array[Value] = []
  left.push(SetValue(left))
  right.push(SetValue(right))
  let request = {
    ..sample_request(),
    context: { "left": SetValue(left), "right": SetValue(right) },
  }
  let policy = parse_policies(
    "@id(\"base\") permit(principal, action, resource); @id(\"guard\") forbid(principal, action, resource) when { context.left == context.right };",
  )
  let response = authorize(policy, request, [])
  assert_true(response.decision == Allow && response.reasons == ["base"])
  assert_true(
    response.errors.length() == 1 && response.errors[0].policy_id == "guard",
  )
  assert_true(
    response.errors[0].message == "value comparison nesting limit exceeded",
  )
}

///|
test "comparison work is limited and isolated per policy" {
  let left = []
  let right = []
  for i in 0..<1500 {
    left.push(LongValue(i.to_int64()))
    right.push(LongValue((1499 - i).to_int64()))
  }
  let request = {
    ..sample_request(),
    context: { "left": SetValue(left), "right": SetValue(right) },
  }
  let policy = parse_policies(
    "@id(\"heavy\") permit(principal, action, resource) when { context.left == context.right }; @id(\"guard\") forbid(principal, action, resource) when { 1 == 1 };",
  )
  let result = authorize(policy, request, [])
  assert_true(result.decision == Deny && result.reasons == ["guard"])
  assert_true(
    result.errors.length() == 1 && result.errors[0].policy_id == "heavy",
  )
  assert_true(result.errors[0].message == "value comparison budget exceeded")
  assert_true(same_value(LongValue(1L), LongValue(1L), Ref(1), 0))
  let rejected = try {
    let _ = same_value(LongValue(1L), LongValue(1L), Ref(0), 0)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "set methods share the comparison budget within each policy" {
  let left = []
  let reversed = []
  let disjoint = []
  for i in 0..<1500 {
    left.push(LongValue(i.to_int64()))
    reversed.push(LongValue((1499 - i).to_int64()))
    disjoint.push(LongValue((i + 1500).to_int64()))
  }
  let request = {
    ..sample_request(),
    context: {
      "left": SetValue(left),
      "reversed": SetValue(reversed),
      "disjoint": SetValue(disjoint),
    },
  }
  for
    expression in [
      "context.left.containsAll(context.reversed)", "context.left.containsAny(context.disjoint)",
    ] {
    let policy = parse_policies(
      "permit(principal, action, resource) when { " + expression + " };",
    )
    let result = authorize(policy, request, [])
    assert_true(
      result.decision == Deny && result.errors.length() == 1,
      msg=expression,
    )
    assert_true(result.errors[0].message == "value comparison budget exceeded")
  }
}
