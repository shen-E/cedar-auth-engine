///|
fn slow_match(
  text : Array[Char],
  pattern : Array[PatternPart],
  i : Int32,
  j : Int32,
) -> Bool {
  if j == pattern.length() {
    return i == text.length()
  }
  match pattern[j] {
    AnySequence =>
      slow_match(text, pattern, i, j + 1) ||
      (i < text.length() && slow_match(text, pattern, i + 1, j))
    PatternChar(c) =>
      i < text.length() &&
      text[i] == c &&
      slow_match(text, pattern, i + 1, j + 1)
  }
}

///|
test "wildcard matcher agrees with an independent small exhaustive oracle" {
  let symbols = ['a', 'b', '*']
  let mut pattern_count = 1
  for pattern_length in 0..<5 {
    for pattern_number in 0..<pattern_count {
      let pattern : Array[PatternPart] = []
      let mut code = pattern_number
      for _ in 0..<pattern_length {
        pattern.push(
          match code % 4 {
            0 => PatternChar('a')
            1 => PatternChar('b')
            2 => PatternChar('*')
            _ => AnySequence
          },
        )
        code = code / 4
      }
      let mut text_count = 1
      for text_length in 0..<5 {
        for text_number in 0..<text_count {
          let builder = StringBuilder()
          let mut text_code = text_number
          for _ in 0..<text_length {
            builder.write_char(symbols[text_code % 3])
            text_code = text_code / 3
          }
          let text = builder.to_string()
          assert_true(
            match_pattern(text, pattern) ==
            slow_match(text.to_array(), pattern, 0, 0),
          )
        }
        text_count = text_count * 3
      }
    }
    pattern_count = pattern_count * 4
  }
}

///|
test "long repeated prefixes do not change matching" {
  let text = StringBuilder()
  for _ in 0..<16384 {
    text.write_char('a')
  }
  let pattern : Array[PatternPart] = [AnySequence]
  for _ in 0..<4096 {
    pattern.push(PatternChar('a'))
  }
  pattern.push(PatternChar('b'))
  pattern.push(AnySequence)
  assert_false(match_pattern(text.to_string(), pattern))
}

///|
test "like handles Unicode, empty strings and escaped stars" {
  let collapsed = cedar_parts("\"**\\u{2a}***\"", pattern=true)
  assert_true(collapsed.length() == 1 && collapsed[0] is AnySequence)
  let literal_between = cedar_parts("\"*\\**\"", pattern=true)
  assert_true(
    literal_between.length() == 3 && literal_between[1] is PatternChar('*'),
  )
  for
    expression in [
      "\"\" like \"**\"", "\"文件😀.txt\" like \"文*.txt\"", "\"a*b\" like \"a\\*b\"",
      "\"axb\" like \"a\\u{2a}b\"", "\"abc\" like \"a**c\"",
    ] {
    let result = evaluate_condition(expression)
    assert_true(result.decision == Allow && result.errors.is_empty())
  }
  for
    expression in [
      "\"abc\" like \"a\\*c\"", "\"ab\" like \"*abc*\"", "\"ab\" like \"a*b*b\"",
    ] {
    let result = evaluate_condition(expression)
    assert_true(result.decision == Deny && result.errors.is_empty())
  }
  let bad = evaluate_condition("1 like \"*\"")
  assert_true(bad.decision == Deny && bad.errors.length() == 1)
}

///|
test "Cedar string escapes preserve scalars and reject malformed escapes" {
  assert_true(cedar_quoted("\"\\x41\\u{1f600}\"") == "A😀")
  assert_true(cedar_quoted("\"\\u{0_41}\\u{41_}\"") == "AA")
  assert_true(cedar_quoted("\"\\0\\n\\t\"") == "\u{0}\n\t")
  for
    token in [
      "\"\\u0041\"", "\"\\b\"", "\"\\/\"", "\"\\x80\"", "\"\\u{}\"", "\"\\u{_41}\"",
      "\"\\u{d800}\"", "\"\\u{110000}\"", "\"\\*\"", "\"\\x0\"", "\"\\u{1234567}\"",
    ] {
    let rejected = try {
      let _ = cedar_quoted(token)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let duplicate = try {
    let _ = parse_json("{\"a\":1,\"\\u0061\":2}")
    false
  } catch {
    _ => true
  }
  assert_true(duplicate)
}

///|
test "like requires a literal pattern and rejects malformed escapes" {
  for
    expression in [
      "context.name like context.pattern", "\"x\" like \"\\q\"", "\"x\" like \"\\u0041\"",
    ] {
    let source = "permit(principal, action, resource) when { " +
      expression +
      " };"
    let rejected = try {
      let _ = parse_policies(source)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}
