///|
fn tagged_sample() -> Array[TaggedEntity] {
  [
    {
      entity: {
        uid: { kind: "File", id: "report", },
        attrs: { "classification": StringValue("attribute") },
        parents: [{ kind: "Folder", id: "group", }],
      },
      tags: {
        "classification": StringValue("secret"),
        "approved": BoolValue(false),
        "label": RecordValue({ "level": LongValue(3L) }),
        "ranges": SetValue([LongValue(1L), LongValue(2L)]),
      },
    },
    {
      entity: { uid: { kind: "Folder", id: "group", }, attrs: {}, parents: [], },
      tags: { "inherited": BoolValue(true) },
    },
  ]
}

///|
fn evaluate_tag_condition(
  expression : String,
  entities : Array[TaggedEntity],
) -> Response raise PolicyError {
  let request = {
    ..sample_request(),
    context: { "key": StringValue("classification") },
  }
  let source = "permit(principal, action, resource) when { " +
    expression +
    " };"
  authorize_with_tags(parse_policies(source), request, entities)
}

///|
test "entity tags support dynamic keys and Cedar values" {
  for
    condition in [
      "resource.hasTag(context.key)", "resource.getTag(context.key) == \"secret\"",
      "resource.classification == \"attribute\" && resource.getTag(\"classification\") == \"secret\"",
      "resource.getTag(\"approved\") == false", "resource.getTag(\"label\").level == 3",
      "resource.getTag(\"ranges\").contains(2)", "!resource.hasTag(\"inherited\")",
      "resource in Folder::\"group\" && !resource.hasTag(\"inherited\")", "true || resource.getTag(\"missing\") == 1",
      "!resource.hasTag(\"missing\")",
    ] {
    let response = evaluate_tag_condition(condition, tagged_sample())
    assert_true(
      response.decision == Allow && response.errors.is_empty(),
      msg=condition,
    )
  }
  for
    condition in [
      "resource.hasTag(\"missing\")", "resource.getTag(context.key) == \"other\"",
    ] {
    let response = evaluate_tag_condition(condition, tagged_sample())
    assert_true(
      response.decision == Deny && response.errors.is_empty(),
      msg=condition,
    )
  }
}

///|
test "missing tags, missing entities and bad operands follow Cedar semantics" {
  for
    condition in [
      "resource.getTag(\"missing\") == 1", "resource.hasTag(1)", "resource.getTag(1) == 1",
      "{}.hasTag(\"x\")", "{}.getTag(\"x\") == 1",
    ] {
    let response = evaluate_tag_condition(condition, tagged_sample())
    assert_true(
      response.decision == Deny && response.errors.length() == 1,
      msg=condition,
    )
  }
  let absent = evaluate_tag_condition("resource.hasTag(\"classification\")", [])
  assert_true(absent.decision == Deny && absent.errors.is_empty())
  let absent = evaluate_tag_condition(
    "resource.getTag(\"classification\") == 1",
    [],
  )
  assert_true(absent.decision == Deny && absent.errors.length() == 1)
  let source = "permit(principal, action, resource); forbid(principal, action, resource) when { resource.getTag(\"missing\") == true };"
  let response = authorize_with_tags(
    parse_policies(source),
    sample_request(),
    tagged_sample(),
  )
  assert_true(response.decision == Allow && response.reasons == ["policy0"])
  assert_true(
    response.errors.length() == 1 && response.errors[0].policy_id == "policy1",
  )
}

///|
test "tag JSON is retained or rejected instead of silently discarded" {
  let text = "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":{\"classification\":\"secret\",\"ip\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"10.0.0.1\"}}}}]"
  let json = parse_json(text)
  let tagged = tagged_entities_from_json(json)
  assert_true(
    tagged.length() == 1 &&
    tagged[0].tags.get("classification") == Some(StringValue("secret")),
  )
  let response = evaluate_tag_condition(
    "resource.getTag(\"ip\").isInRange(ip(\"10.0.0.0/8\"))", tagged,
  )
  assert_true(response.decision == Allow && response.errors.is_empty())
  let rejected = try {
    let _ = entities_from_json(json)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let empty = parse_json(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":{}}]",
  )
  assert_true(entities_from_json(empty).length() == 1)
  for
    text in [
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":null}]",
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":{\"x\":null}}]",
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":{\"x\":1,\"x\":2}}]",
    ] {
    let rejected = try {
      let _ = tagged_entities_from_json(parse_json(text))
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=text)
  }
}

///|
test "tag calls reject wrong arity and respect nesting limits" {
  for
    condition in [
      "resource.hasTag()", "resource.getTag()", "resource.hasTag(\"x\", \"y\")",
    ] {
    let rejected = try {
      let _ = parse_policies(
        "permit(principal,action,resource) when { " + condition + " };",
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
    builder.write_string("resource.getTag(")
  }
  builder.write_string("\"x\"")
  for _ in 0..<130 {
    builder.write_string(")")
  }
  builder.write_string(" == true };")
  let rejected = try {
    let _ = parse_policies(builder.to_string())
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "tagged and untagged entry points enforce the same entity limits" {
  let entities = tagged_sample()
  let duplicate = [entities[0], entities[0]]
  let rejected = try {
    let _ = authorize_with_tags(parse_policies(""), sample_request(), duplicate)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let many = []
  let many_tagged = []
  for _ in 0..<4097 {
    many.push(entities[0].entity)
    many_tagged.push(entities[0])
  }
  let rejected_plain = try {
    let _ = authorize(parse_policies(""), sample_request(), many)
    false
  } catch {
    _ => true
  }
  let rejected_tagged = try {
    let _ = authorize_with_tags(
      parse_policies(""),
      sample_request(),
      many_tagged,
    )
    false
  } catch {
    _ => true
  }
  assert_true(rejected_plain && rejected_tagged)
}
