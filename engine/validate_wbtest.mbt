///|
test "typed request validation checks every entity reference" {
  let valid = sample_request()
  valid.validate()
  let invalid = { kind: "Bad::", id: "x", }
  for
    request in [
      { ..valid, principal: invalid, },
      { ..valid, action: invalid, },
      { ..valid, resource: invalid, },
      {
        ..valid,
        context: {
          "nested": RecordValue({ "members": SetValue([EntityValue(invalid)]) }),
        },
      },
    ] {
    let rejected = try {
      request.validate()
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "typed request validation bounds nesting, cycles, and value count" {
  let fields : Map[String, Value] = Map([])
  let request = { ..sample_request(), context: fields, }
  let mut value : Value = BoolValue(true)
  for _ in 0..<64 {
    value = SetValue([value])
  }
  fields["value"] = value
  request.validate()
  fields["value"] = SetValue([value])
  let rejected = try {
    request.validate()
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let cycle : Array[Value] = []
  cycle.push(SetValue(cycle))
  fields["value"] = SetValue(cycle)
  let rejected = try {
    request.validate()
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  fields["value"] = SetValue(Array::make(131071, BoolValue(true)))
  request.validate()
  fields["value"] = SetValue(Array::make(131072, BoolValue(true)))
  let rejected = try {
    request.validate()
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "typed entity validation covers ids, parents, attributes, and tags" {
  let invalid = { kind: "Bad::", id: "x", }
  let base = tagged_sample()[0]
  validate_typed_entities([base])
  let nested = RecordValue({ "inner": SetValue([EntityValue(invalid)]) })
  for
    entity in [
      { ..base, entity: { ..base.entity, uid: invalid, }, },
      { ..base, entity: { ..base.entity, parents: [invalid], }, },
      { ..base, entity: { ..base.entity, attrs: { "bad": nested }, }, },
      { ..base, tags: { "bad": nested }, },
    ] {
    let rejected = try {
      let _ = EntityStore::new_with_tags_checked([entity])
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let cyclic = [group("loop", [{ kind: "Group", id: "loop", }])]
  let rejected = try {
    validate_typed_entities(cyclic)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "typed entity validation bounds attributes and tags together" {
  let base = tagged_sample()[0]
  let values = Array::make(131070, BoolValue(true))
  let entity : TaggedEntity = {
    entity: { ..base.entity, attrs: { "values": SetValue(values) }, },
    tags: { "tag": BoolValue(true) },
  }
  validate_typed_entities([entity])
  let _ = EntityStore::new_with_tags_checked([entity])
  values.push(BoolValue(true))
  let rejected = try {
    validate_typed_entities([entity])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let rejected = try {
    let _ = EntityStore::new_with_tags_checked([entity])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "checked authorization validates all requests and preserves responses" {
  let policies = parse_policies(
    "@id(\"ok\") permit(principal, action, resource); @id(\"bad\") forbid(principal, action, resource) when { resource.missing };",
  )
  let entities = tagged_sample()
  let store = EntityStore::new_with_tags_checked(entities)
  let request = sample_request()
  let expected = response_to_json(store.authorize(policies, request)).stringify()
  assert_true(
    response_to_json(store.authorize_checked(policies, request)).stringify() ==
    expected,
  )
  let responses = store.authorize_batch_checked(policies, [request, request])
  assert_true(responses.length() == 2)
  assert_true(response_to_json(responses[0]).stringify() == expected)
  assert_true(response_to_json(responses[1]).stringify() == expected)
  let invalid = { ..request, resource: { kind: "", id: "x", }, }
  let rejected = try {
    let _ = store.authorize_checked(policies, invalid)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let rejected = try {
    let _ = store.authorize_batch_checked(policies, [request, invalid])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  assert_true(store.authorize_batch_checked(policies, []).is_empty())
  let rejected = try {
    let _ = store.authorize_batch_checked(policies, Array::make(4097, request))
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let plain = EntityStore::new_checked([])
  assert_true(plain.authorize_checked(policies, request).decision == Allow)
}
