///|
test "entity stores preserve authorization diagnostics and validate graphs" {
  let policies = parse_policies(
    "@id(\"ok\") permit(principal, action, resource); @id(\"bad\") forbid(principal, action, resource) when { resource.missing };",
  )
  let entities = tagged_sample()
  let store = EntityStore::new_with_tags(entities)
  let requests = [
    sample_request(),
    { ..sample_request(), resource: { kind: "File", id: "other", }, },
  ]
  for i in 0..<requests.length() {
    assert_true(
      response_to_json(store.authorize(policies, requests[i])).stringify() ==
      response_to_json(authorize_with_tags(policies, requests[i], entities)).stringify(),
    )
  }
  let responses = store.authorize_batch(policies, requests)
  for i in 0..<requests.length() {
    assert_true(
      response_to_json(responses[i]).stringify() ==
      response_to_json(store.authorize(policies, requests[i])).stringify(),
    )
  }
  assert_true(
    responses[0].decision == Allow && responses[0].errors.length() == 1,
  )
  assert_true(
    responses[1].decision == Allow && responses[1].errors.length() == 1,
  )
  let cyclic = [group("loop", [{ kind: "Group", id: "loop", }])]
  let rejected = try {
    let _ = EntityStore::new_with_tags(cyclic)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let rejected = try {
    let _ = EntityStore::new_with_tags([entities[0], entities[0]])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  assert_true(store.authorize_batch(policies, []).is_empty())
  let requests_at_limit = Array::make(16384, sample_request())
  assert_true(
    store.authorize_batch(parse_policies(""), requests_at_limit).length() ==
    16384,
  )
  requests_at_limit.push(sample_request())
  let rejected = try {
    let _ = store.authorize_batch(policies, requests_at_limit)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "entity stores bound nested and cyclic input values" {
  let fields : Map[String, Value] = Map([])
  let entities : Array[Entity] = [
    { uid: { kind: "File", id: "report", }, attrs: fields, parents: [], },
  ]
  let mut value : Value = BoolValue(true)
  for _ in 0..<64 {
    value = SetValue([value])
  }
  fields["nested"] = value
  let _ = EntityStore::new(entities)
  fields["nested"] = SetValue([value])
  let rejected = try {
    let _ = EntityStore::new(entities)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let cycle : Array[Value] = []
  cycle.push(SetValue(cycle))
  fields["nested"] = SetValue(cycle)
  let rejected = try {
    let _ = EntityStore::new(entities)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  fields["nested"] = SetValue(Array::make(131071, BoolValue(true)))
  let _ = EntityStore::new(entities)
  fields["nested"] = SetValue(Array::make(524288, BoolValue(true)))
  let rejected = try {
    let _ = EntityStore::new(entities)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
