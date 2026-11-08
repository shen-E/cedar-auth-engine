///|
test "batch decisions match individual authorization in request order" {
  let policy = parse_policies(
    "@id(\"permit\") permit(principal, action, resource) when { context.authenticated }; @id(\"forbid\") forbid(principal, action, resource) when { resource.missing };",
  )
  let allowed = sample_request()
  let denied = {
    ..sample_request(),
    context: { "authenticated": BoolValue(false) },
  }
  let missing = { ..sample_request(), context: {}, }
  let requests = [allowed, denied, missing, allowed]
  let responses = authorize_batch(policy, requests, [])
  assert_true(responses.length() == requests.length())
  for i in 0..<requests.length() {
    let individual = authorize(policy, requests[i], [])
    assert_true(
      response_to_json(responses[i]).stringify() ==
      response_to_json(individual).stringify(),
    )
  }
  assert_true(
    responses[0].decision == Allow && responses[0].errors.length() == 1,
  )
  assert_true(
    responses[1].decision == Deny && responses[1].errors.length() == 1,
  )
  assert_true(
    responses[2].decision == Deny && responses[2].errors.length() == 2,
  )
}

///|
test "tagged batches retain entity attributes, tags and hierarchy" {
  let policy = parse_policies(
    "permit(principal, action, resource in Folder::\"group\") when { resource.hasTag(\"classification\") && resource.getTag(\"classification\") == \"secret\" };",
  )
  let requests = [
    sample_request(),
    { ..sample_request(), resource: { kind: "File", id: "missing", }, },
  ]
  let entities = tagged_sample()
  let responses = authorize_batch_with_tags(policy, requests, entities)
  assert_true(responses[0].decision == Allow && responses[0].errors.is_empty())
  assert_true(responses[1].decision == Deny && responses[1].errors.is_empty())
  for i in 0..<requests.length() {
    let individual = authorize_with_tags(policy, requests[i], entities)
    assert_true(
      response_to_json(responses[i]).stringify() ==
      response_to_json(individual).stringify(),
    )
  }
}

///|
test "batch limits and graph errors are checked before returning results" {
  let policy = parse_policies("")
  assert_true(authorize_batch(policy, [], []).is_empty())
  assert_true(authorize_batch_with_tags(policy, [], []).is_empty())
  let at_limit = Array::make(32768, sample_request())
  assert_true(authorize_batch(policy, at_limit, []).length() == 32768)
  assert_true(authorize_batch_with_tags(policy, at_limit, []).length() == 32768)
  at_limit.push(sample_request())
  let plain_rejected = try {
    let _ = authorize_batch(policy, at_limit, [])
    false
  } catch {
    _ => true
  }
  let tagged_rejected = try {
    let _ = authorize_batch_with_tags(policy, at_limit, [])
    false
  } catch {
    _ => true
  }
  assert_true(plain_rejected && tagged_rejected)
  let cyclic = [group("loop", [{ kind: "Group", id: "loop", }])]
  let rejected = try {
    let _ = authorize_batch_with_tags(policy, [], cyclic)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let rejected = try {
    let _ = authorize_batch(policy, [], [cyclic[0].entity])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
