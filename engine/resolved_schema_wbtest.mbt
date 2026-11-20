///|
test "resolved schema decodes implicit references in records and sets" {
  let schema = parse_json(
    (
      #|{"App":{"entityTypes":{"User":{},"File":{"shape":{"type":"Record","attributes":{"owner":{"type":"Entity","name":"App::User"},"editors":{"type":"Set","element":{"type":"Entity","name":"App::User"}},"details":{"type":"Record","attributes":{"enabled":{"type":"Bool"}}}}}}},"actions":{}}}
    ),
  )
  let input = parse_json(
    (
      #|[{"uid":{"type":"App::File","id":"report"},"attrs":{"owner":{"type":"App::User","id":"alice"},"editors":[{"type":"App::User","id":"alice"}],"details":{"enabled":true}},"parents":[]}]
    ),
  )
  let entities = tagged_entities_from_json_with_resolved_schema(input, schema)
  let uid : EntityId = { kind: "App::User", id: "alice", }
  assert_true(entities[0].entity.attrs["owner"] == EntityValue(uid))
  assert_true(
    entities[0].entity.attrs["editors"] == SetValue([EntityValue(uid)]),
  )
  let request : Request = {
    principal: uid,
    action: { kind: "Action", id: "read", },
    resource: { kind: "App::File", id: "report", },
    context: {},
  }
  let policy = parse_policies(
    "permit(principal, action, resource) when { resource.owner == principal && resource.editors.contains(principal) && resource.details.enabled };",
  )
  assert_true(authorize_with_tags(policy, request, entities).decision == Allow)
}

///|
test "resolved schema rejects unsupported and mismatched input" {
  let schema = parse_json(
    "{\"\":{\"entityTypes\":{\"File\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"owner\":{\"type\":\"Entity\",\"name\":\"User\"}}}}},\"actions\":{}}}",
  )
  for
    source in [
      "[{\"uid\":{\"type\":\"File\",\"id\":\"f\"},\"attrs\":{\"owner\":{\"type\":\"Group\",\"id\":\"a\"}},\"parents\":[]}]",
      "[{\"uid\":{\"type\":\"File\",\"id\":\"f\"},\"attrs\":{\"unknown\":true},\"parents\":[]}]",
      "[{\"uid\":{\"type\":\"Other\",\"id\":\"f\"},\"attrs\":{},\"parents\":[]}]",
    ] {
    let rejected = try {
      let _ = tagged_entities_from_json_with_resolved_schema(
        parse_json(source),
        schema,
      )
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=source)
  }
  let unsupported = parse_json(
    "{\"\":{\"entityTypes\":{\"File\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"owner\":{\"type\":\"EntityOrCommon\",\"name\":\"User\"}}}}},\"actions\":{}}}",
  )
  let input = parse_json(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"f\"},\"attrs\":{\"owner\":{\"type\":\"User\",\"id\":\"a\"}},\"parents\":[]}]",
  )
  let rejected = try {
    let _ = tagged_entities_from_json_with_resolved_schema(input, unsupported)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let tags_schema = parse_json(
    "{\"\":{\"entityTypes\":{\"File\":{\"tags\":{\"type\":\"String\"}}},\"actions\":{}}}",
  )
  let rejected = try {
    let _ = tagged_entities_from_json_with_resolved_schema(
      parse_json("[]"),
      tags_schema,
    )
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
