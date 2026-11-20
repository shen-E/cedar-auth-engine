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
  let no_tags_schema = parse_json(
    "{\"\":{\"entityTypes\":{\"File\":{}},\"actions\":{}}}",
  )
  let tagged = parse_json(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"f\"},\"attrs\":{},\"parents\":[],\"tags\":{\"owner\":\"alice\"}}]",
  )
  let rejected = try {
    let _ = tagged_entities_from_json_with_resolved_schema(
      tagged, no_tags_schema,
    )
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "resolved schema decodes entity and extension tags" {
  let schema = parse_json(
    "{\"\":{\"entityTypes\":{\"User\":{},\"File\":{\"tags\":{\"type\":\"Entity\",\"name\":\"User\"}},\"Net\":{\"tags\":{\"type\":\"ipaddr\"}}},\"actions\":{}}}",
  )
  let input = parse_json(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":{\"owner\":{\"type\":\"User\",\"id\":\"alice\"}}},{\"uid\":{\"type\":\"Net\",\"id\":\"network\"},\"attrs\":{},\"parents\":[],\"tags\":{\"address\":\"10.0.0.1\"}}]",
  )
  let entities = tagged_entities_from_json_with_resolved_schema(input, schema)
  assert_true(
    entities[0].tags["owner"] == EntityValue({ kind: "User", id: "alice", }),
  )
  assert_true(
    entities[1].tags["address"] == IpValue(IpAddress::parse("10.0.0.1")),
  )
  let policy = parse_policies(
    "permit(principal, action, resource) when { resource.getTag(\"owner\") == principal };",
  )
  assert_true(
    authorize_with_tags(policy, sample_request(), entities).decision == Allow,
  )
  let bad = parse_json(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"f\"},\"attrs\":{},\"parents\":[],\"tags\":{\"owner\":{\"type\":\"Group\",\"id\":\"alice\"}}}]",
  )
  let rejected = try {
    let _ = tagged_entities_from_json_with_resolved_schema(bad, schema)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "resolved schema decodes sets of entity tags" {
  let schema = parse_json(
    "{\"\":{\"entityTypes\":{\"User\":{},\"File\":{\"tags\":{\"type\":\"Set\",\"element\":{\"type\":\"Entity\",\"name\":\"User\"}}}},\"actions\":{}}}",
  )
  let input = parse_json(
    "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tags\":{\"editors\":[{\"type\":\"User\",\"id\":\"alice\"}]}}]",
  )
  let entities = tagged_entities_from_json_with_resolved_schema(input, schema)
  let policy = parse_policies(
    "permit(principal, action, resource) when { resource.getTag(\"editors\").contains(principal) };",
  )
  assert_true(
    authorize_with_tags(policy, sample_request(), entities).decision == Allow,
  )
}

///|
test "resolved schema decodes implicit and explicit extension values" {
  let schema = parse_json(
    "{\"\":{\"entityTypes\":{\"File\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"addr\":{\"type\":\"ipaddr\"},\"amount\":{\"type\":\"decimal\"},\"time\":{\"type\":\"datetime\"},\"age\":{\"type\":\"duration\"}}}}},\"actions\":{}}}",
  )
  let inputs = [
    "{\"addr\":\"10.0.0.1\",\"amount\":\"1.0\",\"time\":\"2026-11-20\",\"age\":\"1h\"}",
    "{\"addr\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"10.0.0.1\"}},\"amount\":{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"1.0\"}},\"time\":{\"__extn\":{\"fn\":\"datetime\",\"arg\":\"2026-11-20\"}},\"age\":{\"__extn\":{\"fn\":\"duration\",\"arg\":\"1h\"}}}",
  ]
  let policy = parse_policies(
    "permit(principal, action, resource) when { resource.addr.isIpv4() && resource.amount == decimal(\"1.0\") && resource.time == datetime(\"2026-11-20\") && resource.age == duration(\"1h\") };",
  )
  for attrs in inputs {
    let input = parse_json(
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":" +
      attrs +
      ",\"parents\":[]}]",
    )
    let entities = tagged_entities_from_json_with_resolved_schema(input, schema)
    assert_true(
      authorize_with_tags(policy, sample_request(), entities).decision == Allow,
    )
  }
  for
    bad in [
      "1", "\"invalid\"", "{\"__extn\":{\"fn\":\"decimal\",\"arg\":\"1.0\"}}",
    ] {
    let input = parse_json(
      "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{\"addr\":" +
      bad +
      "},\"parents\":[]}]",
    )
    let rejected = try {
      let _ = tagged_entities_from_json_with_resolved_schema(input, schema)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=bad)
  }
  let nested = decode_resolved_value(
    parse_json("[\"1h\",\"30m\"]"),
    parse_json("{\"type\":\"Set\",\"element\":{\"type\":\"duration\"}}"),
    0,
    Ref(0),
  )
  assert_true(
    nested ==
    SetValue([
      DurationValue(Duration::parse("1h")),
      DurationValue(Duration::parse("30m")),
    ]),
  )
}
