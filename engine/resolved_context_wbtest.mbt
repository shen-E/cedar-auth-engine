///|
test "resolved action context decodes nested entities and extensions" {
  let schema = parse_json(
    "{\"App\":{\"entityTypes\":{},\"actions\":{\"read\":{\"appliesTo\":{\"context\":{\"type\":\"Record\",\"attributes\":{\"source\":{\"type\":\"ipaddr\"},\"detail\":{\"type\":\"Record\",\"attributes\":{\"owner\":{\"type\":\"Entity\",\"name\":\"App::User\"}}}}}}}}}}",
  )
  let decoder = ResolvedContextSchema::from_json(schema)
  let input = parse_json(
    "{\"principal\":{\"type\":\"App::User\",\"id\":\"alice\"},\"action\":{\"type\":\"App::Action\",\"id\":\"read\"},\"resource\":{\"type\":\"App::File\",\"id\":\"report\"},\"context\":{\"source\":\"10.0.0.1\",\"detail\":{\"owner\":{\"type\":\"App::User\",\"id\":\"alice\"}}}}",
  )
  let request = decoder.request_from_json(input)
  assert_true(
    request.context["source"] == IpValue(IpAddress::parse("10.0.0.1")),
  )
  let policy = parse_policies(
    "permit(principal, action, resource) when { context.source.isIpv4() && context.detail.owner == principal };",
  )
  assert_true(authorize(policy, request, []).decision == Allow)
  assert_true(decoder.request_from_json(input).context == request.context)
  let other = parse_json(
    "{\"principal\":{\"type\":\"App::User\",\"id\":\"alice\"},\"action\":{\"type\":\"App::Action\",\"id\":\"read\"},\"resource\":{\"type\":\"App::File\",\"id\":\"report\"},\"context\":{\"source\":\"10.0.0.1\",\"detail\":{\"owner\":{\"type\":\"App::Group\",\"id\":\"team\"}}}}",
  )
  assert_true(
    decoder.request_from_json(other).context["detail"] ==
    RecordValue({ "owner": EntityValue({ kind: "App::Group", id: "team", }) }),
  )
}

///|
test "resolved context rejects unknown actions, fields and wrong types" {
  let schema = parse_json(
    "{\"\":{\"actions\":{\"read\":{\"appliesTo\":{\"context\":{\"type\":\"Record\",\"attributes\":{\"ip\":{\"type\":\"ipaddr\"}}}}},\"empty\":{}}}}",
  )
  let decoder = ResolvedContextSchema::from_json(schema)
  for
    (action, context, valid) in [
      ("read", "{\"ip\":\"10.0.0.1\"}", true),
      ("read", "{\"ip\":\"bad\"}", false),
      ("read", "{\"unknown\":true}", false),
      ("empty", "{}", true),
      ("empty", "{\"ip\":\"10.0.0.1\"}", false),
      ("other", "{}", false),
    ] {
    let input = parse_json(
      "{\"principal\":{\"type\":\"User\",\"id\":\"a\"},\"action\":{\"type\":\"Action\",\"id\":\"" +
      action +
      "\"},\"resource\":{\"type\":\"File\",\"id\":\"f\"},\"context\":" +
      context +
      "}",
    )
    let accepted = try {
      let _ = decoder.request_from_json(input)
      true
    } catch {
      _ => false
    }
    assert_true(accepted == valid, msg=action + ": " + context)
  }
}

///|
test "resolved context schema snapshots its input and bounds cycles" {
  let attributes : Map[String, Json] = { "source": { "type": "ipaddr" } }
  let shape : Json = {
    "type": "Record",
    "attributes": Json::object(attributes),
  }
  let schema : Json = {
    "": { "actions": { "read": { "appliesTo": { "context": shape } } } },
  }
  let decoder = ResolvedContextSchema::from_json(schema)
  attributes["source"] = { "type": "String" }
  let request = parse_json(
    "{\"principal\":{\"type\":\"User\",\"id\":\"a\"},\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"f\"},\"context\":{\"source\":\"10.0.0.1\"}}",
  )
  assert_true(
    decoder.request_from_json(request).context["source"] ==
    IpValue(IpAddress::parse("10.0.0.1")),
  )
  let cyclic : Map[String, Json] = Map([])
  cyclic["self"] = Json::object(cyclic)
  let malformed : Json = {
    "": {
      "actions": {
        "read": { "appliesTo": { "context": Json::object(cyclic) } },
      },
    },
  }
  let rejected = try {
    let _ = ResolvedContextSchema::from_json(malformed)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
