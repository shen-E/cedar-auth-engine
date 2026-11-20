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

///|
test "partial request type checks follow action applicability and context types" {
  let schema = parse_json(
    "{\"App\":{\"actions\":{\"read\":{\"appliesTo\":{\"principalTypes\":[\"App::Group\"],\"resourceTypes\":[\"App::File\"],\"context\":{\"type\":\"Record\",\"attributes\":{\"owner\":{\"type\":\"Entity\",\"name\":\"App::Group\"}}}}},\"empty\":{}}}}",
  )
  let decoder = ResolvedContextSchema::from_json(schema)
  for
    (principal, action, resource, owner, valid) in [
      ("App::Group", "read", "App::File", "App::Group", true),
      ("App::User", "read", "App::File", "App::Group", false),
      ("App::Group", "read", "App::Other", "App::Group", false),
      ("App::Group", "read", "App::File", "App::User", false),
      ("App::Group", "empty", "App::File", "App::Group", false),
      ("App::Group", "missing", "App::File", "App::Group", false),
    ] {
    let input = parse_json(
      "{\"principal\":{\"type\":\"" +
      principal +
      "\",\"id\":\"a\"},\"action\":{\"type\":\"App::Action\",\"id\":\"" +
      action +
      "\"},\"resource\":{\"type\":\"" +
      resource +
      "\",\"id\":\"f\"},\"context\":{\"owner\":{\"type\":\"" +
      owner +
      "\",\"id\":\"a\"}}}",
    )
    let accepted = try {
      let _ = decoder.request_from_json_with_action_types(input)
      true
    } catch {
      _ => false
    }
    assert_true(
      accepted == valid,
      msg=principal + " / " + action + " / " + resource + " / " + owner,
    )
  }
}

///|
test "request action types are snapshotted" {
  let principals : Array[Json] = [Json::string("User")]
  let applicability : Json = {
    "principalTypes": Json::array(principals),
    "resourceTypes": ["File"],
  }
  let schema : Json = {
    "": { "actions": { "read": { "appliesTo": applicability } } },
  }
  let decoder = ResolvedContextSchema::from_json(schema)
  principals.clear()
  let input = parse_json(
    "{\"principal\":{\"type\":\"User\",\"id\":\"a\"},\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"f\"},\"context\":{}}",
  )
  assert_true(
    decoder.request_from_json_with_action_types(input).principal.kind == "User",
  )
}

///|
test "request type checks validate enum IDs in nested context" {
  let schema = parse_json(
    (
      #|{"App":{"entityTypes":{"Role":{"enum":["Admin","Reader"]},"File":{}},"actions":{"read":{"appliesTo":{"principalTypes":["App::Role"],"resourceTypes":["App::File"],"context":{"type":"Record","attributes":{"owners":{"type":"Set","element":{"type":"Record","attributes":{"role":{"type":"Entity","name":"App::Role"}}}}}}}}}}}
    ),
  )
  let decoder = ResolvedContextSchema::from_json(schema)
  for
    (principal, owner, valid) in [
      ("Admin", "Reader", true),
      ("Unknown", "Reader", false),
      ("Admin", "Unknown", false),
    ] {
    let input = parse_json(
      "{\"principal\":{\"type\":\"App::Role\",\"id\":\"" +
      principal +
      "\"},\"action\":{\"type\":\"App::Action\",\"id\":\"read\"},\"resource\":{\"type\":\"App::File\",\"id\":\"f\"},\"context\":{\"owners\":[{\"role\":{\"type\":\"App::Role\",\"id\":\"" +
      owner +
      "\"}}]}}",
    )
    let accepted = try {
      let _ = decoder.request_from_json_with_action_types(input)
      true
    } catch {
      _ => false
    }
    assert_true(accepted == valid)
    let _ = decoder.request_from_json(input)
  }
}

///|
test "request enum IDs are snapshotted" {
  let ids : Array[Json] = [Json::string("Admin")]
  let schema : Json = {
    "": {
      "entityTypes": { "Role": { "enum": Json::array(ids) } },
      "actions": {
        "read": {
          "appliesTo": { "principalTypes": ["Role"], "resourceTypes": ["File"] },
        },
      },
    },
  }
  let decoder = ResolvedContextSchema::from_json(schema)
  ids.clear()
  let input = parse_json(
    (
      #|{"principal":{"type":"Role","id":"Admin"},"action":{"type":"Action","id":"read"},"resource":{"type":"File","id":"f"},"context":{}}
    ),
  )
  assert_true(
    decoder.request_from_json_with_action_types(input).principal.id == "Admin",
  )
}
