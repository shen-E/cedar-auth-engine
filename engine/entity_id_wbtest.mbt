///|
test "validate entity type names and allow arbitrary IDs" {
  for
    kind in [
      "User", "Foo::Bar", "_", "Foo_1::_2", "principal", "when", "__cedarX",
    ] {
    EntityId::{ kind, id: "", }.validate()
    EntityId::{ kind, id: "id with spaces::\" and punctuation", }.validate()
  }
  for
    kind in [
      "", " ", " User", "User ", "1User", "User-Name", "User.Name", "équipe", "::User",
      "User::", "User::::Group", "User::1Group", "User:: if", "User::Group\n", "if",
      "then", "else", "in", "is", "has", "like", "true", "false", "__cedar", "App::if",
      "App::__cedar",
    ] {
    let rejected = try {
      EntityId::{ kind, id: "x", }.validate()
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=kind)
  }
}

///|
test "JSON entity references validate types at all input locations" {
  let invalid = "not a type"
  let entity = "{\"type\":\"" + invalid + "\",\"id\":\"a\"}"
  let valid = "{\"type\":\"User\",\"id\":\"a\"}"
  let good_request = "{\"principal\":" +
    valid +
    ",\"action\":{\"type\":\"Action\",\"id\":\"read\"},\"resource\":{\"type\":\"File\",\"id\":\"r\"},\"context\":{}}"
  for
    text in [
      "{\"principal\":" +
      entity +
      ",\"action\":" +
      valid +
      ",\"resource\":" +
      valid +
      ",\"context\":{}}",
      "{\"principal\":" +
      valid +
      ",\"action\":" +
      entity +
      ",\"resource\":" +
      valid +
      ",\"context\":{}}",
      "{\"principal\":" +
      valid +
      ",\"action\":" +
      valid +
      ",\"resource\":" +
      entity +
      ",\"context\":{}}",
      "{\"principal\":" +
      valid +
      ",\"action\":" +
      valid +
      ",\"resource\":" +
      valid +
      ",\"context\":{\"owner\":{\"__entity\":" +
      entity +
      "}}}",
    ] {
    let rejected = try {
      let _ = request_from_json(parse_json(text))
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  for
    text in [
      "[{\"uid\":" + entity + ",\"attrs\":{},\"parents\":[]}]",
      "[{\"uid\":" + valid + ",\"attrs\":{},\"parents\":[" + entity + "]}]",
      "[{\"uid\":" +
      valid +
      ",\"attrs\":{\"owner\":{\"__entity\":" +
      entity +
      "}},\"parents\":[]}]",
      "[{\"uid\":" +
      valid +
      ",\"attrs\":{},\"parents\":[],\"tags\":{\"owner\":{\"__entity\":" +
      entity +
      "}}}]",
    ] {
    let rejected = try {
      let _ = tagged_entities_from_json(parse_json(text))
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let request = request_from_json(parse_json(good_request))
  let policy = parse_policies("permit(principal, action, resource);")
  assert_true(authorize(policy, request, []).decision == Allow)
}

///|
test "template links reject invalid typed slot entity names" {
  let template = parse_template(
    "permit(principal == ?principal, action, resource == ?resource);",
  )
  let policies = parse_policies("")
  for
    bindings in [
      {
        principal: Some({ kind: "Invalid Type", id: "a", }),
        resource: Some({ kind: "File", id: "r", }),
      },
      {
        principal: Some({ kind: "User", id: "a", }),
        resource: Some({ kind: "if", id: "r", }),
      },
    ] {
    let rejected = try {
      let _ = policies.link(template, "share", bindings)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  assert_true(policies.metadata().is_empty())
}
