///|
fn rejects_request_input(text : String) -> Bool {
  try {
    let _ = @engine.request_from_json(@engine.parse_json(text))
    false
  } catch {
    _ => true
  }
}

///|
fn rejects_entity_input(text : String) -> Bool {
  try {
    let _ = @engine.tagged_entities_from_json(@engine.parse_json(text))
    false
  } catch {
    _ => true
  }
}

///|
test "request and nested entity references reject unknown structural fields" {
  let user = "{\"type\":\"User\",\"id\":\"alice\"}"
  let invalid = "{\"type\":\"User\",\"id\":\"alice\",\"tenant\":\"x\"}"
  let action = "{\"type\":\"Action\",\"id\":\"read\"}"
  let resource = "{\"type\":\"File\",\"id\":\"report\"}"
  let base = "\"principal\":" +
    user +
    ",\"action\":" +
    action +
    ",\"resource\":" +
    resource
  let bad : Array[String] = [
    "{" + base + ",\"context\":{},\"contextt\":{}}",
    "{\"principal\":" +
    invalid +
    ",\"action\":" +
    action +
    ",\"resource\":" +
    resource +
    ",\"context\":{}}",
    "{\"principal\":" +
    user +
    ",\"action\":" +
    invalid +
    ",\"resource\":" +
    resource +
    ",\"context\":{}}",
    "{\"principal\":" +
    user +
    ",\"action\":" +
    action +
    ",\"resource\":" +
    invalid +
    ",\"context\":{}}",
    "{" + base + ",\"context\":{\"owner\":{\"__entity\":" + invalid + "}}}",
    "{" + base + ",\"context\":{\"items\":[{\"__entity\":" + invalid + "}]}}",
  ]
  for text in bad {
    assert_true(rejects_request_input(text), msg=text)
  }
  let valid = "{" +
    base +
    ",\"context\":{\"tagz\":true,\"record\":{\"tenant\":\"x\"},\"owner\":{\"__entity\":" +
    user +
    "}}}"
  let request = @engine.request_from_json(@engine.parse_json(valid))
  assert_true(
    request.context.contains("tagz") && request.context.contains("record"),
  )
}

///|
test "entity input rejects unknown structural fields without restricting attributes or tags" {
  let uid = "{\"type\":\"File\",\"id\":\"report\"}"
  let invalid_uid = "{\"type\":\"File\",\"id\":\"report\",\"tenant\":\"x\"}"
  let bad : Array[String] = [
    "[{\"uid\":" +
    uid +
    ",\"attrs\":{},\"parents\":[],\"tagz\":{\"suspended\":true}}]",
    "[{\"uid\":" + invalid_uid + ",\"attrs\":{},\"parents\":[]}]",
    "[{\"uid\":" + uid + ",\"attrs\":{},\"parents\":[" + invalid_uid + "]}]",
    "[{\"uid\":" +
    uid +
    ",\"attrs\":{\"owner\":{\"__entity\":" +
    invalid_uid +
    "}},\"parents\":[]}]",
    "[{\"uid\":" +
    uid +
    ",\"attrs\":{},\"parents\":[],\"tags\":{\"owner\":{\"__entity\":" +
    invalid_uid +
    "}}}]",
  ]
  for text in bad {
    assert_true(rejects_entity_input(text), msg=text)
  }
  let valid = "[{\"uid\":" +
    uid +
    ",\"attrs\":{\"tagz\":true,\"detail\":{\"type\":\"free-form\",\"id\":1,\"extra\":true}},\"parents\":[],\"tags\":{\"tenant\":\"x\"}}]"
  let entities = @engine.tagged_entities_from_json(@engine.parse_json(valid))
  assert_true(entities[0].entity.attrs.contains("tagz"))
  assert_true(entities[0].tags.contains("tenant"))
}

///|
test "unknown structural field reports its location and name" {
  let text = "[{\"uid\":{\"type\":\"File\",\"id\":\"report\"},\"attrs\":{},\"parents\":[],\"tagz\":{}}]"
  let clear_error = try {
    let _ = @engine.tagged_entities_from_json(@engine.parse_json(text))
    false
  } catch {
    err => err.to_string() == "unknown entity field 'tagz'"
  }
  assert_true(clear_error)
  let untagged_rejected = try {
    let _ = @engine.entities_from_json(@engine.parse_json(text))
    false
  } catch {
    err => err.to_string() == "unknown entity field 'tagz'"
  }
  assert_true(untagged_rejected)
}

///|
test "direct JSON inputs enforce request value limits" {
  let values = Array::make(131071, Json::boolean(true))
  let request : Json = {
    "principal": { "type": "User", "id": "alice" },
    "action": { "type": "Action", "id": "read" },
    "resource": { "type": "File", "id": "report" },
    "context": { "values": Json::array(values) },
  }
  let parsed = @engine.request_from_json(request)
  parsed.validate()
  values.push(Json::boolean(true))
  let rejected = try {
    let _ = @engine.request_from_json(request)
    false
  } catch {
    error => error.to_string() == "value limit exceeded"
  }
  assert_true(rejected)
}
