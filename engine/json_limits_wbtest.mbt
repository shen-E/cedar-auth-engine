///|
fn input_request(context : Json) -> Json {
  {
    "principal": { "type": "User", "id": "alice" },
    "action": { "type": "Action", "id": "read" },
    "resource": { "type": "File", "id": "report" },
    "context": context,
  }
}

///|
fn input_entity(id : String, attrs : Json, tags : Json, parents : Json) -> Json {
  {
    "uid": { "type": "File", "id": id },
    "attrs": attrs,
    "tags": tags,
    "parents": parents,
  }
}

///|
test "JSON request values have a shared bounded budget" {
  let values = Array::make(524286, Json::boolean(true))
  let context : Json = {
    "items": Json::array(values),
    "nested": { "allowed": true },
  }
  // One set, 524,286 elements, one record and its member.
  let rejected = try {
    let _ = request_from_json(input_request(context))
    false
  } catch {
    error => error.to_string() == "value limit exceeded"
  }
  assert_true(rejected)
  let _ = values.pop()
  let request = request_from_json(input_request(context))
  request.validate()
  values.push(Json::boolean(true))
  let rejected = try {
    let _ = request_from_json(input_request(context))
    false
  } catch {
    error => error.to_string() == "value limit exceeded"
  }
  assert_true(rejected)
}

///|
test "JSON entity value budget covers all attributes and tags" {
  let values = Array::make(524285, Json::boolean(true))
  let first = input_entity(
    "one",
    { "items": Json::array(values) },
    { "shared": true },
    [],
  )
  let second = input_entity("two", { "active": true }, {}, [])
  let input = Json::array([first, second])
  let entities = tagged_entities_from_json(input)
  validate_typed_entities(entities)
  let _ = EntityStore::new_with_tags_checked(entities)
  values.push(Json::boolean(true))
  let rejected = try {
    let _ = tagged_entities_from_json(input)
    false
  } catch {
    error => error.to_string() == "value limit exceeded"
  }
  assert_true(rejected)
}

///|
test "JSON entity and cumulative parent limits are enforced before conversion" {
  let entities = []
  for i in 0..<16384 {
    entities.push(input_entity(i.to_string(), {}, {}, []))
  }
  assert_true(
    tagged_entities_from_json(Json::array(entities)).length() == 16384,
  )
  entities.push(Json::null())
  let rejected = try {
    let _ = tagged_entities_from_json(Json::array(entities))
    false
  } catch {
    error => error.to_string() == "entity limit exceeded"
  }
  assert_true(rejected)
  let parent : Json = { "type": "Group", "id": "team" }
  let left = Array::make(65536, parent)
  let right = Array::make(65536, parent)
  let input = Json::array([
    input_entity("one", {}, {}, Json::array(left)),
    input_entity("two", {}, {}, Json::array(right)),
  ])
  let parsed = tagged_entities_from_json(input)
  validate_entities(parsed)
  right.push(parent)
  let rejected = try {
    let _ = tagged_entities_from_json(input)
    false
  } catch {
    error => error.to_string() == "entity parent limit exceeded"
  }
  assert_true(rejected)
}

///|
test "constructed JSON containers obey depth limits and reject cycles" {
  let mut nested = Json::boolean(true)
  for _ in 0..<64 {
    nested = Json::array([nested])
  }
  let request = request_from_json(input_request({ "value": nested }))
  request.validate()
  let rejected = try {
    let _ = request_from_json(input_request({ "value": Json::array([nested]) }))
    false
  } catch {
    error => error.to_string() == "value nesting limit exceeded"
  }
  assert_true(rejected)
  let cyclic : Array[Json] = []
  let value = Json::array(cyclic)
  cyclic.push(value)
  let rejected = try {
    let _ = request_from_json(input_request({ "value": value }))
    false
  } catch {
    error => error.to_string() == "value nesting limit exceeded"
  }
  assert_true(rejected)
}
