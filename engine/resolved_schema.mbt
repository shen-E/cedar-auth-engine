///|
// Decode a value using a resolved Cedar JSON type. This is input decoding,
// not policy, schema, entity hierarchy or request validation.
fn decode_resolved_value(
  value : Json,
  spec : Json,
  depth : Int32,
  count : Ref[Int32],
) -> Value raise PolicyError {
  if depth > 64 || count.val >= 524288 {
    raise PolicyError("resolved schema value limit exceeded")
  }
  let fields = object(spec, "resolved schema type")
  let kind = string_field(fields, "type")
  match kind {
    "Entity" => {
      let expected = string_field(fields, "name")
      let raw = match value {
        Object(obj) =>
          match obj.get("__entity") {
            Some(uid) => {
              if obj.length() != 1 {
                raise PolicyError("invalid entity escape")
              }
              uid
            }
            None => value
          }
        _ => value
      }
      let uid = entity_id(raw)
      if uid.kind != expected {
        raise PolicyError("entity type does not match resolved schema")
      }
      count.val += 1
      EntityValue(uid)
    }
    "Set" => {
      count.val += 1
      let items = match value {
        Array(items) => items
        _ => raise PolicyError("expected set")
      }
      let element = required(fields, "element")
      let result = []
      for item in items {
        result.push(decode_resolved_value(item, element, depth + 1, count))
      }
      SetValue(result)
    }
    "Record" => {
      count.val += 1
      let attributes = object(
        required(fields, "attributes"),
        "schema attributes",
      )
      let input = object(value, "record")
      let result : Map[String, Value] = Map([])
      for key, item in input {
        let attribute = match attributes.get(key) {
          Some(spec) => spec
          None => raise PolicyError("attribute not declared in resolved schema")
        }
        result[key] = decode_resolved_value(item, attribute, depth + 1, count)
      }
      RecordValue(result)
    }
    "Bool" | "Long" | "String" => {
      let result = json_value(value, depth, count)
      match (kind, result) {
        ("Bool", BoolValue(_))
        | ("Long", LongValue(_))
        | ("String", StringValue(_)) => result
        _ => raise PolicyError("value does not match resolved schema type")
      }
    }
    "ipaddr" | "decimal" | "datetime" | "duration" => {
      let result = match value {
        String(text) => {
          count.val += 1
          match kind {
            "ipaddr" => IpValue(IpAddress::parse(text))
            "decimal" => DecimalValue(Decimal::parse(text))
            "datetime" => DateTimeValue(DateTime::parse(text))
            _ => DurationValue(Duration::parse(text))
          }
        }
        _ => json_value(value, depth, count)
      }
      match (kind, result) {
        ("ipaddr", IpValue(_))
        | ("decimal", DecimalValue(_))
        | ("datetime", DateTimeValue(_))
        | ("duration", DurationValue(_)) => result
        _ => raise PolicyError("value does not match resolved schema type")
      }
    }
    _ => raise PolicyError("unsupported resolved schema type '\{kind}'")
  }
}

///|
fn resolved_schema_index(
  schema : Json,
) -> (Map[String, Json], Map[String, Bool]) raise PolicyError {
  let namespaces = object(schema, "resolved schema")
  let shapes : Map[String, Json] = Map([])
  let action_ids : Map[String, Bool] = Map([])
  for ns, body in namespaces {
    let fields = object(body, "schema namespace")
    let types = match fields.get("entityTypes") {
      Some(types) => object(types, "schema entity types")
      None => Map([])
    }
    for name, definition in types {
      let qualified = if ns == "" { name } else { ns + "::" + name }
      if shapes.contains(qualified) || shapes.length() >= 16384 {
        raise PolicyError("duplicate or excessive schema entity types")
      }
      let entity = object(definition, "schema entity type")
      if entity.contains("tags") {
        raise PolicyError("schema tag types are unsupported")
      }
      shapes[qualified] = match entity.get("shape") {
        Some(shape) => shape
        None => { "type": "Record", "attributes": Json::object(Map([])) }
      }
    }
    let action_kind = if ns == "" { "Action" } else { ns + "::Action" }
    let actions = match fields.get("actions") {
      Some(actions) => object(actions, "schema actions")
      None => Map([])
    }
    for id, _ in actions {
      let key = entity_key({ kind: action_kind, id, })
      if action_ids.contains(key) || action_ids.length() >= 16384 {
        raise PolicyError("duplicate or excessive schema actions")
      }
      action_ids[key] = true
    }
  }
  (shapes, action_ids)
}

///|
/// Decode entity attributes using resolved Cedar JSON schema types. Supports
/// entity references, records, sets, basic values and the IP, decimal,
/// datetime and duration extensions. This is not schema validation.
pub fn tagged_entities_from_json_with_resolved_schema(
  value : Json,
  schema : Json,
) -> Array[TaggedEntity] raise PolicyError {
  let entities = tagged_entities_from_json(value)
  let items = match value {
    Array(items) => items
    _ => raise PolicyError("entities must be an array")
  }
  let count = Ref(0)
  let (shapes, action_ids) = resolved_schema_index(schema)
  let result : Array[TaggedEntity] = []
  for i in 0..<entities.length() {
    let tagged = entities[i]
    let input = object(items[i], "entity")
    let shape = match shapes.get(tagged.entity.uid.kind) {
      Some(shape) => shape
      None =>
        if action_ids.contains(entity_key(tagged.entity.uid)) {
          { "type": "Record", "attributes": Json::object(Map([])) }
        } else {
          raise PolicyError("entity type not declared in resolved schema")
        }
    }
    let attrs = match
      decode_resolved_value(required(input, "attrs"), shape, 0, count) {
      RecordValue(attrs) => attrs
      _ => raise PolicyError("entity schema shape must be a record")
    }
    result.push({ entity: { ..tagged.entity, attrs, }, tags: tagged.tags, })
  }
  result
}
