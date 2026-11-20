///|
/// Resolved action context types for decoding requests. This does not validate
/// the schema, principal/resource types, or policies.
pub struct ResolvedContextSchema {
  priv contexts : Map[String, Json]
  priv applicability : Map[String, Json]
}

///|
fn copy_context_schema(
  value : Json,
  depth : Int32,
  count : Ref[Int32],
) -> Json raise PolicyError {
  if depth > 64 || count.val >= 524288 {
    raise PolicyError("resolved context schema limit exceeded")
  }
  count.val += 1
  match value {
    Object(fields) => {
      let copied : Map[String, Json] = Map([])
      for key, item in fields {
        copied[key] = copy_context_schema(item, depth + 1, count)
      }
      Json::object(copied)
    }
    Array(items) => {
      let copied : Array[Json] = []
      for item in items {
        copied.push(copy_context_schema(item, depth + 1, count))
      }
      Json::array(copied)
    }
    _ => value
  }
}

///|
/// Index the action context types in a resolved Cedar JSON schema.
pub fn ResolvedContextSchema::from_json(
  schema : Json,
) -> ResolvedContextSchema raise PolicyError {
  let contexts : Map[String, Json] = Map([])
  let applicability : Map[String, Json] = Map([])
  let count = Ref(0)
  for ns, body in object(schema, "resolved schema") {
    let fields = object(body, "schema namespace")
    let actions = match fields.get("actions") {
      Some(value) => object(value, "schema actions")
      None => Map([])
    }
    let action_kind = if ns == "" { "Action" } else { ns + "::Action" }
    for id, value in actions {
      let key = entity_key({ kind: action_kind, id, })
      if contexts.contains(key) || contexts.length() >= 16384 {
        raise PolicyError("duplicate or excessive schema actions")
      }
      let action = object(value, "schema action")
      let applies = match action.get("appliesTo") {
        Some(value) => object(value, "action appliesTo")
        None => Map([])
      }
      let copied = copy_context_schema(Json::object(applies), 0, count)
      applicability[key] = copied
      let copied_fields = object(copied, "action appliesTo")
      contexts[key] = match copied_fields.get("context") {
        Some(value) => value
        None => { "type": "Record", "attributes": Json::object(Map([])) }
      }
    }
  }
  { contexts, applicability, }
}

///|
/// Decode request context using the action's resolved type. Undeclared
/// actions, undeclared context fields and unsupported types are rejected.
pub fn ResolvedContextSchema::request_from_json(
  self : ResolvedContextSchema,
  value : Json,
) -> Request raise PolicyError {
  self.decode_request(value, false)
}

///|
fn resolved_type_allowed(
  fields : Map[String, Json],
  name : String,
  kind : String,
) -> Bool raise PolicyError {
  let allowed = match fields.get(name) {
    Some(Array(items)) => items
    None => []
    _ => raise PolicyError("action type list must be an array")
  }
  let mut found = false
  for item in allowed {
    match item {
      String(value) => if value == kind { found = true }
      _ => raise PolicyError("action type list must contain strings")
    }
  }
  found
}

///|
/// Decode and check action applicability and context entity-reference types.
/// This is a partial check, not full schema or request validation.
pub fn ResolvedContextSchema::request_from_json_with_action_types(
  self : ResolvedContextSchema,
  value : Json,
) -> Request raise PolicyError {
  self.decode_request(value, true)
}

///|
fn ResolvedContextSchema::decode_request(
  self : ResolvedContextSchema,
  value : Json,
  check_types : Bool,
) -> Request raise PolicyError {
  let request = request_from_json(value)
  let key = entity_key(request.action)
  let shape = match self.contexts.get(key) {
    Some(shape) => shape
    None => raise PolicyError("action not declared in resolved schema")
  }
  if check_types {
    let applies = object(self.applicability[key], "action appliesTo")
    if !resolved_type_allowed(applies, "principalTypes", request.principal.kind) ||
      !resolved_type_allowed(applies, "resourceTypes", request.resource.kind) {
      raise PolicyError(
        "request entity types do not match action applicability",
      )
    }
  }
  let fields = object(value, "request")
  let context = match
    decode_resolved_value_impl(
      required(fields, "context"),
      shape,
      0,
      Ref(0),
      Ref(1000000),
      check_types,
    ) {
    RecordValue(context) => context
    _ => raise PolicyError("action context schema must be a record")
  }
  { ..request, context, }
}
