///|
priv enum JsonContainer {
  JsonObject(Map[String, Bool])
  JsonArray
}

///|
pub fn parse_json(text : String) -> Json raise PolicyError {
  let chars = text.to_array()
  if chars.length() > 8388608 {
    raise PolicyError("JSON input exceeds 8 MiB")
  }
  let stack : Array[JsonContainer] = []
  let mut i = 0
  while i < chars.length() {
    match chars[i] {
      '{' => {
        stack.push(JsonObject(Map([])))
        i += 1
      }
      '[' => {
        stack.push(JsonArray)
        i += 1
      }
      '}' | ']' => {
        if !stack.is_empty() {
          let _ = stack.pop()
        }
        i += 1
      }
      '"' => {
        let token = StringBuilder()
        token.write_char('"')
        i += 1
        let mut done = false
        while i < chars.length() {
          let c = chars[i]
          token.write_char(c)
          i += 1
          if c == '\\' {
            if i >= chars.length() {
              raise PolicyError("unterminated JSON escape")
            }
            token.write_char(chars[i])
            i += 1
          } else if c == '"' {
            done = true
            break
          }
        }
        if !done {
          raise PolicyError("unterminated JSON string")
        }
        let mut next = i
        while next < chars.length() &&
              (
                chars[next] == ' ' ||
                chars[next] == '\n' ||
                chars[next] == '\r' ||
                chars[next] == '\t'
              ) {
          next += 1
        }
        if next < chars.length() && chars[next] == ':' && !stack.is_empty() {
          match stack[stack.length() - 1] {
            JsonObject(keys) => {
              let key = quoted(token.to_string())
              if keys.contains(key) {
                raise PolicyError("duplicate JSON key '\{key}'")
              }
              keys[key] = true
            }
            JsonArray => ()
          }
        }
      }
      _ => i += 1
    }
    if stack.length() > 64 {
      raise PolicyError("JSON nesting limit exceeded")
    }
  }
  @json.parse(text) catch {
    e => raise PolicyError("invalid JSON: " + e.to_string())
  }
}

///|
fn object(value : Json, label : String) -> Map[String, Json] raise PolicyError {
  match value {
    Object(fields) => fields
    _ => raise PolicyError("\{label} must be an object")
  }
}

///|
fn check_fields(
  fields : Map[String, Json],
  allowed : Array[String],
  label : String,
) -> Unit raise PolicyError {
  for key, _ in fields {
    if !allowed.contains(key) {
      raise PolicyError("unknown \{label} field '\{key}'")
    }
  }
}

///|
fn required(
  fields : Map[String, Json],
  name : String,
) -> Json raise PolicyError {
  match fields.get(name) {
    Some(value) => value
    None => raise PolicyError("missing field '\{name}'")
  }
}

///|
fn string_field(
  fields : Map[String, Json],
  name : String,
) -> String raise PolicyError {
  match required(fields, name) {
    String(value) => value
    _ => raise PolicyError("field '\{name}' must be a string")
  }
}

///|
fn entity_id(value : Json) -> EntityId raise PolicyError {
  let fields = object(value, "entity id")
  check_fields(fields, ["type", "id"], "entity id")
  let uid : EntityId = {
    kind: string_field(fields, "type"),
    id: string_field(fields, "id"),
  }
  uid.validate()
  uid
}

///|
fn json_value(
  value : Json,
  depth : Int32,
  count : Ref[Int32],
) -> Value raise PolicyError {
  if depth > 64 {
    raise PolicyError("value nesting limit exceeded")
  }
  if count.val >= 524288 {
    raise PolicyError("value limit exceeded")
  }
  count.val += 1
  match value {
    True => BoolValue(true)
    False => BoolValue(false)
    String(s) => StringValue(s)
    Number(_) => {
      let n : Int64 = @json.from_json(Json::string(value.stringify())) catch {
        _ => raise PolicyError("expected signed 64-bit integer")
      }
      LongValue(n)
    }
    Array(items) => {
      if items.length() > 524288 - count.val {
        raise PolicyError("value limit exceeded")
      }
      let result = []
      for item in items {
        result.push(json_value(item, depth + 1, count))
      }
      SetValue(result)
    }
    Object(fields) => {
      if fields.contains("__expr") {
        raise PolicyError("Cedar expression values are unsupported")
      }
      if fields.contains("__extn") {
        if fields.length() != 1 {
          raise PolicyError("extension escape must contain only __extn")
        }
        let ext = object(required(fields, "__extn"), "extension escape")
        if ext.length() != 2 {
          raise PolicyError("invalid extension escape")
        }
        let name = string_field(ext, "fn")
        let argument = string_field(ext, "arg")
        return match name {
          "ip" => IpValue(IpAddress::parse(argument))
          "decimal" => DecimalValue(Decimal::parse(argument))
          "duration" => DurationValue(Duration::parse(argument))
          "datetime" => DateTimeValue(DateTime::parse(argument))
          _ => raise PolicyError("unsupported extension value")
        }
      }
      match fields.get("__entity") {
        Some(uid) => {
          if fields.length() != 1 {
            raise PolicyError("entity escape must contain only __entity")
          }
          EntityValue(entity_id(uid))
        }
        None => {
          if fields.length() > 524288 - count.val {
            raise PolicyError("value limit exceeded")
          }
          let result : Map[String, Value] = Map([])
          for key, item in fields {
            result[key] = json_value(item, depth + 1, count)
          }
          RecordValue(result)
        }
      }
    }
    _ => raise PolicyError("null is not a Cedar value")
  }
}

///|
fn value_map(
  value : Json,
  label : String,
  count : Ref[Int32],
) -> Map[String, Value] raise PolicyError {
  let fields = object(value, label)
  if fields.length() > 524288 - count.val {
    raise PolicyError("value limit exceeded")
  }
  let result : Map[String, Value] = Map([])
  for key, item in fields {
    result[key] = json_value(item, 0, count)
  }
  result
}

///|
pub fn request_from_json(value : Json) -> Request raise PolicyError {
  let fields = object(value, "request")
  check_fields(
    fields,
    ["principal", "action", "resource", "context"],
    "request",
  )
  {
    principal: entity_id(required(fields, "principal")),
    action: entity_id(required(fields, "action")),
    resource: entity_id(required(fields, "resource")),
    context: value_map(required(fields, "context"), "context", Ref(0)),
  }
}

///|
/// Parse Cedar entities, retaining their optional tags.
pub fn tagged_entities_from_json(
  value : Json,
) -> Array[TaggedEntity] raise PolicyError {
  let items = match value {
    Array(items) => items
    _ => raise PolicyError("entities must be an array")
  }
  if items.length() > 16384 {
    raise PolicyError("entity limit exceeded")
  }
  let result = []
  let count = Ref(0)
  let mut edges = 0
  for item in items {
    let fields = object(item, "entity")
    check_fields(fields, ["uid", "attrs", "parents", "tags"], "entity")
    let parents = match required(fields, "parents") {
      Array(items) => {
        if items.length() > 131072 - edges {
          raise PolicyError("entity parent limit exceeded")
        }
        edges += items.length()
        let result = []
        for item in items {
          result.push(entity_id(item))
        }
        result
      }
      _ => raise PolicyError("entity parents must be an array")
    }
    let tags = match fields.get("tags") {
      Some(tags) => value_map(tags, "entity tags", count)
      None => Map([])
    }
    result.push({
      entity: {
        uid: entity_id(required(fields, "uid")),
        attrs: value_map(required(fields, "attrs"), "entity attrs", count),
        parents,
      },
      tags,
    })
  }
  result
}

///|
/// Parse entities without tags. Nonempty tags are rejected to avoid data loss.
pub fn entities_from_json(value : Json) -> Array[Entity] raise PolicyError {
  let result = []
  for tagged in tagged_entities_from_json(value) {
    if !tagged.tags.is_empty() {
      raise PolicyError("entity tags require tagged_entities_from_json")
    }
    result.push(tagged.entity)
  }
  result
}

///|
pub fn response_to_json(response : Response) -> Json {
  let reasons : Array[Json] = []
  let errors : Array[Json] = []
  for id in response.reasons {
    reasons.push(Json::string(id))
  }
  for error in response.errors {
    errors.push({ "policy_id": error.policy_id, "message": error.message })
  }
  {
    "decision": match response.decision {
      Allow => "Allow"
      Deny => "Deny"
    },
    "reasons": reasons,
    "errors": errors,
  }
}
