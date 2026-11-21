///|
// Decode a value using a resolved Cedar JSON type. This is input decoding,
// not policy, schema, entity hierarchy or request validation.
fn decode_resolved_value(
  value : Json,
  spec : Json,
  depth : Int32,
  count : Ref[Int32],
  work : Ref[Int32],
) -> Value raise PolicyError {
  decode_resolved_value_impl(value, spec, depth, count, work, true)
}

///|
fn decode_resolved_value_impl(
  value : Json,
  spec : Json,
  depth : Int32,
  count : Ref[Int32],
  work : Ref[Int32],
  enforce_entity_type : Bool,
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
      if enforce_entity_type && uid.kind != expected {
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
        result.push(
          decode_resolved_value_impl(
            item,
            element,
            depth + 1,
            count,
            work,
            enforce_entity_type,
          ),
        )
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
      for key, attribute in attributes {
        if work.val <= 0 {
          raise PolicyError("resolved schema field work limit exceeded")
        }
        work.val -= 1
        let definition = object(attribute, "schema attribute")
        let mandatory = match definition.get("required") {
          None | Some(True) => true
          Some(False) => false
          _ => raise PolicyError("schema required must be a boolean")
        }
        if mandatory && !input.contains(key) {
          raise PolicyError("required schema field missing: \{key}")
        }
      }
      let result : Map[String, Value] = Map([])
      for key, item in input {
        let attribute = match attributes.get(key) {
          Some(spec) => spec
          None => raise PolicyError("attribute not declared in resolved schema")
        }
        result[key] = decode_resolved_value_impl(
          item,
          attribute,
          depth + 1,
          count,
          work,
          enforce_entity_type,
        )
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
) -> (Map[String, Json], Map[String, Json], Map[String, Bool]) raise PolicyError {
  let namespaces = object(schema, "resolved schema")
  let shapes : Map[String, Json] = Map([])
  let tag_types : Map[String, Json] = Map([])
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
      match entity.get("tags") {
        Some(tag_type) => tag_types[qualified] = tag_type
        None => ()
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
  (shapes, tag_types, action_ids)
}

///|
/// Decode entity attributes and tags using resolved Cedar JSON schema types. Supports
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
  let work = Ref(1000000)
  let (shapes, tag_types, action_ids) = resolved_schema_index(schema)
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
      decode_resolved_value(required(input, "attrs"), shape, 0, count, work) {
      RecordValue(attrs) => attrs
      _ => raise PolicyError("entity schema shape must be a record")
    }
    let tags : Map[String, Value] = Map([])
    match input.get("tags") {
      Some(value) => {
        let input_tags = object(value, "entity tags")
        if !input_tags.is_empty() {
          let tag_spec = match tag_types.get(tagged.entity.uid.kind) {
            Some(spec) => spec
            None => raise PolicyError("entity type does not declare tags")
          }
          for key, item in input_tags {
            tags[key] = decode_resolved_value(item, tag_spec, 0, count, work)
          }
        }
      }
      None => ()
    }
    result.push({ entity: { ..tagged.entity, attrs, }, tags, })
  }
  result
}

///|
/// Decode entities and check enum IDs in entity UIDs, parents, attributes and
/// tags. This is a partial check, not full entity or schema validation.
pub fn tagged_entities_from_json_with_checked_enums(
  value : Json,
  schema : Json,
) -> Array[TaggedEntity] raise PolicyError {
  let entities = tagged_entities_from_json_with_resolved_schema(value, schema)
  let index = ResolvedContextSchema::from_json(schema)
  for tagged in entities {
    index.check_enum_id(tagged.entity.uid)
    for parent in tagged.entity.parents {
      index.check_enum_id(parent)
    }
    for _, value in tagged.entity.attrs {
      index.check_enum_value(value)
    }
    for _, value in tagged.tags {
      index.check_enum_value(value)
    }
  }
  entities
}

///|
/// Check non-action entity parent types against the transitive memberOfTypes
/// declarations in a resolved schema. Action entities are not checked. This
/// does not validate the schema, entity IDs or graph cycles.
pub fn check_entity_parent_types(
  entities : Array[TaggedEntity],
  schema : Json,
) -> Unit raise PolicyError {
  let graph : Map[String, Array[String]] = Map([])
  let mut edge_count = 0
  for ns, body in object(schema, "resolved schema") {
    let fields = object(body, "schema namespace")
    let types = match fields.get("entityTypes") {
      Some(types) => object(types, "schema entity types")
      None => Map([])
    }
    for name, definition in types {
      let kind = if ns == "" { name } else { ns + "::" + name }
      if graph.contains(kind) || graph.length() >= 16384 {
        raise PolicyError("duplicate or excessive schema entity types")
      }
      let entity = object(definition, "schema entity type")
      let parents = match entity.get("memberOfTypes") {
        None => []
        Some(Array(items)) => items
        _ => raise PolicyError("memberOfTypes must be an array")
      }
      let list : Array[String] = []
      for parent in parents {
        edge_count += 1
        if edge_count > 131072 {
          raise PolicyError("schema parent type limit exceeded")
        }
        match parent {
          String(value) => list.push(value)
          _ => raise PolicyError("memberOfTypes must contain strings")
        }
      }
      graph[kind] = list
    }
  }
  let (_, _, action_ids) = resolved_schema_index(schema)
  let cache : Map[String, Map[String, Bool]] = Map([])
  let mut work = 0
  for tagged in entities {
    let uid = tagged.entity.uid
    if !action_ids.contains(entity_key(uid)) &&
      !tagged.entity.parents.is_empty() {
      if !graph.contains(uid.kind) {
        raise PolicyError("entity type not declared in resolved schema")
      }
      let allowed = match cache.get(uid.kind) {
        Some(cached) => cached
        None => {
          let found : Map[String, Bool] = Map([])
          let queue : Array[String] = [uid.kind]
          let mut i = 0
          while i < queue.length() {
            let current = queue[i]
            i += 1
            match graph.get(current) {
              Some(parents) =>
                for parent in parents {
                  work += 1
                  if work > 1000000 {
                    raise PolicyError("schema parent type work limit exceeded")
                  }
                  if !found.contains(parent) {
                    found[parent] = true
                    queue.push(parent)
                  }
                }
              None => ()
            }
          }
          cache[uid.kind] = found
          found
        }
      }
      for parent in tagged.entity.parents {
        if !allowed.contains(parent.kind) {
          raise PolicyError("entity parent type is not allowed by schema")
        }
      }
    }
  }
}

///|
/// Add schema-declared actions and their transitive ancestors to an entity
/// snapshot. Explicit action entities must match the schema definition.
/// This does not validate the schema or non-action entities.
pub fn entities_with_schema_actions(
  entities : Array[TaggedEntity],
  schema : Json,
) -> Array[TaggedEntity] raise PolicyError {
  let actions : Map[String, EntityId] = Map([])
  let graph : Map[String, Array[EntityId]] = Map([])
  let action_kinds : Map[String, Bool] = Map([])
  let mut edges = 0
  for ns, body in object(schema, "resolved schema") {
    let fields = object(body, "schema namespace")
    let declared = match fields.get("actions") {
      Some(value) => object(value, "schema actions")
      None => Map([])
    }
    let kind = if ns == "" { "Action" } else { ns + "::Action" }
    action_kinds[kind] = true
    for id, value in declared {
      let uid : EntityId = { kind, id, }
      let key = entity_key(uid)
      if actions.contains(key) || actions.length() >= 16384 {
        raise PolicyError("duplicate or excessive schema actions")
      }
      let definition = object(value, "schema action")
      let members = match definition.get("memberOf") {
        None => []
        Some(Array(items)) => items
        _ => raise PolicyError("action memberOf must be an array")
      }
      let parents : Array[EntityId] = []
      for parent_item in members {
        edges += 1
        if edges > 131072 {
          raise PolicyError("schema action parent limit exceeded")
        }
        let fields = object(parent_item, "action parent")
        let parent_kind = match fields.get("type") {
          Some(String(value)) => value
          None => kind
          _ => raise PolicyError("action parent type must be a string")
        }
        parents.push({ kind: parent_kind, id: string_field(fields, "id"), })
      }
      actions[key] = uid
      graph[key] = parents
    }
  }
  let expanded : Map[String, Array[EntityId]] = Map([])
  let mut work = 0
  for key, uid in actions {
    let found : Map[String, Bool] = Map([])
    let queue : Array[EntityId] = [uid]
    let parents : Array[EntityId] = []
    let mut i = 0
    while i < queue.length() {
      let current = queue[i]
      i += 1
      let current_key = entity_key(current)
      match graph.get(current_key) {
        Some(members) =>
          for parent_item in members {
            work += 1
            if work > 1000000 {
              raise PolicyError("schema action traversal limit exceeded")
            }
            let parent_key = entity_key(parent_item)
            if !actions.contains(parent_key) {
              raise PolicyError("action parent is not declared in schema")
            }
            if parent_key == key {
              raise PolicyError("schema action hierarchy contains a cycle")
            }
            if !found.contains(parent_key) {
              found[parent_key] = true
              parents.push(parent_item)
              queue.push(parent_item)
            }
          }
        None => raise PolicyError("action parent is not declared in schema")
      }
    }
    expanded[key] = parents
  }
  let seen : Map[String, Bool] = Map([])
  let result : Array[TaggedEntity] = []
  for tagged in entities {
    let key = entity_key(tagged.entity.uid)
    match expanded.get(key) {
      Some(parents) => {
        if !same_parents(tagged.entity.parents, parents) ||
          !tagged.entity.attrs.is_empty() ||
          !tagged.tags.is_empty() {
          raise PolicyError("action entity does not match schema declaration")
        }
        seen[key] = true
      }
      None =>
        if action_kinds.contains(tagged.entity.uid.kind) {
          raise PolicyError("action entity is not declared in schema")
        }
    }
    result.push(tagged)
  }
  for key, uid in actions {
    if !seen.contains(key) {
      result.push({
        entity: { uid, attrs: {}, parents: expanded[key], },
        tags: {},
      })
    }
  }
  let _ = build_entity_graph(result)
  result
}
