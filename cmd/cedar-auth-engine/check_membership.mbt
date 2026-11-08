///|
fn membership_uid(value : Json) -> @engine.EntityId raise {
  let fields = match value {
    Object(fields) => fields
    _ => raise CliError("membership entity must be an object")
  }
  if fields.length() != 2 {
    raise CliError("membership entity must contain only type and id")
  }
  let uid : @engine.EntityId = match (fields.get("type"), fields.get("id")) {
    (Some(String(kind)), Some(String(id))) => { kind, id, }
    _ => raise CliError("membership entity requires string type and id")
  }
  uid.validate()
  uid
}

///|
fn run_check_membership(args : Array[String]) -> Int32 raise {
  if args.length() != 4 &&
    !(args.length() == 6 && args[4] == "--format" && args[5] == "json") {
    raise CliError("invalid arguments; use --help")
  }
  let entities = @engine.tagged_entities_from_json(load_json(args[2]))
  let store = @engine.EntityStore::new_with_tags(entities)
  let items = match load_json(args[3]) {
    Array(items) => items
    _ => raise CliError("membership input must be an array")
  }
  if items.length() > 16384 {
    raise CliError("membership batch limit exceeded")
  }
  let pairs : Array[(@engine.EntityId, @engine.EntityId)] = []
  for item in items {
    let fields = match item {
      Object(fields) => fields
      _ => raise CliError("membership query must be an object")
    }
    match (fields.get("child"), fields.get("ancestor")) {
      (Some(child), Some(ancestor)) => {
        if fields.length() != 2 {
          raise CliError("unknown membership query field")
        }
        pairs.push((membership_uid(child), membership_uid(ancestor)))
      }
      _ => raise CliError("membership query requires child and ancestor")
    }
  }
  let results = store.is_descendant_batch(pairs)
  if args.length() == 6 {
    let output : Array[Json] = []
    for result in results {
      output.push(
        if result {
          Json::boolean(true)
        } else {
          Json::boolean(false)
        },
      )
    }
    println(Json::array(output).stringify())
  } else {
    for result in results {
      println(if result { "true" } else { "false" })
    }
  }
  0
}
