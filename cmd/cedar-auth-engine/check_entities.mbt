///|
fn uid_json(uid : @engine.EntityId) -> Json {
  { "type": uid.kind, "id": uid.id }
}

///|
fn run_check_entities(args : Array[String]) -> Int32 raise {
  if args.length() < 3 {
    raise CliError("invalid arguments; use --help")
  }
  let mut json = false
  let mut require_closed = false
  let mut i = 3
  while i < args.length() {
    if args[i] == "--format" &&
      !json &&
      i + 1 < args.length() &&
      args[i + 1] == "json" {
      json = true
      i += 2
    } else if args[i] == "--require-closed" && !require_closed {
      require_closed = true
      i += 1
    } else {
      raise CliError("invalid arguments; use --help")
    }
  }
  let entities = @engine.tagged_entities_from_json(load_json(args[2]))
  let store = @engine.EntityStore::new_with_tags(entities)
  let missing = store.missing_parents()
  if json {
    let items : Array[Json] = []
    for item in missing {
      let children : Array[Json] = []
      for child in item.children {
        children.push(uid_json(child))
      }
      items.push({
        "parent": uid_json(item.parent),
        "children": Json::array(children),
      })
    }
    let output : Json = {
      "closed": missing.is_empty(),
      "entity_count": Json::number(store.length().to_double()),
      "missing_parents": Json::array(items),
    }
    println(output.stringify())
  } else if missing.is_empty() {
    println("Entity hierarchy is closed (\{store.length()} entities)")
  } else {
    println("Entity hierarchy has \{missing.length()} missing parents")
    for item in missing {
      println("Missing parent: " + uid_json(item.parent).stringify())
      for child in item.children {
        println("  Referenced by: " + uid_json(child).stringify())
      }
    }
  }
  if require_closed && !missing.is_empty() {
    1
  } else {
    0
  }
}
