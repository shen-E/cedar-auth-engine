///|
priv struct EntityGraph {
  entities : Array[TaggedEntity]
  index : Map[String, Int32]
}

///|
// The length prefix keeps distinct type/ID pairs from sharing an index key.
fn entity_key(uid : EntityId) -> String {
  "\{uid.kind.length()}:\{uid.kind}\{uid.id}"
}

///|
fn build_entity_graph(
  entities : Array[TaggedEntity],
) -> EntityGraph raise PolicyError {
  if entities.length() > 16384 {
    raise PolicyError("entity limit exceeded")
  }
  let index : Map[String, Int32] = Map([])
  let mut edges = 0
  for i in 0..<entities.length() {
    let entity = entities[i].entity
    let key = entity_key(entity.uid)
    if index.contains(key) {
      raise PolicyError("duplicate entity")
    }
    index[key] = i
    let parent_count = entity.parents.length()
    if parent_count > 131072 - edges {
      raise PolicyError("entity parent limit exceeded")
    }
    edges += parent_count
  }
  // Count incoming edges only for entities in the supplied slice; references
  // to absent parents are allowed and cannot participate in a cycle.
  let incoming = Array::make(entities.length(), 0)
  for tagged in entities {
    for parent in tagged.entity.parents {
      match index.get(entity_key(parent)) {
        Some(i) => incoming[i] += 1
        None => ()
      }
    }
  }
  let pending = []
  for i in 0..<entities.length() {
    if incoming[i] == 0 {
      pending.push(i)
    }
  }
  let mut next = 0
  while next < pending.length() {
    let entity = entities[pending[next]].entity
    next += 1
    for parent in entity.parents {
      match index.get(entity_key(parent)) {
        Some(i) => {
          incoming[i] -= 1
          if incoming[i] == 0 {
            pending.push(i)
          }
        }
        None => ()
      }
    }
  }
  if next != entities.length() {
    raise PolicyError("entity hierarchy contains a cycle")
  }
  { entities, index, }
}

///|
/// Validate entity and parent-link limits, unique IDs, and hierarchy cycles.
pub fn validate_entities(
  entities : Array[TaggedEntity],
) -> Unit raise PolicyError {
  let _ = build_entity_graph(entities)
}
