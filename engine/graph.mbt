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
fn same_parents(left : Array[EntityId], right : Array[EntityId]) -> Bool {
  let a : Map[String, Bool] = Map([])
  let b : Map[String, Bool] = Map([])
  for uid in left {
    a[entity_key(uid)] = true
  }
  for uid in right {
    b[entity_key(uid)] = true
  }
  if a.length() != b.length() {
    return false
  }
  for key, _ in a {
    if !b.contains(key) {
      return false
    }
  }
  true
}

///|
fn same_entity(
  left : TaggedEntity,
  right : TaggedEntity,
  budget : Ref[Int32],
) -> Bool raise PolicyError {
  same_parents(left.entity.parents, right.entity.parents) &&
  same_value(
    RecordValue(left.entity.attrs),
    RecordValue(right.entity.attrs),
    budget,
    0,
  ) &&
  same_value(RecordValue(left.tags), RecordValue(right.tags), budget, 0)
}

///|
fn build_entity_graph(
  entities : Array[TaggedEntity],
) -> EntityGraph raise PolicyError {
  if entities.length() > 16384 {
    raise PolicyError("entity limit exceeded")
  }
  let index : Map[String, Int32] = Map([])
  let unique : Array[TaggedEntity] = []
  let budget = Ref(1000000)
  let mut edges = 0
  for tagged in entities {
    let entity = tagged.entity
    let key = entity_key(entity.uid)
    let parent_count = entity.parents.length()
    if parent_count > 131072 - edges {
      raise PolicyError("entity parent limit exceeded")
    }
    edges += parent_count
    match index.get(key) {
      Some(i) =>
        if !same_entity(unique[i], tagged, budget) {
          raise PolicyError("duplicate entity")
        }
      None => {
        index[key] = unique.length()
        unique.push(tagged)
      }
    }
  }
  // Count incoming edges only for entities in the supplied slice; references
  // to absent parents are allowed and cannot participate in a cycle.
  let incoming = Array::make(unique.length(), 0)
  for tagged in unique {
    for parent in tagged.entity.parents {
      match index.get(entity_key(parent)) {
        Some(i) => incoming[i] += 1
        None => ()
      }
    }
  }
  let pending = []
  for i in 0..<unique.length() {
    if incoming[i] == 0 {
      pending.push(i)
    }
  }
  let mut next = 0
  while next < pending.length() {
    let entity = unique[pending[next]].entity
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
  if next != unique.length() {
    raise PolicyError("entity hierarchy contains a cycle")
  }
  { entities: unique, index, }
}

///|
/// Validate limits and hierarchy cycles; reject conflicting duplicate IDs.
pub fn validate_entities(
  entities : Array[TaggedEntity],
) -> Unit raise PolicyError {
  let _ = build_entity_graph(entities)
}
