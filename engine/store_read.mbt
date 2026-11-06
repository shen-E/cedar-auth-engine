///|
// Store construction already bounds nesting and rejects cyclic containers.
fn copy_snapshot_value(value : Value) -> Value {
  match value {
    SetValue(items) => {
      let result = []
      for item in items {
        result.push(copy_snapshot_value(item))
      }
      SetValue(result)
    }
    RecordValue(fields) => RecordValue(copy_snapshot_fields(fields))
    _ => value
  }
}

///|
fn copy_snapshot_fields(fields : Map[String, Value]) -> Map[String, Value] {
  let result : Map[String, Value] = Map([])
  for key, value in fields {
    result[key] = copy_snapshot_value(value)
  }
  result
}

///|
fn copy_snapshot_entity(tagged : TaggedEntity) -> TaggedEntity {
  {
    entity: {
      uid: tagged.entity.uid,
      attrs: copy_snapshot_fields(tagged.entity.attrs),
      parents: tagged.entity.parents.copy(),
    },
    tags: copy_snapshot_fields(tagged.tags),
  }
}

///|
/// Return the number of entities in this snapshot.
pub fn EntityStore::length(self : EntityStore) -> Int32 {
  self.graph.entities.length()
}

///|
/// Find an entity by ID, returning an independent copy if present.
pub fn EntityStore::get(self : EntityStore, uid : EntityId) -> TaggedEntity? {
  match self.graph.index.get(entity_key(uid)) {
    Some(index) => Some(copy_snapshot_entity(self.graph.entities[index]))
    None => None
  }
}

///|
/// Return independent copies of the entities in snapshot order.
pub fn EntityStore::entities(self : EntityStore) -> Array[TaggedEntity] {
  let result = []
  for entity in self.graph.entities {
    result.push(copy_snapshot_entity(entity))
  }
  result
}
