///|
/// Insert or replace complete tagged entities in a new, validated snapshot.
pub fn EntityStore::upsert(
  self : EntityStore,
  updates : Array[TaggedEntity],
) -> EntityStore raise PolicyError {
  self.apply_changes(updates, [])
}

///|
/// Apply entity inserts, replacements and removals to one new snapshot.
pub fn EntityStore::apply_changes(
  self : EntityStore,
  updates : Array[TaggedEntity],
  removals : Array[EntityId],
) -> EntityStore raise PolicyError {
  if updates.length() > 4096 {
    raise PolicyError("entity update limit exceeded")
  }
  if removals.length() > 4096 {
    raise PolicyError("entity removal limit exceeded")
  }
  let positions : Map[String, Int32] = Map([])
  for i in 0..<updates.length() {
    let key = entity_key(updates[i].entity.uid)
    if positions.contains(key) {
      raise PolicyError("duplicate entity update")
    }
    positions[key] = i
  }
  let removed : Map[String, Bool] = Map([])
  for uid in removals {
    uid.validate()
    let key = entity_key(uid)
    if removed.contains(key) {
      raise PolicyError("duplicate entity removal")
    }
    if !self.graph.index.contains(key) {
      raise PolicyError("unknown entity removal")
    }
    if positions.contains(key) {
      raise PolicyError("entity cannot be updated and removed")
    }
    removed[key] = true
  }
  let entities = []
  for current in self.graph.entities {
    let key = entity_key(current.entity.uid)
    if !removed.contains(key) {
      match positions.get(key) {
        Some(i) => entities.push(updates[i])
        None => entities.push(current)
      }
    }
  }
  for update in updates {
    if !self.graph.index.contains(entity_key(update.entity.uid)) {
      entities.push(update)
    }
  }
  EntityStore::new_with_tags_checked(entities)
}

///|
/// Return a new snapshot without the entity identified by `uid`.
pub fn EntityStore::remove(
  self : EntityStore,
  uid : EntityId,
) -> EntityStore raise PolicyError {
  self.remove_batch([uid])
}

///|
/// Remove all specified entities or raise an error without changing the store.
pub fn EntityStore::remove_batch(
  self : EntityStore,
  uids : Array[EntityId],
) -> EntityStore raise PolicyError {
  self.apply_changes([], uids)
}
