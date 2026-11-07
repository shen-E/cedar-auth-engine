///|
/// Test Cedar entity membership, including reflexive membership.
pub fn EntityStore::is_descendant(
  self : EntityStore,
  child : EntityId,
  ancestor : EntityId,
) -> Bool {
  is_descendant(self.graph, child, ancestor)
}

///|
/// Return distinct direct and transitive parents, excluding the entity itself.
pub fn EntityStore::ancestors(
  self : EntityStore,
  uid : EntityId,
) -> Array[EntityId] {
  let visited : Map[String, Bool] = Map([])
  visited[entity_key(uid)] = true
  let pending = [uid]
  let result = []
  let mut next = 0
  while next < pending.length() {
    let current = pending[next]
    next += 1
    match find_entity(self.graph, current) {
      Some(tagged) =>
        for parent in tagged.entity.parents {
          let key = entity_key(parent)
          if !visited.contains(key) {
            visited[key] = true
            pending.push(parent)
            result.push(parent)
          }
        }
      None => ()
    }
  }
  result
}

///|
/// Return distinct stored descendants, excluding the queried entity itself.
pub fn EntityStore::descendants(
  self : EntityStore,
  uid : EntityId,
) -> Array[EntityId] {
  let target = entity_key(uid)
  let children : Map[String, Array[EntityId]] = Map([])
  for tagged in self.graph.entities {
    for parent in tagged.entity.parents {
      let key = entity_key(parent)
      // Other absent parents cannot occur later in a descendant traversal.
      if key == target || self.graph.index.contains(key) {
        match children.get(key) {
          Some(existing) => existing.push(tagged.entity.uid)
          None => children[key] = [tagged.entity.uid]
        }
      }
    }
  }
  let visited : Map[String, Bool] = Map([])
  visited[target] = true
  let pending = [uid]
  let result = []
  let mut next = 0
  while next < pending.length() {
    let current = pending[next]
    next += 1
    match children.get(entity_key(current)) {
      Some(values) =>
        for child in values {
          let key = entity_key(child)
          if !visited.contains(key) {
            visited[key] = true
            pending.push(child)
            result.push(child)
          }
        }
      None => ()
    }
  }
  result
}
