///|
/// A missing parent and the stored entities that directly reference it.
pub(all) struct MissingParent {
  parent : EntityId
  children : Array[EntityId]
} derive(Debug)

///|
pub extend MissingParent with Debug::{to_repr}

///|
/// List absent parent entities and their distinct direct children.
pub fn EntityStore::missing_parents(self : EntityStore) -> Array[MissingParent] {
  let positions : Map[String, Int32] = Map([])
  let result : Array[MissingParent] = []
  for tagged in self.graph.entities {
    let child = tagged.entity.uid
    for parent in tagged.entity.parents {
      let key = entity_key(parent)
      if !self.graph.index.contains(key) {
        match positions.get(key) {
          Some(index) => {
            let children = result[index].children
            if children[children.length() - 1] != child {
              children.push(child)
            }
          }
          None => {
            positions[key] = result.length()
            result.push({ parent, children: [child], })
          }
        }
      }
    }
  }
  result
}

///|
/// Reject a snapshot if any parent link points to an absent entity.
pub fn EntityStore::validate_closed(
  self : EntityStore,
) -> Unit raise PolicyError {
  for tagged in self.graph.entities {
    for parent in tagged.entity.parents {
      if !self.graph.index.contains(entity_key(parent)) {
        raise PolicyError("entity hierarchy has a missing parent")
      }
    }
  }
}
