///|
/// An immutable snapshot of validated entities for repeated authorization.
pub struct EntityStore {
  priv graph : EntityGraph
}

///|
fn copy_store_value(
  value : Value,
  depth : Int32,
  count : Ref[Int32],
) -> Value raise PolicyError {
  if depth > 64 {
    raise PolicyError("entity value nesting limit exceeded")
  }
  if count.val >= 524288 {
    raise PolicyError("entity value limit exceeded")
  }
  count.val += 1
  match value {
    SetValue(items) => {
      let copied = []
      for item in items {
        copied.push(copy_store_value(item, depth + 1, count))
      }
      SetValue(copied)
    }
    RecordValue(fields) => {
      let copied : Map[String, Value] = Map([])
      for key, item in fields {
        copied[key] = copy_store_value(item, depth + 1, count)
      }
      RecordValue(copied)
    }
    _ => value
  }
}

///|
fn copy_store_fields(
  fields : Map[String, Value],
  count : Ref[Int32],
) -> Map[String, Value] raise PolicyError {
  let copied : Map[String, Value] = Map([])
  for key, value in fields {
    copied[key] = copy_store_value(value, 0, count)
  }
  copied
}

///|
/// Validate and snapshot entities without tags.
pub fn EntityStore::new(
  entities : Array[Entity],
) -> EntityStore raise PolicyError {
  if entities.length() > 16384 {
    raise PolicyError("entity limit exceeded")
  }
  let tagged = []
  for entity in entities {
    tagged.push({ entity, tags: {}, })
  }
  EntityStore::new_with_tags(tagged)
}

///|
/// Validate and snapshot entities and their tags, including nested values.
pub fn EntityStore::new_with_tags(
  entities : Array[TaggedEntity],
) -> EntityStore raise PolicyError {
  let graph = build_entity_graph(entities)
  let copied = []
  let count = Ref(0)
  for tagged in entities {
    copied.push({
      entity: {
        uid: tagged.entity.uid,
        attrs: copy_store_fields(tagged.entity.attrs, count),
        parents: tagged.entity.parents.copy(),
      },
      tags: copy_store_fields(tagged.tags, count),
    })
  }
  { graph: { entities: copied, index: graph.index, }, }
}

///|
/// Authorize one request using this entity snapshot.
pub fn EntityStore::authorize(
  self : EntityStore,
  policies : PolicySet,
  request : Request,
) -> Response {
  authorize_in_graph(policies, request, self.graph)
}

///|
/// Authorize up to 32,768 requests using this entity snapshot.
pub fn EntityStore::authorize_batch(
  self : EntityStore,
  policies : PolicySet,
  requests : Array[Request],
) -> Array[Response] raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  let context = EvaluationContext::new(self.graph)
  let responses = []
  for request in requests {
    responses.push(authorize_in_context(policies, request, context))
  }
  responses
}
