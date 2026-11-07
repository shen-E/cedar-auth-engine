///|
fn validate_typed_value(
  value : Value,
  depth : Int32,
  count : Ref[Int32],
) -> Unit raise PolicyError {
  if depth > 64 {
    raise PolicyError("value nesting limit exceeded")
  }
  if count.val >= 524288 {
    raise PolicyError("value limit exceeded")
  }
  count.val += 1
  match value {
    EntityValue(uid) => uid.validate()
    SetValue(items) =>
      for item in items {
        validate_typed_value(item, depth + 1, count)
      }
    RecordValue(fields) =>
      for _, item in fields {
        validate_typed_value(item, depth + 1, count)
      }
    _ => ()
  }
}

///|
fn validate_typed_fields(
  fields : Map[String, Value],
  count : Ref[Int32],
) -> Unit raise PolicyError {
  for _, value in fields {
    validate_typed_value(value, 0, count)
  }
}

///|
/// Validate typed request entity names and bound context values.
pub fn Request::validate(self : Request) -> Unit raise PolicyError {
  self.principal.validate()
  self.action.validate()
  self.resource.validate()
  validate_typed_fields(self.context, Ref(0))
}

///|
/// Validate typed entity names, hierarchy and nested attribute and tag values.
pub fn validate_typed_entities(
  entities : Array[TaggedEntity],
) -> Unit raise PolicyError {
  validate_entities(entities)
  validate_typed_entity_values(entities)
}

///|
fn validate_typed_entity_values(
  entities : Array[TaggedEntity],
) -> Unit raise PolicyError {
  let count = Ref(0)
  for tagged in entities {
    tagged.entity.uid.validate()
    for parent in tagged.entity.parents {
      parent.validate()
    }
    validate_typed_fields(tagged.entity.attrs, count)
    validate_typed_fields(tagged.tags, count)
  }
}

///|
/// Validate and snapshot typed entities without tags.
pub fn EntityStore::new_checked(
  entities : Array[Entity],
) -> EntityStore raise PolicyError {
  if entities.length() > 16384 {
    raise PolicyError("entity limit exceeded")
  }
  let tagged = []
  for entity in entities {
    tagged.push({ entity, tags: {}, })
  }
  EntityStore::new_with_tags_checked(tagged)
}

///|
/// Validate and snapshot typed entities and tags.
pub fn EntityStore::new_with_tags_checked(
  entities : Array[TaggedEntity],
) -> EntityStore raise PolicyError {
  let store = EntityStore::new_with_tags(entities)
  validate_typed_entity_values(store.graph.entities)
  store
}

///|
/// Validate a typed request before authorizing it.
pub fn EntityStore::authorize_checked(
  self : EntityStore,
  policies : PolicySet,
  request : Request,
) -> Response raise PolicyError {
  request.validate()
  self.authorize(policies, request)
}

///|
/// Validate every typed request before authorizing the batch.
pub fn EntityStore::authorize_batch_checked(
  self : EntityStore,
  policies : PolicySet,
  requests : Array[Request],
) -> Array[Response] raise PolicyError {
  if requests.length() > 16384 {
    raise PolicyError("request batch limit exceeded")
  }
  for request in requests {
    request.validate()
  }
  self.authorize_batch(policies, requests)
}
