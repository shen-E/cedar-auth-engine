///|
test "equivalent duplicate entities retain one independent snapshot" {
  let team : EntityId = { kind: "Group", id: "team", }
  let other : EntityId = { kind: "Group", id: "other", }
  let uid : EntityId = { kind: "User", id: "alice", }
  let first : TaggedEntity = {
    entity: {
      uid,
      attrs: { "roles": SetValue([LongValue(1L), LongValue(2L)]) },
      parents: [team, other],
    },
    tags: { "labels": SetValue([StringValue("a"), StringValue("b")]) },
  }
  let second : TaggedEntity = {
    entity: {
      uid,
      attrs: {
        "roles": SetValue([LongValue(2L), LongValue(1L), LongValue(1L)]),
      },
      parents: [other, team, team],
    },
    tags: { "labels": SetValue([StringValue("b"), StringValue("a")]) },
  }
  let extra = group("team", [])
  let store = EntityStore::new_with_tags_checked([first, extra, second])
  assert_true(store.length() == 2)
  assert_true(store.is_descendant(uid, team) && store.is_descendant(uid, other))
  assert_true(store.missing_parents().length() == 1)
  first.entity.attrs.clear()
  first.tags.clear()
  assert_true(store.get(uid).unwrap().entity.attrs.contains("roles"))
  assert_true(store.get(uid).unwrap().tags.contains("labels"))
}

///|
test "duplicate entities reject distinct attributes, tags and parent sets" {
  let uid : EntityId = { kind: "User", id: "alice", }
  let first : TaggedEntity = {
    entity: { uid, attrs: { "active": BoolValue(true) }, parents: [], },
    tags: { "label": StringValue("a") },
  }
  let conflicts : Array[TaggedEntity] = [
    {
      ..first,
      entity: { ..first.entity, attrs: { "active": BoolValue(false) }, },
    },
    { ..first, tags: { "label": StringValue("b") }, },
    {
      ..first,
      entity: { ..first.entity, parents: [{ kind: "Group", id: "x", }], },
    },
  ]
  for conflict in conflicts {
    let rejected = try {
      let _ = EntityStore::new_with_tags([first, conflict])
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
}

///|
test "duplicate entity equality is bounded" {
  let left = []
  let right = []
  for i in 0..<1500 {
    left.push(LongValue(i.to_int64()))
    right.push(LongValue((1499 - i).to_int64()))
  }
  let uid : EntityId = { kind: "User", id: "alice", }
  let first : TaggedEntity = {
    entity: { uid, attrs: { "values": SetValue(left) }, parents: [], },
    tags: {},
  }
  let second : TaggedEntity = {
    entity: { uid, attrs: { "values": SetValue(right) }, parents: [], },
    tags: {},
  }
  let rejected = try {
    let _ = EntityStore::new_with_tags([first, second])
    false
  } catch {
    PolicyError(message) => message == "value comparison budget exceeded"
  }
  assert_true(rejected)
}

///|
test "duplicate inputs still count towards graph and value limits" {
  let uid : EntityId = { kind: "User", id: "alice", }
  let parent : EntityId = { kind: "Group", id: "team", }
  let many_parents = Array::make(65537, parent)
  let graph_entity : TaggedEntity = {
    entity: { uid, attrs: {}, parents: many_parents, },
    tags: {},
  }
  let graph_rejected = try {
    validate_entities([graph_entity, graph_entity])
    false
  } catch {
    PolicyError(message) => message == "entity parent limit exceeded"
  }
  assert_true(graph_rejected)
  let values = Array::make(262144, BoolValue(true))
  let value_entity : TaggedEntity = {
    entity: { uid, attrs: { "values": SetValue(values) }, parents: [], },
    tags: {},
  }
  let values_rejected = try {
    let _ = EntityStore::new_with_tags([value_entity, value_entity])
    false
  } catch {
    PolicyError(message) => message == "entity value limit exceeded"
  }
  assert_true(values_rejected)
}
