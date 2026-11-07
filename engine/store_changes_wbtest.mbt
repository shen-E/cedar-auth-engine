///|
test "apply entity changes to one independent snapshot" {
  let user : EntityId = { kind: "User", id: "alice", }
  let old_team : EntityId = { kind: "Group", id: "old", }
  let new_team : EntityId = { kind: "Group", id: "new", }
  let resource = sample_request().resource
  let original = EntityStore::new_with_tags_checked([
    { entity: { uid: user, attrs: {}, parents: [old_team], }, tags: {}, },
    group("old", []),
    {
      entity: { uid: resource, attrs: {}, parents: [], },
      tags: { "team": StringValue("old") },
    },
  ])
  let parents = [new_team]
  let tags : Map[String, Value] = { "team": StringValue("new") }
  let updates : Array[TaggedEntity] = [
    { entity: { uid: user, attrs: {}, parents, }, tags: {}, },
    { entity: { uid: resource, attrs: {}, parents: [], }, tags, },
    group("new", []),
  ]
  let updated = original.apply_changes(updates, [old_team])
  let policy = parse_policies(
    "permit(principal in Group::\"new\", action, resource) when { resource.getTag(\"team\") == \"new\" };",
  )
  assert_false(original.authorize(policy, sample_request()).is_authorized())
  assert_true(updated.authorize(policy, sample_request()).is_authorized())
  assert_true(updated.length() == 3 && updated.get(old_team) is None)
  assert_true(original.get(old_team) is Some(_))
  parents.clear()
  tags.clear()
  updates.clear()
  assert_true(updated.authorize(policy, sample_request()).is_authorized())
  assert_true(
    original.compare_with_entities(updated, policy, policy, [sample_request()])[0].enforcement_granted(),
  )
}

///|
test "entity change batches reject conflicts and cycles atomically" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let missing : EntityId = { kind: "Group", id: "missing", }
  let store = EntityStore::new_with_tags_checked([
    group("a", [b]),
    group("b", []),
  ])
  let cases : Array[(Array[TaggedEntity], Array[EntityId])] = [
    ([group("a", [])], [a]),
    ([group("a", []), group("a", [])], []),
    ([], [a, a]),
    ([group("new", [])], [missing]),
    ([group("b", [a])], []),
    ([group("bad", [{ kind: "Bad::", id: "x", }])], []),
  ]
  for (updates, removals) in cases {
    let rejected = try {
      let _ = store.apply_changes(updates, removals)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
    assert_true(
      store.length() == 2 && store.get(a) is Some(_) && store.get(b) is Some(_),
    )
  }
  let request = { ..sample_request(), resource: a, }
  let policy = parse_policies(
    "permit(principal, action, resource in Group::\"b\");",
  )
  assert_true(store.authorize(policy, request).is_authorized())
}

///|
test "entity change batches validate the final graph" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let store = EntityStore::new_with_tags_checked([
    group("a", [b]),
    group("b", []),
  ])
  let updates = [group("b", [a])]
  let rejected = try {
    let _ = store.upsert(updates)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let next = store.apply_changes(updates, [a])
  assert_true(next.length() == 1 && next.get(a) is None)
  let request = { ..sample_request(), resource: b, }
  let policy = parse_policies(
    "permit(principal, action, resource in Group::\"a\");",
  )
  assert_true(next.authorize(policy, request).is_authorized())
  assert_false(store.authorize(policy, request).is_authorized())
}

///|
test "entity change batches enforce limits on the final snapshot" {
  let entities = []
  for i in 0..<4096 {
    entities.push(group(i.to_string(), []))
  }
  let store = EntityStore::new_with_tags_checked(entities)
  let removed : EntityId = { kind: "Group", id: "0", }
  let next = store.apply_changes([group("new", [])], [removed])
  assert_true(next.length() == 4096 && next.get(removed) is None)
  assert_true(next.get({ kind: "Group", id: "new", }) is Some(_))
  let rejected = try {
    let _ = store.apply_changes([group("new", [])], [])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let excessive_updates = Array::make(4097, group("x", []))
  let excessive_removals = Array::make(4097, removed)
  let rejected = try {
    let _ = store.apply_changes(excessive_updates, [])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let rejected = try {
    let _ = store.apply_changes([], excessive_removals)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  assert_true(store.length() == 4096 && store.get(removed) is Some(_))
}
