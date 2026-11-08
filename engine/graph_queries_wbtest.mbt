///|
test "query hierarchy with diamonds, repeated links and missing parents" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let c : EntityId = { kind: "Group", id: "c", }
  let root : EntityId = { kind: "Group", id: "root", }
  let missing : EntityId = { kind: "Group", id: "missing", }
  let store = EntityStore::new_with_tags([
    group("a", [b, c, b]),
    group("b", [root]),
    group("c", [root, missing]),
    group("root", []),
  ])
  assert_true(store.ancestors(a) == [b, c, root, missing])
  assert_true(store.descendants(root) == [b, c, a])
  assert_true(store.descendants(missing) == [c, a])
  assert_true(store.ancestors(missing).is_empty())
  assert_true(store.is_descendant(a, missing))
  assert_true(store.is_descendant(missing, missing))
  assert_false(store.is_descendant(missing, a))
  let copied = store.ancestors(a)
  copied.clear()
  assert_true(store.ancestors(a) == [b, c, root, missing])
  let after = store.remove(c)
  assert_true(after.ancestors(a) == [b, c, root])
  assert_true(after.descendants(missing).is_empty())
  assert_true(store.descendants(missing) == [c, a])
}

///|
test "hierarchy lookup keeps type and id boundaries distinct" {
  let one : EntityId = { kind: "A", id: "BC", }
  let two : EntityId = { kind: "AB", id: "C", }
  let parent : EntityId = { kind: "Group", id: "root", }
  let store = EntityStore::new_with_tags([
    { entity: { uid: one, attrs: {}, parents: [parent], }, tags: {}, },
    { entity: { uid: two, attrs: {}, parents: [], }, tags: {}, },
  ])
  assert_true(store.ancestors(one) == [parent])
  assert_true(store.ancestors(two).is_empty())
  assert_true(store.descendants(parent) == [one])
  assert_false(store.is_descendant(two, parent))
  assert_true(store.is_descendant(one, parent))
}

///|
test "hierarchy queries traverse long graphs iteratively" {
  let entities = []
  for i in 0..<4096 {
    let parents = if i < 4095 {
      [{ kind: "Group", id: "\{i + 1}", }]
    } else {
      []
    }
    entities.push(group("\{i}", parents))
  }
  let store = EntityStore::new_with_tags(entities)
  let first : EntityId = { kind: "Group", id: "0", }
  let last : EntityId = { kind: "Group", id: "4095", }
  let ancestors = store.ancestors(first)
  let descendants = store.descendants(last)
  assert_true(ancestors.length() == 4095 && ancestors[4094] == last)
  assert_true(descendants.length() == 4095 && descendants[4094] == first)
  assert_true(store.is_descendant(first, last))
}

///|
test "batch membership preserves single query semantics and snapshot isolation" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let root : EntityId = { kind: "Group", id: "root", }
  let absent : EntityId = { kind: "Group", id: "absent", }
  let store = EntityStore::new_with_tags([
    group("a", [b, root, b]),
    group("b", [root, absent]),
    group("root", []),
  ])
  let pairs = [
    (a, root),
    (root, a),
    (a, absent),
    (absent, absent),
    (absent, a),
    (a, root),
  ]
  let results = store.is_descendant_batch(pairs)
  assert_true(results == [true, false, true, true, false, true])
  for i in 0..<pairs.length() {
    let (child, ancestor) = pairs[i]
    assert_true(results[i] == store.is_descendant(child, ancestor))
  }
  assert_true(store.is_descendant_batch([]).is_empty())
  let updated = store.remove(b)
  assert_false(updated.is_descendant_batch([(a, absent)])[0])
  assert_true(store.is_descendant_batch([(a, absent)])[0])
}

///|
test "batch membership rejects oversized input before evaluation" {
  let id : EntityId = { kind: "User", id: "alice", }
  let store = EntityStore::new_with_tags([])
  let pairs = Array::make(16384, (id, id))
  assert_true(store.is_descendant_batch(pairs).length() == 16384)
  pairs.push((id, id))
  let rejected = try {
    let _ = store.is_descendant_batch(pairs)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "batch membership remains consistent when the ancestry cache is full" {
  let root : EntityId = { kind: "Group", id: "root", }
  let entities = []
  let pairs = []
  for i in 0..<4100 {
    let child : EntityId = { kind: "Group", id: "\{i}", }
    entities.push(group("\{i}", if i % 2 == 0 { [root] } else { [] }))
    pairs.push((child, root))
  }
  let store = EntityStore::new_with_tags(entities)
  let results = store.is_descendant_batch(pairs)
  for i in 0..<pairs.length() {
    let (child, ancestor) = pairs[i]
    assert_true(results[i] == store.is_descendant(child, ancestor))
    assert_true(results[i] == (i % 2 == 0))
  }
}
