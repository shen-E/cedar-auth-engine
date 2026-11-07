///|
test "missing parent report groups distinct direct children" {
  let x : EntityId = { kind: "A", id: "BC", }
  let y : EntityId = { kind: "AB", id: "C", }
  let one : EntityId = { kind: "Group", id: "one", }
  let two : EntityId = { kind: "Group", id: "two", }
  let store = EntityStore::new_with_tags_checked([
    group("one", [x, y, x]),
    group("two", [x, x]),
  ])
  let missing = store.missing_parents()
  assert_true(missing.length() == 2)
  assert_true(missing[0].parent == x && missing[0].children == [one, two])
  assert_true(missing[1].parent == y && missing[1].children == [one])
  let rejected = try {
    store.validate_closed()
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  missing[0].children.clear()
  missing.clear()
  assert_true(store.missing_parents()[0].children == [one, two])
  let complete = store.upsert([
    { entity: { uid: x, attrs: {}, parents: [], }, tags: {}, },
    { entity: { uid: y, attrs: {}, parents: [], }, tags: {}, },
  ])
  complete.validate_closed()
  assert_true(complete.missing_parents().is_empty())
  assert_true(store.missing_parents().length() == 2)
}

///|
test "closed hierarchy validation catches dangling links after removal" {
  let user : EntityId = { kind: "User", id: "alice", }
  let team : EntityId = { kind: "Group", id: "team", }
  let original = EntityStore::new_with_tags_checked([
    { entity: { uid: user, attrs: {}, parents: [team], }, tags: {}, },
    group("team", []),
  ])
  original.validate_closed()
  let removed = original.remove(team)
  assert_true(removed.is_descendant(user, team))
  let missing = removed.missing_parents()
  assert_true(
    missing.length() == 1 &&
    missing[0].parent == team &&
    missing[0].children == [user],
  )
  let rejected = try {
    removed.validate_closed()
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let updated = original.apply_changes(
    [{ entity: { uid: user, attrs: {}, parents: [], }, tags: {}, }],
    [team],
  )
  updated.validate_closed()
  assert_false(updated.is_descendant(user, team))
  assert_true(original.is_descendant(user, team))
}

///|
test "missing parent report handles a full batch of repeated links" {
  let parent : EntityId = { kind: "Group", id: "outside", }
  let parents = Array::make(65536, parent)
  let store = EntityStore::new_with_tags([group("one", parents)])
  let missing = store.missing_parents()
  assert_true(missing.length() == 1 && missing[0].parent == parent)
  assert_true(missing[0].children == [{ kind: "Group", id: "one", }])
  let empty = EntityStore::new([])
  empty.validate_closed()
  assert_true(empty.missing_parents().is_empty())
}
