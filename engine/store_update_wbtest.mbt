///|
test "entity updates replace full records and retain independent snapshots" {
  let user : EntityId = { kind: "User", id: "alice", }
  let team : EntityId = { kind: "Group", id: "team", }
  let org : EntityId = { kind: "Group", id: "org", }
  let original = EntityStore::new_with_tags_checked([
    { entity: { uid: user, attrs: {}, parents: [], }, tags: {}, },
    group("team", []),
    {
      entity: {
        uid: sample_request().resource,
        attrs: { "active": BoolValue(false) },
        parents: [],
      },
      tags: {},
    },
  ])
  let policy = parse_policies(
    "permit(principal in Group::\"org\", action, resource) when { resource.active && resource.getTag(\"owner\").members.contains(\"alice\") };",
  )
  let members : Array[Value] = [StringValue("alice")]
  let owner : Map[String, Value] = { "members": SetValue(members) }
  let parents = [team]
  let tags : Map[String, Value] = { "owner": RecordValue(owner) }
  let attrs : Map[String, Value] = { "active": BoolValue(true) }
  let updates : Array[TaggedEntity] = [
    { entity: { uid: user, attrs: {}, parents, }, tags: {}, },
    group("team", [org]),
    { entity: { uid: sample_request().resource, attrs, parents: [], }, tags, },
    group("org", []),
  ]
  let updated = original.upsert(updates)
  assert_true(original.authorize(policy, sample_request()).decision == Deny)
  assert_true(
    updated.authorize_checked(policy, sample_request()).is_authorized(),
  )
  parents.clear()
  attrs["active"] = BoolValue(false)
  members.clear()
  owner.clear()
  tags.clear()
  updates.clear()
  assert_true(
    updated.authorize_checked(policy, sample_request()).is_authorized(),
  )
  let comparisons = original.compare_with_entities(updated, policy, policy, [
    sample_request(),
  ])
  assert_true(comparisons[0].enforcement_granted())
}

///|
test "entity removal preserves references but breaks further ancestry" {
  let user : EntityId = { kind: "User", id: "alice", }
  let team : EntityId = { kind: "Group", id: "team", }
  let org : EntityId = { kind: "Group", id: "org", }
  let original = EntityStore::new_with_tags_checked([
    { entity: { uid: user, attrs: {}, parents: [team], }, tags: {}, },
    group("team", [org]),
    group("org", []),
  ])
  let direct = parse_policies(
    "permit(principal in Group::\"team\", action, resource);",
  )
  let inherited = parse_policies(
    "permit(principal in Group::\"org\", action, resource);",
  )
  let removed = original.remove(team)
  assert_true(original.authorize(inherited, sample_request()).decision == Allow)
  assert_true(removed.authorize(inherited, sample_request()).decision == Deny)
  assert_true(removed.authorize(direct, sample_request()).decision == Allow)
  let removed_both = original.remove_batch([team, org])
  assert_true(
    removed_both.authorize(inherited, sample_request()).decision == Deny,
  )
  assert_true(
    removed_both.authorize(direct, sample_request()).decision == Allow,
  )
  assert_true(
    original.remove_batch([]).authorize(inherited, sample_request()).decision ==
    Allow,
  )
  assert_true(
    original.upsert([]).authorize(inherited, sample_request()).decision == Allow,
  )
}

///|
test "replacement clears omitted fields and distinguishes entity ids" {
  let one : EntityId = { kind: "A", id: "BC", }
  let two : EntityId = { kind: "AB", id: "C", }
  let original = EntityStore::new_with_tags_checked([
    {
      entity: { uid: one, attrs: { "active": BoolValue(true) }, parents: [], },
      tags: { "shared": BoolValue(true) },
    },
    {
      entity: { uid: two, attrs: { "active": BoolValue(true) }, parents: [], },
      tags: { "shared": BoolValue(true) },
    },
  ])
  let updated = original.upsert([
    { entity: { uid: one, attrs: {}, parents: [], }, tags: {}, },
  ])
  let policy = parse_policies(
    "permit(principal, action, resource) when { resource has active && resource.hasTag(\"shared\") };",
  )
  let first = { ..sample_request(), resource: one, }
  let second = { ..sample_request(), resource: two, }
  assert_true(original.authorize(policy, first).decision == Allow)
  assert_true(updated.authorize(policy, first).decision == Deny)
  assert_true(updated.authorize(policy, second).decision == Allow)
  let removed = updated.remove(one)
  assert_true(removed.authorize(policy, second).decision == Allow)
}

///|
test "invalid entity updates and removals are atomic" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let original = EntityStore::new_with_tags_checked([
    group("a", [b]),
    group("b", []),
  ])
  let invalid : TaggedEntity = {
    entity: { uid: { kind: "bad-type", id: "x", }, attrs: {}, parents: [], },
    tags: {},
  }
  let cyclic = [group("b", [a])]
  for updates in [[group("a", []), group("a", [])], [invalid], cyclic] {
    let rejected = try {
      let _ = original.upsert(updates)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let invalid_nested = {
    ..group("b", []),
    tags: { "owner": EntityValue({ kind: "Bad::", id: "x", }) },
  }
  let rejected = try {
    let _ = original.upsert([invalid_nested])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  for
    ids in [
      [a, a],
      [a, { kind: "Group", id: "missing", }],
      [{ kind: "bad-type", id: "x", }],
    ] {
    let rejected = try {
      let _ = original.remove_batch(ids)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let policy = parse_policies(
    "permit(principal, action, resource in Group::\"b\");",
  )
  let request = { ..sample_request(), resource: a, }
  assert_true(original.authorize(policy, request).decision == Allow)
}

///|
test "entity update and removal limits apply to the resulting snapshot" {
  let entities = []
  for i in 0..<4096 {
    entities.push(group(i.to_string(), []))
  }
  let original = EntityStore::new_with_tags_checked(entities)
  let _ = original.upsert([group("0", [])])
  let rejected = try {
    let _ = original.upsert([group("new", [])])
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let excessive = Array::make(4097, group("same", []))
  let rejected = try {
    let _ = original.upsert(excessive)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let ids = Array::make(4097, { kind: "Group", id: "0", })
  let rejected = try {
    let _ = original.remove_batch(ids)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let after = original
    .remove({ kind: "Group", id: "0", })
    .upsert([group("new", [])])
  let request = { ..sample_request(), resource: { kind: "Group", id: "new", }, }
  let policy = parse_policies(
    "permit(principal, action, resource in Group::\"new\");",
  )
  assert_true(after.authorize(policy, request).decision == Allow)
}
