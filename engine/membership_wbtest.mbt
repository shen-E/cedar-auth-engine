///|
test "membership cache keeps graph snapshots and entity identities separate" {
  let user : EntityId = { kind: "User", id: "alice", }
  let team : EntityId = { kind: "Group", id: "team", }
  let first = build_entity_graph([
    { entity: { uid: user, attrs: {}, parents: [team], }, tags: {}, },
  ])
  let second = build_entity_graph([
    { entity: { uid: user, attrs: {}, parents: [], }, tags: {}, },
  ])
  let a = EvaluationContext::new(first)
  let b = EvaluationContext::new(second)
  for _ in 0..<3 {
    assert_true(a.is_descendant(user, team))
    assert_false(b.is_descendant(user, team))
    assert_true(a.is_descendant(team, team))
  }
  assert_true(a.entries == 1 && b.entries == 1)
  let x : EntityId = { kind: "A", id: "BC", }
  let y : EntityId = { kind: "AB", id: "C", }
  let parent : EntityId = { kind: "Group", id: "root", }
  let graph = build_entity_graph([
    { entity: { uid: x, attrs: {}, parents: [parent], }, tags: {}, },
    { entity: { uid: y, attrs: {}, parents: [], }, tags: {}, },
  ])
  let indexed = EvaluationContext::new(graph)
  assert_true(indexed.is_descendant(x, parent))
  assert_false(indexed.is_descendant(y, parent))
  assert_true(indexed.is_descendant(x, parent))
  assert_false(indexed.is_descendant(y, parent))
}

///|
test "membership cache bounds entries while preserving uncached results" {
  let context = EvaluationContext::new(build_entity_graph([]))
  let missing : EntityId = { kind: "Group", id: "missing", }
  for i in 0..<4100 {
    let child : EntityId = { kind: "User", id: "user-" + i.to_string(), }
    assert_false(context.is_descendant(child, missing))
  }
  assert_true(context.entries == 4096)
  assert_false(
    context.is_descendant({ kind: "User", id: "user-4099", }, missing),
  )
  assert_false(context.is_descendant({ kind: "User", id: "user-0", }, missing))
  assert_true(context.entries == 4096 && context.key_units <= 262144)
}

///|
test "membership cache bounds identifier storage and bypasses long identifiers" {
  let context = EvaluationContext::new(build_entity_graph([]))
  let text = StringBuilder()
  for _ in 0..<4000 {
    text.write_char('x')
  }
  let prefix = text.to_string()
  let missing : EntityId = { kind: "Group", id: "missing", }
  for i in 0..<100 {
    assert_false(
      context.is_descendant(
        { kind: "User", id: prefix + i.to_string(), },
        missing,
      ),
    )
  }
  assert_true(
    context.entries > 0 && context.entries < 100 && context.key_units <= 262144,
  )
  let original_entries = context.entries
  let very_long = StringBuilder()
  for _ in 0..<65537 {
    very_long.write_char('z')
  }
  let long_id : EntityId = { kind: "User", id: very_long.to_string(), }
  assert_false(context.is_descendant(long_id, missing))
  assert_true(context.is_descendant(long_id, long_id))
  assert_true(context.entries == original_entries)
}

///|
test "cached membership preserves short circuiting and per-policy errors" {
  let user : EntityId = { kind: "User", id: "alice", }
  let team : EntityId = { kind: "Group", id: "team", }
  let entities = [
    { entity: { uid: user, attrs: {}, parents: [team], }, tags: {}, },
  ]
  let graph = build_entity_graph(entities)
  let context = EvaluationContext::new(graph)
  let policies = parse_policies(
    "@id(\"allowed\") permit(principal in Group::\"team\", action, resource); @id(\"guard\") forbid(principal in Group::\"team\", action, resource) when { context.suspended };",
  )
  let request = sample_request()
  let first = authorize_in_context(policies, request, context)
  assert_true(first.decision == Allow && first.reasons == ["allowed"])
  assert_true(
    first.errors.length() == 1 && first.errors[0].policy_id == "guard",
  )
  assert_true(context.entries == 1)
  let safe = { ..request, context: { "suspended": BoolValue(false) }, }
  let next = authorize_in_context(policies, safe, context)
  assert_true(next.decision == Allow && next.errors.is_empty())
  assert_true(context.entries == 1)
  let bob = { ..request, principal: { kind: "User", id: "bob", }, }
  let denied = authorize_in_context(policies, bob, context)
  assert_true(denied.decision == Deny && denied.errors.is_empty())
  assert_true(context.entries == 2)
  let bad_set = parse_policies(
    "@id(\"bad-set\") permit(principal, action, resource) when { principal in [Group::\"team\", 1] };",
  )
  let invalid = authorize_in_context(bad_set, request, context)
  assert_true(invalid.decision == Deny && invalid.errors.length() == 1)
  assert_true(invalid.errors[0].policy_id == "bad-set")
}

///|
test "cached batch matches individual calls across tags and policies" {
  let alice : EntityId = { kind: "User", id: "alice", }
  let team : EntityId = { kind: "Group", id: "team", }
  let file : EntityId = { kind: "File", id: "report", }
  let folder : EntityId = { kind: "Folder", id: "shared", }
  let entities : Array[TaggedEntity] = [
    { entity: { uid: alice, attrs: {}, parents: [team], }, tags: {}, },
    {
      entity: { uid: file, attrs: {}, parents: [folder], },
      tags: { "sensitive": BoolValue(true) },
    },
  ]
  let policies = parse_policies(
    "@id(\"read\") permit(principal in Group::\"team\", action, resource in Folder::\"shared\"); @id(\"guard\") forbid(principal in Group::\"team\", action, resource in Folder::\"shared\") when { resource.getTag(\"sensitive\") && context.restricted };",
  )
  let first = sample_request()
  let safe = { ..first, context: { "restricted": BoolValue(false) }, }
  let blocked = { ..first, context: { "restricted": BoolValue(true) }, }
  let bob = { ..first, principal: { kind: "User", id: "bob", }, }
  let requests = [first, safe, blocked, first, bob, safe, blocked]
  let batch = authorize_batch_with_tags(policies, requests, entities)
  let store = EntityStore::new_with_tags(entities)
  let stored = store.authorize_batch(policies, requests)
  let compared = store.compare(policies, policies, requests)
  for i in 0..<requests.length() {
    let single = authorize_with_tags(policies, requests[i], entities)
    let expected = response_to_json(single).stringify()
    assert_true(response_to_json(batch[i]).stringify() == expected)
    assert_true(response_to_json(stored[i]).stringify() == expected)
    assert_true(response_to_json(compared[i].before).stringify() == expected)
    assert_false(compared[i].changed())
  }
}
