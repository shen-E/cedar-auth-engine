///|
fn group(id : String, parents : Array[EntityId]) -> TaggedEntity {
  { entity: { uid: { kind: "Group", id, }, attrs: {}, parents, }, tags: {}, }
}

///|
test "reject cycles before evaluating any policy" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let c : EntityId = { kind: "Group", id: "c", }
  let sets = [
    [group("a", [a])],
    [group("a", [b]), group("b", [a])],
    [group("a", [b]), group("b", [c]), group("c", [a])],
    [group("unrelated", []), group("a", [b]), group("b", [a])],
  ]
  let policy = parse_policies("permit(principal, action, resource);")
  for entities in sets {
    let rejected = try {
      let _ = authorize_with_tags(policy, sample_request(), entities)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let plain = [group("a", [b]).entity, group("b", [a]).entity]
  let rejected = try {
    let _ = authorize(policy, sample_request(), plain)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "missing ancestors, repeated links and multiple parents" {
  let a : EntityId = { kind: "Group", id: "a", }
  let b : EntityId = { kind: "Group", id: "b", }
  let c : EntityId = { kind: "Group", id: "c", }
  let root : EntityId = { kind: "Group", id: "root", }
  let missing : EntityId = { kind: "Group", id: "outside", }
  let graph = build_entity_graph([
    group("a", [b, c, b]),
    group("b", [root]),
    group("c", [root, missing]),
    group("root", []),
  ])
  assert_true(is_descendant(graph, a, root))
  assert_true(is_descendant(graph, a, missing))
  assert_true(is_descendant(graph, missing, missing))
  assert_false(is_descendant(graph, root, a))
  assert_false(is_descendant(graph, missing, root))
}

///|
test "entity index preserves type and identifier boundaries" {
  let one : EntityId = { kind: "A", id: "BC", }
  let two : EntityId = { kind: "AB", id: "C", }
  let one_entity : TaggedEntity = {
    entity: { uid: one, attrs: {}, parents: [], },
    tags: {},
  }
  let two_entity : TaggedEntity = {
    entity: { uid: two, attrs: {}, parents: [one], },
    tags: {},
  }
  let graph = build_entity_graph([one_entity, two_entity])
  assert_true(is_descendant(graph, two, one))
  assert_false(is_descendant(graph, one, two))
}

///|
test "all three-entity graphs match independent reachability" {
  let ids : Array[EntityId] = [
    { kind: "Group", id: "a", },
    { kind: "Group", id: "b", },
    { kind: "Group", id: "c", },
  ]
  for mask in 0..<512 {
    let reach = Array::make(9, false)
    let entities = []
    let mut weight = 1
    for i in 0..<3 {
      let parents = []
      for j in 0..<3 {
        if mask / weight % 2 == 1 {
          reach[i * 3 + j] = true
          parents.push(ids[j])
        }
        weight *= 2
      }
      entities.push(group(ids[i].id, parents))
    }
    for k in 0..<3 {
      for i in 0..<3 {
        for j in 0..<3 {
          if reach[i * 3 + k] && reach[k * 3 + j] {
            reach[i * 3 + j] = true
          }
        }
      }
    }
    let cyclic = reach[0] || reach[4] || reach[8]
    let graph = Some(build_entity_graph(entities)) catch { _ => None }
    assert_true((graph is None) == cyclic, msg="mask \{mask}")
    match graph {
      Some(value) => {
        let context = EvaluationContext::new(value)
        for i in 0..<3 {
          for j in 0..<3 {
            let expected = i == j || reach[i * 3 + j]
            assert_true(
              is_descendant(value, ids[i], ids[j]) == expected,
              msg="mask \{mask}",
            )
            assert_true(
              context.is_descendant(ids[i], ids[j]) == expected,
              msg="mask \{mask}",
            )
            assert_true(
              context.is_descendant(ids[i], ids[j]) == expected,
              msg="cached mask \{mask}",
            )
          }
        }
      }
      None => ()
    }
  }
}

///|
test "long entity hierarchies are traversed without recursion" {
  let entities = []
  for i in 0..<4096 {
    let parents = if i < 4095 {
      [{ kind: "Group", id: "\{i + 1}", }]
    } else {
      []
    }
    entities.push(group("\{i}", parents))
  }
  let request = { ..sample_request(), principal: { kind: "Group", id: "0", }, }
  let policy = parse_policies(
    "permit(principal in Group::\"4095\", action, resource);",
  )
  let result = authorize_with_tags(policy, request, entities)
  assert_true(result.decision == Allow && result.errors.is_empty())
}

///|
test "entity graph parent link limit includes repeated references" {
  let missing : EntityId = { kind: "Group", id: "missing", }
  let parents = Array::make(65536, missing)
  let entities = [group("a", parents)]
  let graph = build_entity_graph(entities)
  assert_true(is_descendant(graph, entities[0].entity.uid, missing))
  parents.push(missing)
  let rejected = try {
    let _ = build_entity_graph(entities)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
