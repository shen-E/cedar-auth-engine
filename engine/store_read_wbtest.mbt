///|
test "look up and list entity snapshots" {
  let first : EntityId = { kind: "A", id: "BC", }
  let second : EntityId = { kind: "AB", id: "C", }
  let first_entity : TaggedEntity = {
    entity: { uid: first, attrs: {}, parents: [], },
    tags: {},
  }
  let second_entity : TaggedEntity = {
    entity: { uid: second, attrs: {}, parents: [], },
    tags: {},
  }
  let empty = EntityStore::new([])
  assert_true(empty.length() == 0 && empty.entities().is_empty())
  assert_true(empty.get(first) is None)
  let store = EntityStore::new_with_tags([first_entity, second_entity])
  assert_true(store.length() == 2)
  assert_true(store.get(first).unwrap().entity.uid == first)
  assert_true(store.get(second).unwrap().entity.uid == second)
  assert_true(store.get({ kind: "A", id: "missing", }) is None)
  let list = store.entities()
  assert_true(list.length() == 2)
  assert_true(list[0].entity.uid == first && list[1].entity.uid == second)
  list.clear()
  assert_true(store.length() == 2)
  let updated = store.remove(first).upsert([first_entity])
  let reordered = updated.entities()
  assert_true(
    reordered[0].entity.uid == second && reordered[1].entity.uid == first,
  )
  assert_true(store.entities()[0].entity.uid == first)
}

///|
fn clear_nested_value(value : Value) -> Bool {
  match value {
    RecordValue(fields) =>
      match fields.get("members") {
        Some(SetValue(members)) => {
          members.clear()
          true
        }
        _ => false
      }
    _ => false
  }
}

///|
test "lookup and list copies do not expose nested snapshot state" {
  let resource = sample_request().resource
  let parent : EntityId = { kind: "Folder", id: "shared", }
  let data : Map[String, Value] = {
    "members": SetValue([StringValue("alice")]),
  }
  let store = EntityStore::new_with_tags([
    {
      entity: {
        uid: resource,
        attrs: { "data": RecordValue(data) },
        parents: [parent],
      },
      tags: { "owner": RecordValue(data) },
    },
  ])
  let policy = parse_policies(
    "permit(principal, action, resource in Folder::\"shared\") when { resource.data.members.contains(\"alice\") && resource.getTag(\"owner\").members.contains(\"alice\") };",
  )
  let first = store.get(resource).unwrap()
  let second = store.get(resource).unwrap()
  let all = store.entities()
  assert_true(clear_nested_value(first.entity.attrs.get("data").unwrap()))
  assert_true(clear_nested_value(first.tags.get("owner").unwrap()))
  first.entity.parents.clear()
  second.entity.attrs.clear()
  second.tags.clear()
  assert_true(clear_nested_value(all[0].entity.attrs.get("data").unwrap()))
  assert_true(clear_nested_value(all[0].tags.get("owner").unwrap()))
  all[0].entity.parents.clear()
  assert_true(store.authorize(policy, sample_request()).is_authorized())
  let intact = store.get(resource).unwrap()
  assert_true(intact.entity.parents == [parent])
  let rebuilt = EntityStore::new_with_tags_checked(store.entities())
  assert_true(rebuilt.authorize(policy, sample_request()).is_authorized())
}

///|
test "reading respects the full supported snapshot value limits" {
  let resource = sample_request().resource
  let mut nested : Value = BoolValue(true)
  for _ in 0..<64 {
    nested = SetValue([nested])
  }
  let store = EntityStore::new_with_tags([
    {
      entity: {
        uid: resource,
        attrs: {
          "nested": nested,
          "values": SetValue(Array::make(131006, BoolValue(true))),
        },
        parents: [],
      },
      tags: {},
    },
  ])
  let copied = store.get(resource).unwrap()
  assert_true(copied.entity.attrs.get("nested").unwrap() == nested)
  match copied.entity.attrs.get("values") {
    Some(SetValue(values)) => values.clear()
    _ => assert_true(false)
  }
  let list = store.entities()
  assert_true(list[0].entity.attrs.get("nested").unwrap() == nested)
  match list[0].entity.attrs.get("values") {
    Some(SetValue(values)) => assert_true(values.length() == 131006)
    _ => assert_true(false)
  }
  assert_true(store.length() == 1)
}
