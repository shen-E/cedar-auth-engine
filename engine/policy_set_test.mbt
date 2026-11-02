///|
test "remove linked policies while preserving snapshots and authorization" {
  let template = @engine.parse_template(
    "@owner(\"sharing\") permit(principal == ?principal, action == Action::\"read\", resource == ?resource);",
  )
  let alice = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let bob = { ..alice, principal: { kind: "User", id: "bob", }, }
  let base = @engine.parse_policies(
    "@id(\"blocked\") forbid(principal, action == Action::\"delete\", resource);",
  )
  let links : Array[@engine.TemplateLink] = [
    {
      id: "alice",
      bindings: {
        principal: Some(alice.principal),
        resource: Some(alice.resource),
      },
    },
    {
      id: "bob",
      bindings: {
        principal: Some(bob.principal),
        resource: Some(bob.resource),
      },
    },
  ]
  let original = base.link_batch(template, links)
  let updated = original.remove("alice")
  assert_true(@engine.authorize(original, alice, []).reasons == ["alice"])
  assert_true(@engine.authorize(updated, alice, []).decision == @engine.Deny)
  assert_true(@engine.authorize(updated, bob, []).reasons == ["bob"])
  let store = @engine.EntityStore::new([])
  assert_true(store.authorize(original, alice).reasons == ["alice"])
  assert_true(store.authorize(updated, alice).decision == @engine.Deny)
  assert_true(store.authorize(updated, bob).reasons == ["bob"])
  assert_true(updated.metadata().length() == 2)
  assert_true(
    updated.metadata()[0].id == "blocked" && updated.metadata()[1].id == "bob",
  )
  assert_true(updated.metadata()[1].annotations.get("owner") == Some("sharing"))
  let recreated = updated.link(template, "alice", links[0].bindings)
  assert_true(@engine.authorize(recreated, alice, []).reasons == ["alice"])
  assert_true(@engine.authorize(updated, alice, []).decision == @engine.Deny)
  let empty = original.remove_batch(["bob", "blocked", "alice"])
  assert_true(empty.metadata().is_empty())
  assert_true(@engine.authorize(empty, bob, []).decision == @engine.Deny)
  assert_true(original.remove_batch([]).metadata().length() == 3)
}

///|
test "removing a forbid can expose an existing permit" {
  let policies = @engine.parse_policies(
    "@id(\"allow\") permit(principal, action, resource); @id(\"deny\") forbid(principal, action, resource);",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  assert_true(@engine.authorize(policies, request, []).reasons == ["deny"])
  assert_true(
    @engine.authorize(policies.remove("deny"), request, []).reasons == ["allow"],
  )
  assert_true(
    @engine.authorize(policies.remove("allow"), request, []).reasons == ["deny"],
  )
}

///|
test "invalid removals are atomic and reject duplicates and missing ids" {
  let policies = @engine.parse_policies(
    "@id(\"\") permit(principal, action, resource); @id(\"授权\") forbid(principal, action, resource);",
  )
  for ids in [["", "missing"], ["授权", "授权"], ["missing"], ["", ""]] {
    let rejected = try {
      let _ = policies.remove_batch(ids)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
    assert_true(policies.metadata().length() == 2)
  }
  let too_many = Array::make(1025, "")
  let rejected = try {
    let _ = policies.remove_batch(too_many)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  assert_true(policies.remove("").metadata()[0].id == "授权")
  assert_true(policies.remove("授权").metadata()[0].id == "")
}

///|
test "remove the maximum number of linked policies in one batch" {
  let template = @engine.parse_template(
    "permit(principal == ?principal, action, resource);",
  )
  let links : Array[@engine.TemplateLink] = []
  let ids : Array[String] = []
  for i in 0..<1024 {
    let id = "share-" + i.to_string()
    ids.push(id)
    links.push({
      id,
      bindings: {
        principal: Some({ kind: "User", id: i.to_string(), }),
        resource: None,
      },
    })
  }
  let original = @engine.parse_policies("").link_batch(template, links)
  let removed = original.remove_batch(ids)
  assert_true(removed.metadata().is_empty())
  assert_true(original.metadata().length() == 1024)
}
