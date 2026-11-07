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

///|
test "merge and replace policy sets without changing either snapshot" {
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let base = @engine.parse_policies(
    "@id(\"allow\") @owner(\"v1\") permit(principal, action, resource); @id(\"guard\") forbid(principal, action, resource) when { false };",
  )
  let added = @engine.parse_policies(
    "@id(\"extra\") permit(principal, action == Action::\"write\", resource);",
  )
  let combined = base.merge(added)
  assert_true(combined.metadata().length() == 3)
  assert_true(combined.metadata()[0].id == "allow")
  assert_true(combined.metadata()[2].id == "extra")
  assert_true(base.metadata().length() == 2 && added.metadata().length() == 1)
  let updates = @engine.parse_policies(
    "@id(\"guard\") forbid(principal, action, resource); @id(\"allow\") @owner(\"v2\") permit(principal, action, resource) when { context.ok };",
  )
  let updated = combined.replace(updates)
  assert_true(updated.metadata()[0].id == "allow")
  assert_true(updated.metadata()[1].id == "guard")
  assert_true(updated.metadata()[2].id == "extra")
  assert_true(updated.metadata()[0].annotations.get("owner") == Some("v2"))
  assert_true(combined.metadata()[0].annotations.get("owner") == Some("v1"))
  let old = @engine.authorize(combined, request, [])
  let new = @engine.authorize(updated, request, [])
  assert_true(old.decision == @engine.Allow && old.reasons == ["allow"])
  assert_true(new.decision == @engine.Deny && new.reasons == ["guard"])
  assert_true(new.errors.length() == 1 && new.errors[0].policy_id == "allow")
  assert_true(
    combined.merge(@engine.parse_policies("")).metadata().length() == 3,
  )
  assert_true(
    combined.replace(@engine.parse_policies("")).metadata().length() == 3,
  )
}

///|
test "policy set updates reject duplicate and missing ids atomically" {
  let existing = @engine.parse_policies(
    "@id(\"a\") permit(principal, action, resource); @id(\"b\") forbid(principal, action, resource);",
  )
  let duplicate = @engine.parse_policies(
    "@id(\"new\") permit(principal, action, resource); @id(\"b\") permit(principal, action, resource);",
  )
  let bad_merge = try {
    let _ = existing.merge(duplicate)
    false
  } catch {
    _ => true
  }
  let missing = @engine.parse_policies(
    "@id(\"a\") forbid(principal, action, resource); @id(\"missing\") permit(principal, action, resource);",
  )
  let bad_update = try {
    let _ = existing.replace(missing)
    false
  } catch {
    _ => true
  }
  assert_true(bad_merge && bad_update)
  assert_true(
    existing.metadata()[0].id == "a" &&
    existing.metadata()[0].effect == "permit",
  )
  assert_true(
    existing.metadata()[1].id == "b" &&
    existing.metadata()[1].effect == "forbid",
  )
}

///|
test "combine and replace linked policy sets under the policy limit" {
  let template = @engine.parse_template(
    "permit(principal == ?principal, action, resource);",
  )
  let links : Array[@engine.TemplateLink] = []
  for i in 0..<4096 {
    links.push({
      id: "share-" + i.to_string(),
      bindings: {
        principal: Some({ kind: "User", id: i.to_string(), }),
        resource: None,
      },
    })
  }
  let empty = @engine.parse_policies("")
  let first = empty.link_batch(template, links[0:512].to_owned())
  let second = empty.link_batch(template, links[512:4096].to_owned())
  let all = first.merge(second)
  assert_true(all.metadata().length() == 4096)
  let replacement = @engine.parse_policies(
    "@id(\"share-512\") forbid(principal, action, resource);",
  )
  let updated = all.replace(replacement)
  assert_true(
    updated.metadata()[512].id == "share-512" &&
    updated.metadata()[512].effect == "forbid",
  )
  assert_true(all.metadata()[512].effect == "permit")
  let rejected = try {
    let _ = all.merge(
      @engine.parse_policies(
        "@id(\"new\") permit(principal, action, resource);",
      ),
    )
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "replace a link with a newly bound link" {
  let template = @engine.parse_template(
    "permit(principal == ?principal, action, resource);",
  )
  let empty = @engine.parse_policies("")
  let before = empty.link(template, "share", {
    principal: Some({ kind: "User", id: "alice", }),
    resource: None,
  })
  let replacement = empty.link(template, "share", {
    principal: Some({ kind: "User", id: "bob", }),
    resource: None,
  })
  let after = before.replace(replacement)
  let alice = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let bob = { ..alice, principal: { kind: "User", id: "bob", }, }
  assert_true(@engine.authorize(before, alice, []).reasons == ["share"])
  assert_true(@engine.authorize(before, bob, []).decision == @engine.Deny)
  assert_true(@engine.authorize(after, alice, []).decision == @engine.Deny)
  assert_true(@engine.authorize(after, bob, []).reasons == ["share"])
  assert_true(replacement.metadata()[0].id == "share")
}
