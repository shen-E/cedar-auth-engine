///|
test "link templates and keep original policy sets unchanged" {
  let template = parse_template(
    "@owner(\"sharing\") permit(principal == ?principal, action in [Action::\"read\", Action::\"comment\"], resource == ?resource) when { context.authenticated };",
  )
  assert_true(template.slots() == ["principal", "resource"])
  let original = parse_policies(
    "@id(\"base\") forbid(principal, action == Action::\"delete\", resource);",
  )
  let bindings : TemplateBindings = {
    principal: Some({ kind: "User", id: "alice", }),
    resource: Some({ kind: "File", id: "report", }),
  }
  let linked = original.link(template, "share-a", bindings)
  assert_true(
    original.metadata().length() == 1 && linked.metadata().length() == 2,
  )
  assert_true(linked.metadata()[1].id == "share-a")
  assert_true(linked.metadata()[1].annotations.get("owner") == Some("sharing"))
  let alice = sample_request()
  assert_true(authorize(original, alice, []).decision == Deny)
  let allow = authorize(linked, alice, [])
  assert_true(
    allow.decision == Allow &&
    allow.reasons == ["share-a"] &&
    allow.errors.is_empty(),
  )
  let bob = { ..alice, principal: { kind: "User", id: "bob", }, }
  assert_true(authorize(linked, bob, []).decision == Deny)
  let both = linked.link(template, "share-b", {
    ..bindings,
    principal: Some(bob.principal),
  })
  assert_true(authorize(both, bob, []).reasons == ["share-b"])
  let missing = { ..alice, context: {}, }
  let errored = authorize(both, missing, [])
  assert_true(
    errored.decision == Deny &&
    errored.errors.length() == 1 &&
    errored.errors[0].policy_id == "share-a",
  )
  let blocked = { ..alice, action: { kind: "Action", id: "delete", }, }
  let denied = authorize(both, blocked, [])
  assert_true(denied.decision == Deny && denied.reasons == ["base"])
}

///|
test "template slots support hierarchy and type scopes" {
  let template = parse_template(
    "permit(principal is User in ?principal, action, resource is File in ?resource);",
  )
  let linked = parse_policies("").link(template, "folder-share", {
    principal: Some({ kind: "Group", id: "team", }),
    resource: Some({ kind: "Folder", id: "shared", }),
  })
  let entities = [
    {
      uid: { kind: "User", id: "alice", },
      attrs: {},
      parents: [{ kind: "Group", id: "team", }],
    },
    {
      uid: { kind: "File", id: "report", },
      attrs: {},
      parents: [{ kind: "Folder", id: "shared", }],
    },
  ]
  assert_true(
    authorize(linked, sample_request(), entities).reasons == ["folder-share"],
  )
  let different = {
    ..sample_request(),
    principal: { kind: "Group", id: "team", },
  }
  assert_true(authorize(linked, different, entities).decision == Deny)
  let only_resource = parse_template(
    "permit(principal, action, resource == ?resource);",
  )
  assert_true(only_resource.slots() == ["resource"])
  let single = parse_policies("").link(only_resource, "one", {
    principal: None,
    resource: Some(sample_request().resource),
  })
  assert_true(authorize(single, sample_request(), []).decision == Allow)
}

///|
test "template parser and linker reject invalid bindings and slots" {
  for
    source in [
      "", "permit(principal, action, resource);", "permit(principal == ?resource, action, resource);",
      "permit(principal, action == ?principal, resource);", "permit(principal, action, resource == ?principal);",
      "permit(principal, action, resource) when { principal == ?principal };", "permit(principal == ?principal, action, resource); permit(principal, action, resource);",
    ] {
    let rejected = try {
      let _ = parse_template(source)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=source)
  }
  let static_rejected = try {
    let _ = parse_policies("permit(principal == ?principal, action, resource);")
    false
  } catch {
    _ => true
  }
  assert_true(static_rejected)
  let template = parse_template(
    "permit(principal == ?principal, action, resource);",
  )
  let base = parse_policies(
    "@id(\"taken\") forbid(principal, action, resource);",
  )
  let principal = Some({ kind: "User", id: "alice", })
  for
    bindings in [
      { principal: None, resource: None, },
      { principal, resource: Some({ kind: "File", id: "report", }), },
    ] {
    let rejected = try {
      let _ = base.link(template, "new", bindings)
      false
    } catch {
      _ => true
    }
    assert_true(rejected)
  }
  let rejected = try {
    let _ = base.link(template, "taken", { principal, resource: None, })
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  assert_true(base.metadata().length() == 1)
}

///|
test "linked policies obey the same policy count limit" {
  let template = parse_template(
    "permit(principal == ?principal, action, resource);",
  )
  let bindings : TemplateBindings = {
    principal: Some({ kind: "User", id: "alice", }),
    resource: None,
  }
  let mut policies = parse_policies("")
  for index in 0..<1024 {
    policies = policies.link(template, "share-" + index.to_string(), bindings)
  }
  assert_true(policies.metadata().length() == 1024)
  let rejected = try {
    let _ = policies.link(template, "one-more", bindings)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
