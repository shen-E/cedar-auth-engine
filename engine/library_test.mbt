///|
test "authorize through the public library" {
  let policies = @engine.parse_policies(
    "permit(principal, action == Action::\"read\", resource);",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let response = @engine.authorize(policies, request, [])
  assert_true(response.decision == @engine.Allow)
}

///|
test "construct IP values through the public library" {
  let policies = @engine.parse_policies(
    "permit(principal, action, resource) when { context.source.isInRange(ip(\"2001:db8::/32\")) };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "connect", },
    resource: { kind: "Service", id: "example", },
    context: {
      "source": @engine.IpValue(@engine.IpAddress::parse("2001:db8::1")),
    },
  }
  let response = @engine.authorize(policies, request, [])
  assert_true(response.decision == @engine.Allow && response.errors.is_empty())
}

///|
test "inspect policy annotations through the public library" {
  let policies = @engine.parse_policies(
    "@id(\"file-read\") @owner(\"platform\") permit(principal, action, resource);",
  )
  let entries = policies.metadata()
  assert_true(entries.length() == 1)
  assert_true(entries[0].id == "file-read" && entries[0].effect == "permit")
  assert_true(entries[0].annotations.get("owner") == Some("platform"))
  entries[0].annotations["owner"] = "other"
  assert_true(
    policies.metadata()[0].annotations.get("owner") == Some("platform"),
  )
}

///|
test "authorize typed entities with tags through the public library" {
  let policy = @engine.parse_policies(
    "permit(principal, action, resource) when { resource.getTag(\"team\") == \"security\" };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let entities : Array[@engine.TaggedEntity] = [
    {
      entity: { uid: { kind: "File", id: "report", }, attrs: {}, parents: [], },
      tags: { "team": @engine.StringValue("security") },
    },
  ]
  let response = @engine.authorize_with_tags(policy, request, entities)
  assert_true(response.decision == @engine.Allow && response.errors.is_empty())
}

///|
test "public authorization rejects cyclic entity hierarchies" {
  let policy = @engine.parse_policies("permit(principal, action, resource);")
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let entities : Array[@engine.Entity] = [
    {
      uid: { kind: "Group", id: "a", },
      attrs: {},
      parents: [{ kind: "Group", id: "b", }],
    },
    {
      uid: { kind: "Group", id: "b", },
      attrs: {},
      parents: [{ kind: "Group", id: "a", }],
    },
  ]
  let rejected = try {
    let _ = @engine.authorize(policy, request, entities)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let tagged = []
  for entity in entities {
    tagged.push(@engine.TaggedEntity::{ entity, tags: {}, })
  }
  let rejected = try {
    @engine.validate_entities(tagged)
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  @engine.validate_entities([])
}

///|
test "authorize using a nested attribute presence check" {
  let policy = @engine.parse_policies(
    "permit(principal, action, resource) when { context has device.posture.managed && context.device.posture.managed };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {
      "device": @engine.RecordValue({
        "posture": @engine.RecordValue({ "managed": @engine.BoolValue(true) }),
      }),
    },
  }
  let response = @engine.authorize(policy, request, [])
  assert_true(response.decision == @engine.Allow && response.errors.is_empty())
}

///|
test "batch authorization through the public library" {
  let policy = @engine.parse_policies(
    "permit(principal, action, resource) when { context.approved };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: { "approved": @engine.BoolValue(true) },
  }
  let no_approval = {
    ..request,
    context: { "approved": @engine.BoolValue(false) },
  }
  let result = @engine.authorize_batch(policy, [request, no_approval], [])
  assert_true(result.length() == 2)
  assert_true(
    result[0].decision == @engine.Allow && result[1].decision == @engine.Deny,
  )
  let tagged_result = @engine.authorize_batch_with_tags(policy, [request], [])
  assert_true(tagged_result[0].decision == @engine.Allow)
}

///|
test "entity snapshots isolate nested attributes, tags and hierarchy" {
  let policy = @engine.parse_policies(
    "permit(principal, action, resource in Folder::\"shared\") when { resource.data.members.contains(\"alice\") && resource.getTag(\"owner\").team == \"security\" };",
  )
  let request = @engine.Request::{
    principal: { kind: "User", id: "alice", },
    action: { kind: "Action", id: "read", },
    resource: { kind: "File", id: "report", },
    context: {},
  }
  let members : Array[@engine.Value] = [@engine.StringValue("alice")]
  let data : Map[String, @engine.Value] = {
    "members": @engine.SetValue(members),
  }
  let owner : Map[String, @engine.Value] = {
    "team": @engine.StringValue("security"),
  }
  let attrs : Map[String, @engine.Value] = { "data": @engine.RecordValue(data) }
  let tags : Map[String, @engine.Value] = {
    "owner": @engine.RecordValue(owner),
  }
  let parents : Array[@engine.EntityId] = [{ kind: "Folder", id: "shared", }]
  let entities : Array[@engine.TaggedEntity] = [
    { entity: { uid: request.resource, attrs, parents, }, tags, },
  ]
  let store = @engine.EntityStore::new_with_tags(entities)
  let initial = store.authorize(policy, request)
  assert_true(initial.decision == @engine.Allow && initial.errors.is_empty())
  members[0] = @engine.StringValue("bob")
  data["members"] = @engine.SetValue([])
  owner["team"] = @engine.StringValue("other")
  attrs["data"] = @engine.BoolValue(false)
  tags["owner"] = @engine.BoolValue(false)
  parents[0] = { kind: "Folder", id: "other", }
  entities.clear()
  let result = store.authorize(policy, request)
  assert_true(result.decision == @engine.Allow && result.errors.is_empty())
  let denied = { ..request, resource: { kind: "File", id: "unknown", }, }
  let responses = store.authorize_batch(policy, [request, denied, request])
  assert_true(responses.length() == 3)
  assert_true(responses[0].decision == @engine.Allow)
  assert_true(responses[1].decision == @engine.Deny)
  assert_true(responses[2].decision == @engine.Allow)
  let plain = @engine.EntityStore::new([])
  assert_true(plain.authorize(policy, request).decision == @engine.Deny)
}
