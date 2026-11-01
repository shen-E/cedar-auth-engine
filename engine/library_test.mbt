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
