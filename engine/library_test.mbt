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
