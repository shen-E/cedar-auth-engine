///|
test "trailing commas in supported expressions preserve decisions" {
  for
    expression in [
      "[1, 2,] == [2, 1]", "{name: \"alice\", nested: {active: true,},}.nested.active",
      "ip(\"127.0.0.1\",).isIpv4()", "ip(\"10.0.0.1\",).isInRange(ip(\"10.0.0.0/8\",),)",
      "decimal(\"1.0\",).lessThan(decimal(\"2.0\",),)", "duration(\"1s\",).toSeconds() == 1",
      "datetime(\"2026-11-01\",).offset(duration(\"1s\",),) > datetime(\"2026-11-01\",)",
      "[1, 2,].containsAll([2,],)",
    ] {
    let result = evaluate_condition(expression)
    assert_true(result.is_authorized(), msg=expression)
  }
  let policy = parse_policies(
    "permit(principal, action in [Action::\"read\",], resource,) when { resource.hasTag(\"owner\",) && resource.getTag(\"owner\",) == \"alice\" };",
  )
  let entity : TaggedEntity = {
    entity: { uid: sample_request().resource, attrs: {}, parents: [], },
    tags: { "owner": StringValue("alice") },
  }
  assert_true(
    authorize_with_tags(policy, sample_request(), [entity]).is_authorized(),
  )
}

///|
test "trailing commas do not allow empty or extra arguments" {
  for
    source in [
      "permit(principal, action, resource,,);", "@owner(\"team\",) permit(principal, action, resource);",
      "permit(principal, action, resource) when { [,] == [] };", "permit(principal, action, resource) when { {,} == {} };",
      "permit(principal, action, resource) when { [1,,] == [1] };", "permit(principal, action, resource) when { {a: 1,,}.a == 1 };",
      "permit(principal, action, resource) when { ip(,).isIpv4() };", "permit(principal, action, resource) when { [1].contains(1, 2,) };",
      "permit(principal, action, resource) when { [].isEmpty(,) };", "permit(principal, action, resource) when { context[\"x\",] == 1 };",
      "permit(principal, action, resource) when { (1,) == 1 };",
    ] {
    let rejected = try {
      let _ = parse_policies(source)
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=source)
  }
}
