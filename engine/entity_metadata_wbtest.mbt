///|
test "entity metadata is opt-in and does not alter Cedar data" {
  let input = parse_json(
    "[{\"uid\":{\"type\":\"User\",\"id\":\"alice\"},\"attrs\":{\"department\":\"sales\"},\"parents\":[],\"tags\":{\"active\":true},\"metadata\":{\"source\":\"external\"}}]",
  )
  let strict_rejected = try {
    let _ = tagged_entities_from_json(input)
    false
  } catch {
    _ => true
  }
  assert_true(strict_rejected)
  let entities = tagged_entities_from_json_with_metadata(input)
  assert_true(entities.length() == 1)
  assert_true(entities[0].entity.attrs["department"] == StringValue("sales"))
  assert_true(entities[0].tags["active"] == BoolValue(true))
  let policy = parse_policies(
    "permit(principal, action, resource) when { principal.department == \"sales\" && principal.getTag(\"active\") };",
  )
  let result = authorize_with_tags(policy, sample_request(), entities)
  assert_true(result.decision == Allow && result.errors.is_empty())
}

///|
test "metadata mode still validates entity internals" {
  for
    source in [
      "[{\"uid\":{\"type\":\"User\",\"id\":\"a\",\"extra\":1},\"attrs\":{},\"parents\":[],\"metadata\":1}]",
      "[{\"uid\":{\"type\":\"User\",\"id\":\"a\"},\"attrs\":{},\"parents\":null,\"metadata\":1}]",
      "[{\"uid\":{\"type\":\"User\",\"id\":\"a\"},\"attrs\":{},\"parents\":[],\"tags\":null,\"metadata\":1}]",
    ] {
    let rejected = try {
      let _ = tagged_entities_from_json_with_metadata(parse_json(source))
      false
    } catch {
      _ => true
    }
    assert_true(rejected, msg=source)
  }
}
