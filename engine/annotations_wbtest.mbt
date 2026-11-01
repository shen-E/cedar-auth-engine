///|
test "policy annotations preserve metadata and assign stable IDs" {
  let source = "@owner(\"security\") @note(\"line\\nnext\") @shadow_mode @if @id(\"network-access\") permit(principal, action, resource); @owner(\"ops\") forbid(principal, action, resource) when { false };"
  let policies = parse_policies(source)
  let info = policies.metadata()
  assert_true(info.length() == 2)
  assert_true(info[0].id == "network-access" && info[0].effect == "permit")
  assert_true(info[0].annotations.get("owner") == Some("security"))
  assert_true(info[0].annotations.get("note") == Some("line\nnext"))
  assert_true(info[0].annotations.get("shadow_mode") == Some(""))
  assert_true(info[0].annotations.get("if") == Some(""))
  assert_true(info[1].id == "policy1" && info[1].effect == "forbid")
  assert_true(
    authorize(policies, sample_request(), []).reasons == ["network-access"],
  )
  info[0].annotations["owner"] = "changed"
  assert_true(
    policies.metadata()[0].annotations.get("owner") == Some("security"),
  )
  let empty_id = parse_policies("@id permit(principal, action, resource);")
  assert_true(empty_id.metadata()[0].id == "")
}

///|
test "malformed annotations and duplicate IDs are rejected" {
  for
    source in [
      "@owner(\"a\") @owner(\"b\") permit(principal, action, resource);", "@id(\"same\") permit(principal, action, resource); @id(\"same\") forbid(principal, action, resource);",
      "@id(\"policy1\") permit(principal, action, resource); permit(principal, action, resource);",
      "@name() permit(principal, action, resource);", "@name(1) permit(principal, action, resource);",
      "@name(\"value\", \"other\") permit(principal, action, resource);", "@name(\"value\")",
      "@123 permit(principal, action, resource);",
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
