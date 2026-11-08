///|
priv suberror CliError {
  CliError(String)
}

///|
impl Show for CliError with fn output(self, logger) {
  let CliError(message) = self
  logger.write_string(message)
}

///|
#borrow(path, out)
extern "C" fn read_file(path : Bytes, out : Bytes) -> Int32 = "cedar_read"

///|
#borrow(text)
extern "C" fn stderr(text : Bytes) = "cedar_stderr"

///|
extern "C" fn exit_process(code : Int32) = "cedar_exit"

///|
fn read_text(path : String) -> String raise CliError {
  let small = Bytes::make(1048577, 0)
  let first_length = read_file(@utf8.encode(path), small)
  if first_length < 0 {
    raise CliError("cannot read: " + path)
  }
  let (buffer, length) = if first_length > 1048576 {
    let large = Bytes::make(8388609, 0)
    (large, read_file(@utf8.encode(path), large))
  } else {
    (small, first_length)
  }
  if length < 0 {
    raise CliError("cannot read: " + path)
  }
  if length > 8388608 {
    raise CliError("input exceeds 8 MiB: " + path)
  }
  @utf8.decode(buffer[0:length]) catch {
    _ => raise CliError("invalid UTF-8: " + path)
  }
}

///|
fn load_json(path : String) -> Json raise {
  @engine.parse_json(read_text(path))
}

///|
fn optional_policy_ids(
  fields : Map[String, Json],
  name : String,
) -> Array[String]? raise CliError {
  match fields.get(name) {
    None => None
    Some(Array(items)) => {
      let result : Array[String] = []
      let seen : Map[String, Bool] = Map([])
      for item in items {
        match item {
          String(id) => {
            if seen.contains(id) {
              raise CliError("duplicate policy ID in '\{name}'")
            }
            seen[id] = true
            result.push(id)
          }
          _ => raise CliError("'\{name}' must be an array of policy ID strings")
        }
      }
      Some(result)
    }
    _ => raise CliError("'\{name}' must be an array of policy ID strings")
  }
}

///|
fn same_policy_ids(expected : Array[String], actual : Array[String]) -> Bool {
  expected.length() == actual.length() &&
  expected.all(fn(id) { actual.contains(id) })
}

///|
fn optional_link_uid(
  fields : Map[String, Json],
  name : String,
) -> @engine.EntityId? raise CliError {
  match fields.get(name) {
    None => None
    Some(Object(uid)) => {
      if uid.length() != 2 {
        raise CliError("link entity must contain only type and id")
      }
      match (uid.get("type"), uid.get("id")) {
        (Some(String(kind)), Some(String(id))) => Some({ kind, id, })
        _ => raise CliError("link entity requires string type and id")
      }
    }
    _ => raise CliError("link slot must be an entity object")
  }
}

///|
fn apply_template(
  policies : @engine.PolicySet,
  template_path : String,
  links_path : String,
) -> @engine.PolicySet raise {
  let template = @engine.parse_template(read_text(template_path))
  let links = match load_json(links_path) {
    Array(items) => items
    _ => raise CliError("template links must be an array")
  }
  if links.length() > 4096 {
    raise CliError("template link limit exceeded")
  }
  let pending : Array[@engine.TemplateLink] = []
  for item in links {
    let fields = match item {
      Object(fields) => fields
      _ => raise CliError("template link must be an object")
    }
    for key, _ in fields {
      if key != "id" && key != "principal" && key != "resource" {
        raise CliError("unknown template link field")
      }
    }
    let id = match fields.get("id") {
      Some(String(id)) => id
      _ => raise CliError("template link requires a string id")
    }
    pending.push({
      id,
      bindings: {
        principal: optional_link_uid(fields, "principal"),
        resource: optional_link_uid(fields, "resource"),
      },
    })
  }
  policies.link_batch(template, pending)
}

///|
priv struct TestCase {
  request : @engine.Request
  expected : String
  expected_reasons : Array[String]?
  expected_errors : Array[String]
}

///|
fn parse_test_case(item : Json) -> TestCase raise {
  let fields = match item {
    Object(fields) => fields
    _ => raise CliError("test case must be an object")
  }
  for key, _ in fields {
    if key != "request" &&
      key != "decision" &&
      key != "reasons" &&
      key != "errors" {
      raise CliError("unknown test case field '\{key}'")
    }
  }
  let request = match fields.get("request") {
    Some(request) => @engine.request_from_json(request)
    None => raise CliError("test case missing request")
  }
  let expected = match fields.get("decision") {
    Some(String(value)) => value
    _ => raise CliError("test case missing decision")
  }
  if expected != "Allow" && expected != "Deny" {
    raise CliError("expected decision must be Allow or Deny")
  }
  {
    request,
    expected,
    expected_reasons: optional_policy_ids(fields, "reasons"),
    expected_errors: optional_policy_ids(fields, "errors").unwrap_or([]),
  }
}

///|
fn enforcement_json(response : @engine.Response) -> Json {
  {
    "allowed": response.is_authorized(),
    "response": @engine.response_to_json(response),
  }
}

///|
fn decision_label(response : @engine.Response) -> String {
  match response.decision {
    Allow => "Allow"
    Deny => "Deny"
  }
}

///|
fn run(args : Array[String]) -> Int32 raise {
  if args.length() < 2 || args[1] == "--help" {
    println(
      "cedar-auth-engine check POLICY [--format json]\ncedar-auth-engine check-entities ENTITIES [--require-closed] [--format json]\ncedar-auth-engine check-membership ENTITIES QUERIES [--format json]\ncedar-auth-engine compare BEFORE AFTER ENTITIES REQUESTS [--after-entities FILE] [--summary] [--format json] [--fail-on-change] [--fail-on-decision-grant] [--fail-on-decision-revoke] [--fail-on-enforcement-grant] [--fail-on-enforcement-revoke] [--fail-on-after-error]\ncedar-auth-engine authorize POLICY ENTITIES REQUEST [--strict] [--format json]\ncedar-auth-engine batch POLICY ENTITIES REQUESTS [--strict] [--format json]\ncedar-auth-engine enforce POLICY ENTITIES REQUEST [--format json]\ncedar-auth-engine enforce-batch POLICY ENTITIES REQUESTS [--format json]\ncedar-auth-engine test POLICY ENTITIES CASES [--format json]\nOptions for authorize, batch, enforce, enforce-batch and test: [--add-policies FILE]... [--template TEMPLATE --links LINKS]... [--replace-policies FILE]... [--remove-policy ID]...\nOptions for compare: [--before-add-policies FILE]... [--before-template TEMPLATE --before-links LINKS]... [--before-replace-policies FILE]... [--before-remove-policy ID]... and corresponding --after-* options",
    )
    return 0
  }
  if args[1] == "--version" {
    println("cedar-auth-engine 0.1.0")
    return 0
  }
  let command = args[1]
  if command == "compare" {
    return run_compare(args)
  }
  if command == "check-entities" {
    return run_check_entities(args)
  }
  if command == "check-membership" {
    return run_check_membership(args)
  }
  let required_count = if command == "check" {
    3
  } else if command == "authorize" ||
    command == "batch" ||
    command == "enforce" ||
    command == "enforce-batch" ||
    command == "test" {
    5
  } else {
    raise CliError("unknown command")
  }
  if args.length() < required_count {
    raise CliError("invalid arguments; use --help")
  }
  let mut json = false
  let mut strict = false
  let inputs = policy_inputs()
  let mut i = required_count
  while i < args.length() {
    if args[i] == "--format" &&
      !json &&
      i + 1 < args.length() &&
      args[i + 1] == "json" {
      json = true
      i += 2
    } else if args[i] == "--strict" &&
      (command == "authorize" || command == "batch") &&
      !strict {
      strict = true
      i += 1
    } else if args[i] == "--template" &&
      command != "check" &&
      i + 1 < args.length() {
      inputs.templates.push(args[i + 1])
      i += 2
    } else if args[i] == "--links" &&
      command != "check" &&
      i + 1 < args.length() {
      inputs.links.push(args[i + 1])
      i += 2
    } else if args[i] == "--add-policies" &&
      command != "check" &&
      i + 1 < args.length() {
      inputs.additions.push(args[i + 1])
      i += 2
    } else if args[i] == "--replace-policies" &&
      command != "check" &&
      i + 1 < args.length() {
      inputs.replacements.push(args[i + 1])
      i += 2
    } else if args[i] == "--remove-policy" &&
      command != "check" &&
      i + 1 < args.length() {
      inputs.removals.push(args[i + 1])
      i += 2
    } else {
      raise CliError("invalid arguments; use --help")
    }
  }
  let policies = inputs.load(args[2])
  if command == "check" {
    if json {
      let entries : Array[Json] = []
      for info in policies.metadata() {
        let annotations : Map[String, Json] = Map([])
        for key, value in info.annotations {
          annotations[key] = Json::string(value)
        }
        let item : Json = {
          "id": info.id,
          "effect": info.effect,
          "annotations": Json::object(annotations),
        }
        entries.push(item)
      }
      let output : Json = { "valid": true, "policies": Json::array(entries) }
      println(output.stringify())
    } else {
      println("Policy syntax accepted")
    }
    return 0
  }
  let entities = @engine.tagged_entities_from_json(load_json(args[3]))
  let input = load_json(args[4])
  if command == "authorize" || command == "enforce" {
    let response = @engine.authorize_with_tags(
      policies,
      @engine.request_from_json(input),
      entities,
    )
    if json {
      if command == "enforce" {
        println(enforcement_json(response).stringify())
      } else {
        println(@engine.response_to_json(response).stringify())
      }
    } else {
      let decision = decision_label(response)
      let reasons = response.reasons.join(", ")
      if command == "enforce" {
        let enforced = if response.is_authorized() { "Allow" } else { "Deny" }
        println("\{enforced} (Cedar \{decision}): \{reasons}")
      } else {
        println("\{decision}: \{reasons}")
      }
      for error in response.errors {
        println("\{error.policy_id}: \{error.message}")
      }
    }
    return if command == "enforce" {
      if response.is_authorized() {
        0
      } else {
        1
      }
    } else if strict && !response.errors.is_empty() {
      1
    } else {
      0
    }
  }
  if command == "batch" || command == "enforce-batch" {
    let items = match input {
      Array(items) => items
      _ => raise CliError("batch input must be an array")
    }
    if items.length() > 32768 {
      raise CliError("request batch limit exceeded")
    }
    let requests = []
    for item in items {
      requests.push(@engine.request_from_json(item))
    }
    let responses = @engine.authorize_batch_with_tags(
      policies, requests, entities,
    )
    let output : Array[Json] = []
    let mut has_errors = false
    let mut has_denied = false
    for i in 0..<responses.length() {
      let response = responses[i]
      if !response.errors.is_empty() {
        has_errors = true
      }
      if !response.is_authorized() {
        has_denied = true
      }
      if json {
        output.push(
          if command == "enforce-batch" {
            enforcement_json(response)
          } else {
            @engine.response_to_json(response)
          },
        )
      } else {
        let decision = decision_label(response)
        let reasons = response.reasons.join(", ")
        if command == "enforce-batch" {
          let enforced = if response.is_authorized() { "Allow" } else { "Deny" }
          println("request \{i}: \{enforced} (Cedar \{decision}): \{reasons}")
        } else {
          println("request \{i}: \{decision}: \{reasons}")
        }
        for error in response.errors {
          println("  \{error.policy_id}: \{error.message}")
        }
      }
    }
    if json {
      println(Json::array(output).stringify())
    }
    return if command == "enforce-batch" {
      if has_denied {
        1
      } else {
        0
      }
    } else if strict && has_errors {
      1
    } else {
      0
    }
  }
  let cases = match input {
    Array(items) => items
    _ => raise CliError("test input must be an array")
  }
  let parsed_cases = []
  for item in cases {
    parsed_cases.push(parse_test_case(item))
  }
  let responses : Array[@engine.Response] = []
  let mut start = 0
  while start < parsed_cases.length() {
    let requests = []
    let end = if start + 16384 < parsed_cases.length() {
      start + 16384
    } else {
      parsed_cases.length()
    }
    for i in start..<end {
      requests.push(parsed_cases[i].request)
    }
    for
      response in @engine.authorize_batch_with_tags(
        policies, requests, entities,
      ) {
      responses.push(response)
    }
    start = end
  }
  if parsed_cases.is_empty() {
    @engine.validate_entities(entities)
  }
  let results : Array[Json] = []
  let mut failures = 0
  for i in 0..<parsed_cases.length() {
    let test_case = parsed_cases[i]
    let expected = test_case.expected
    let expected_reasons = test_case.expected_reasons
    let expected_errors = test_case.expected_errors
    let response = responses[i]
    let actual = match response.decision {
      Allow => "Allow"
      Deny => "Deny"
    }
    let error_ids = []
    for error in response.errors {
      error_ids.push(error.policy_id)
    }
    let decision_match = expected == actual
    let reasons_match = match expected_reasons {
      Some(ids) => same_policy_ids(ids, response.reasons)
      None => true
    }
    let errors_match = same_policy_ids(expected_errors, error_ids)
    let passed = decision_match && reasons_match && errors_match
    if !passed {
      failures += 1
    }
    let report : Json = {
      "index": i,
      "expected": expected,
      "passed": passed,
      "checks": {
        "decision": decision_match,
        "reasons": match expected_reasons {
          Some(_) => Json::boolean(reasons_match)
          None => Json::null()
        },
        "errors": errors_match,
      },
      "response": @engine.response_to_json(response),
    }
    results.push(report)
    if !json {
      let status = if passed { "PASS" } else { "FAIL" }
      println(
        "case \{i}: \{status} - \{actual} (expected \{expected}), errors=\{response.errors.length()}",
      )
      if !reasons_match {
        let wanted = expected_reasons.unwrap_or([]).join(", ")
        let got = response.reasons.join(", ")
        println("  reasons: expected [\{wanted}], got [\{got}]")
      }
      if !errors_match {
        let wanted = expected_errors.join(", ")
        let got = error_ids.join(", ")
        println("  errors: expected [\{wanted}], got [\{got}]")
      }
    }
  }
  if json {
    let report : Json = { "cases": results, "failures": failures }
    println(report.stringify())
  }
  if failures == 0 {
    0
  } else {
    1
  }
}

///|
fn main {
  let code = run(@env.args()) catch {
    e => {
      stderr(@utf8.encode(e.to_string()))
      2
    }
  }
  if code != 0 {
    exit_process(code)
  }
}
