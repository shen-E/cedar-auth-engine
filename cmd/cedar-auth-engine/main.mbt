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
  let buffer = Bytes::make(1048577, 0)
  let length = read_file(@utf8.encode(path), buffer)
  if length < 0 {
    raise CliError("cannot read: " + path)
  }
  if length > 1048576 {
    raise CliError("input exceeds 1 MiB: " + path)
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
  if links.length() > 1024 {
    raise CliError("template link limit exceeded")
  }
  let mut result = policies
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
    result = result.link(template, id, {
      principal: optional_link_uid(fields, "principal"),
      resource: optional_link_uid(fields, "resource"),
    })
  }
  result
}

///|
fn run(args : Array[String]) -> Int32 raise {
  if args.length() < 2 || args[1] == "--help" {
    println(
      "cedar-auth-engine check POLICY [--format json]\ncedar-auth-engine authorize POLICY ENTITIES REQUEST [--strict] [--format json]\ncedar-auth-engine batch POLICY ENTITIES REQUESTS [--strict] [--format json]\ncedar-auth-engine test POLICY ENTITIES CASES [--format json]\nOptions for authorize, batch and test: --template TEMPLATE --links LINKS",
    )
    return 0
  }
  if args[1] == "--version" {
    println("cedar-auth-engine 0.1.0")
    return 0
  }
  let command = args[1]
  let required_count = if command == "check" {
    3
  } else if command == "authorize" || command == "batch" || command == "test" {
    5
  } else {
    raise CliError("unknown command")
  }
  if args.length() < required_count {
    raise CliError("invalid arguments; use --help")
  }
  let mut json = false
  let mut strict = false
  let mut template_path : String? = None
  let mut links_path : String? = None
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
      template_path is None &&
      i + 1 < args.length() {
      template_path = Some(args[i + 1])
      i += 2
    } else if args[i] == "--links" &&
      command != "check" &&
      links_path is None &&
      i + 1 < args.length() {
      links_path = Some(args[i + 1])
      i += 2
    } else {
      raise CliError("invalid arguments; use --help")
    }
  }
  let static_policies = @engine.parse_policies(read_text(args[2]))
  let policies = match (template_path, links_path) {
    (None, None) => static_policies
    (Some(template), Some(links)) =>
      apply_template(static_policies, template, links)
    _ => raise CliError("--template and --links must be provided together")
  }
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
  if command == "authorize" {
    let response = @engine.authorize_with_tags(
      policies,
      @engine.request_from_json(input),
      entities,
    )
    if json {
      println(@engine.response_to_json(response).stringify())
    } else {
      let decision = match response.decision {
        Allow => "Allow"
        Deny => "Deny"
      }
      let reasons = response.reasons.join(", ")
      println("\{decision}: \{reasons}")
      for error in response.errors {
        println("\{error.policy_id}: \{error.message}")
      }
    }
    return if strict && !response.errors.is_empty() { 1 } else { 0 }
  }
  if command == "batch" {
    let items = match input {
      Array(items) => items
      _ => raise CliError("batch input must be an array")
    }
    if items.length() > 4096 {
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
    for i in 0..<responses.length() {
      let response = responses[i]
      if !response.errors.is_empty() {
        has_errors = true
      }
      if json {
        output.push(@engine.response_to_json(response))
      } else {
        let decision = match response.decision {
          Allow => "Allow"
          Deny => "Deny"
        }
        let reasons = response.reasons.join(", ")
        println("request \{i}: \{decision}: \{reasons}")
        for error in response.errors {
          println("  \{error.policy_id}: \{error.message}")
        }
      }
    }
    if json {
      println(Json::array(output).stringify())
    }
    return if strict && has_errors { 1 } else { 0 }
  }
  let cases = match input {
    Array(items) => items
    _ => raise CliError("test input must be an array")
  }
  @engine.validate_entities(entities)
  let results : Array[Json] = []
  let mut failures = 0
  for i in 0..<cases.length() {
    let fields = match cases[i] {
      Object(fields) => fields
      _ => raise CliError("test case must be an object")
    }
    let request = match fields.get("request") {
      Some(request) => request
      None => raise CliError("test case missing request")
    }
    let expected = match fields.get("decision") {
      Some(String(value)) => value
      _ => raise CliError("test case missing decision")
    }
    if expected != "Allow" && expected != "Deny" {
      raise CliError("expected decision must be Allow or Deny")
    }
    let expected_reasons = optional_policy_ids(fields, "reasons")
    let expected_errors = optional_policy_ids(fields, "errors").unwrap_or([])
    let response = @engine.authorize_with_tags(
      policies,
      @engine.request_from_json(request),
      entities,
    )
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
