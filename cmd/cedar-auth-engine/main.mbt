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
fn run(args : Array[String]) -> Int32 raise {
  if args.length() < 2 || args[1] == "--help" {
    println(
      "cedar-auth-engine check POLICY [--format json]\ncedar-auth-engine authorize POLICY ENTITIES REQUEST [--format json]\ncedar-auth-engine test POLICY ENTITIES CASES [--format json]",
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
  } else if command == "authorize" || command == "test" {
    5
  } else {
    raise CliError("unknown command")
  }
  let json = if args.length() == required_count {
    false
  } else if args.length() == required_count + 2 &&
    args[required_count] == "--format" &&
    args[required_count + 1] == "json" {
    true
  } else {
    raise CliError("invalid arguments; use --help")
  }
  let policies = @engine.parse_policies(read_text(args[2]))
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
    return 0
  }
  let cases = match input {
    Array(items) => items
    _ => raise CliError("test input must be an array")
  }
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
    let response = @engine.authorize_with_tags(
      policies,
      @engine.request_from_json(request),
      entities,
    )
    let actual = match response.decision {
      Allow => "Allow"
      Deny => "Deny"
    }
    let passed = expected == actual && response.errors.is_empty()
    if !passed {
      failures += 1
    }
    let report : Json = {
      "index": i,
      "expected": expected,
      "passed": passed,
      "response": @engine.response_to_json(response),
    }
    results.push(report)
    if !json {
      println(
        "case \{i}: \{actual} (expected \{expected}), errors=\{response.errors.length()}",
      )
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
