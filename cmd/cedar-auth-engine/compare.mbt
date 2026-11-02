///|
fn run_compare(args : Array[String]) -> Int32 raise {
  if args.length() < 6 {
    raise CliError("invalid compare arguments; use --help")
  }
  let mut json = false
  let mut fail_on_change = false
  let before_inputs = policy_inputs()
  let after_inputs = policy_inputs()
  let mut i = 6
  while i < args.length() {
    if args[i] == "--format" &&
      !json &&
      i + 1 < args.length() &&
      args[i + 1] == "json" {
      json = true
      i += 2
    } else if args[i] == "--fail-on-change" && !fail_on_change {
      fail_on_change = true
      i += 1
    } else if args[i] == "--before-template" && i + 1 < args.length() {
      before_inputs.templates.push(args[i + 1])
      i += 2
    } else if args[i] == "--before-links" && i + 1 < args.length() {
      before_inputs.links.push(args[i + 1])
      i += 2
    } else if args[i] == "--after-template" && i + 1 < args.length() {
      after_inputs.templates.push(args[i + 1])
      i += 2
    } else if args[i] == "--after-links" && i + 1 < args.length() {
      after_inputs.links.push(args[i + 1])
      i += 2
    } else if args[i] == "--before-add-policies" && i + 1 < args.length() {
      before_inputs.additions.push(args[i + 1])
      i += 2
    } else if args[i] == "--after-add-policies" && i + 1 < args.length() {
      after_inputs.additions.push(args[i + 1])
      i += 2
    } else if args[i] == "--before-replace-policies" && i + 1 < args.length() {
      before_inputs.replacements.push(args[i + 1])
      i += 2
    } else if args[i] == "--after-replace-policies" && i + 1 < args.length() {
      after_inputs.replacements.push(args[i + 1])
      i += 2
    } else if args[i] == "--before-remove-policy" && i + 1 < args.length() {
      before_inputs.removals.push(args[i + 1])
      i += 2
    } else if args[i] == "--after-remove-policy" && i + 1 < args.length() {
      after_inputs.removals.push(args[i + 1])
      i += 2
    } else {
      raise CliError("invalid compare arguments; use --help")
    }
  }
  if before_inputs.templates.length() != before_inputs.links.length() ||
    after_inputs.templates.length() != after_inputs.links.length() {
    raise CliError("template and links counts must match on each side")
  }
  before_inputs.validate()
  after_inputs.validate()
  let before = before_inputs.load(args[2])
  let after = after_inputs.load(args[3])
  let entities = @engine.tagged_entities_from_json(load_json(args[4]))
  let items = match load_json(args[5]) {
    Array(items) => items
    _ => raise CliError("compare requests must be an array")
  }
  if items.length() > 4096 {
    raise CliError("request batch limit exceeded")
  }
  let requests = []
  for item in items {
    requests.push(@engine.request_from_json(item))
  }
  let store = @engine.EntityStore::new_with_tags(entities)
  let comparisons = store.compare(before, after, requests)
  let cases : Array[Json] = []
  let mut changed = 0
  let mut decisions = 0
  let mut enforcement = 0
  let mut reasons = 0
  let mut errors = 0
  for index in 0..<comparisons.length() {
    let item = comparisons[index]
    let decision_changed = item.decision_changed()
    let enforcement_changed = item.enforcement_changed()
    let reasons_changed = item.reasons_changed()
    let errors_changed = item.errors_changed()
    let any_changed = decision_changed || reasons_changed || errors_changed
    if any_changed {
      changed += 1
    }
    if decision_changed {
      decisions += 1
    }
    if enforcement_changed {
      enforcement += 1
    }
    if reasons_changed {
      reasons += 1
    }
    if errors_changed {
      errors += 1
    }
    if json {
      let result : Json = {
        "index": index,
        "before": @engine.response_to_json(item.before),
        "after": @engine.response_to_json(item.after),
        "before_allowed": item.before.is_authorized(),
        "after_allowed": item.after.is_authorized(),
        "changed": any_changed,
        "decision_changed": decision_changed,
        "enforcement_changed": enforcement_changed,
        "reasons_changed": reasons_changed,
        "errors_changed": errors_changed,
      }
      cases.push(result)
    } else {
      let previous = decision_label(item.before)
      let next = decision_label(item.after)
      let status = if any_changed { "changed" } else { "unchanged" }
      println(
        "case \{index}: \{status} - Cedar \{previous} -> \{next}, allowed \{item.before.is_authorized()} -> \{item.after.is_authorized()}, reasons changed=\{reasons_changed}, errors changed=\{errors_changed}",
      )
      if reasons_changed {
        println(
          "  reasons: [\{item.before.reasons.join(", ")}] -> [\{item.after.reasons.join(", ")}]",
        )
      }
      if errors_changed {
        for error in item.before.errors {
          println("  before \{error.policy_id}: \{error.message}")
        }
        for error in item.after.errors {
          println("  after \{error.policy_id}: \{error.message}")
        }
      }
    }
  }
  if json {
    let report : Json = {
      "cases": Json::array(cases),
      "total": comparisons.length(),
      "changed": changed,
      "decisions_changed": decisions,
      "enforcement_changed": enforcement,
      "reasons_changed": reasons,
      "errors_changed": errors,
    }
    println(report.stringify())
  } else {
    println(
      "\{changed}/\{comparisons.length()} changed; decision=\{decisions}, enforcement=\{enforcement}, reasons=\{reasons}, errors=\{errors}",
    )
  }
  if fail_on_change && changed > 0 {
    1
  } else {
    0
  }
}
