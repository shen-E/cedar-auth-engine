///|
fn compare_entities(
  value : Json,
  schema : Json?,
  check_enums : Bool,
  check_parents : Bool,
  schema_actions : Bool,
) -> Array[@engine.TaggedEntity] raise {
  match schema {
    None => @engine.tagged_entities_from_json(value)
    Some(schema) => {
      let decoded = if check_enums {
        @engine.tagged_entities_from_json_with_checked_enums(value, schema)
      } else {
        @engine.tagged_entities_from_json_with_resolved_schema(value, schema)
      }
      if check_parents {
        @engine.check_entity_parent_types(decoded, schema)
      }
      if schema_actions {
        @engine.entities_with_schema_actions(decoded, schema)
      } else {
        decoded
      }
    }
  }
}

///|
fn run_compare(args : Array[String]) -> Int32 raise {
  if args.length() < 6 {
    raise CliError("invalid compare arguments; use --help")
  }
  let mut json = false
  let mut summary_only = false
  let mut fail_on_change = false
  let mut fail_decision_grant = false
  let mut fail_decision_revoke = false
  let mut fail_enforcement_grant = false
  let mut fail_enforcement_revoke = false
  let mut fail_after_error = false
  let mut after_entities_path : String? = None
  let mut entity_schema_path : String? = None
  let mut context_schema_path : String? = None
  let mut check_enums = false
  let mut check_parents = false
  let mut schema_actions = false
  let mut check_request_types = false
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
    } else if args[i] == "--summary" && !summary_only {
      summary_only = true
      i += 1
    } else if args[i] == "--fail-on-change" && !fail_on_change {
      fail_on_change = true
      i += 1
    } else if args[i] == "--fail-on-decision-grant" && !fail_decision_grant {
      fail_decision_grant = true
      i += 1
    } else if args[i] == "--fail-on-decision-revoke" && !fail_decision_revoke {
      fail_decision_revoke = true
      i += 1
    } else if args[i] == "--fail-on-enforcement-grant" &&
      !fail_enforcement_grant {
      fail_enforcement_grant = true
      i += 1
    } else if args[i] == "--fail-on-enforcement-revoke" &&
      !fail_enforcement_revoke {
      fail_enforcement_revoke = true
      i += 1
    } else if args[i] == "--fail-on-after-error" && !fail_after_error {
      fail_after_error = true
      i += 1
    } else if args[i] == "--after-entities" &&
      after_entities_path is None &&
      i + 1 < args.length() {
      after_entities_path = Some(args[i + 1])
      i += 2
    } else if args[i] == "--resolved-entity-schema" &&
      entity_schema_path is None &&
      i + 1 < args.length() {
      entity_schema_path = Some(args[i + 1])
      i += 2
    } else if args[i] == "--resolved-context-schema" &&
      context_schema_path is None &&
      i + 1 < args.length() {
      context_schema_path = Some(args[i + 1])
      i += 2
    } else if args[i] == "--check-entity-enums" && !check_enums {
      check_enums = true
      i += 1
    } else if args[i] == "--check-parent-types" && !check_parents {
      check_parents = true
      i += 1
    } else if args[i] == "--schema-actions" && !schema_actions {
      schema_actions = true
      i += 1
    } else if args[i] == "--check-request-types" && !check_request_types {
      check_request_types = true
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
  if (check_enums || check_parents || schema_actions) &&
    entity_schema_path is None {
    raise CliError("entity schema checks require --resolved-entity-schema")
  }
  if check_request_types && context_schema_path is None {
    raise CliError("--check-request-types requires --resolved-context-schema")
  }
  let before = before_inputs.load(args[2])
  let after = after_inputs.load(args[3])
  let entity_schema = match entity_schema_path {
    Some(path) => Some(load_json(path))
    None => None
  }
  let context_schema = match context_schema_path {
    Some(path) =>
      Some(@engine.ResolvedContextSchema::from_json(load_json(path)))
    None => None
  }
  let entities = compare_entities(
    load_json(args[4]),
    entity_schema,
    check_enums,
    check_parents,
    schema_actions,
  )
  let items = match load_json(args[5]) {
    Array(items) => items
    _ => raise CliError("compare requests must be an array")
  }
  if items.length() > 32768 {
    raise CliError("request batch limit exceeded")
  }
  let requests = []
  for item in items {
    requests.push(decode_request(item, context_schema, check_request_types))
  }
  let store = @engine.EntityStore::new_with_tags(entities)
  let after_store = match after_entities_path {
    None => store
    Some(path) =>
      @engine.EntityStore::new_with_tags(
        compare_entities(
          load_json(path),
          entity_schema,
          check_enums,
          check_parents,
          schema_actions,
        ),
      )
  }
  if summary_only {
    let summary = store.compare_summary_with_entities(
      after_store, before, after, requests,
    )
    print_comparison_summary(summary, json)
    return if (fail_on_change && summary.changed > 0) ||
      (fail_decision_grant && summary.decision_grants > 0) ||
      (fail_decision_revoke && summary.decision_revocations > 0) ||
      (fail_enforcement_grant && summary.enforcement_grants > 0) ||
      (fail_enforcement_revoke && summary.enforcement_revocations > 0) ||
      (fail_after_error && summary.after_error_requests > 0) {
      1
    } else {
      0
    }
  }
  let comparisons = store.compare_with_entities(
    after_store, before, after, requests,
  )
  let cases : Array[Json] = []
  let mut changed = 0
  let mut decisions = 0
  let mut enforcement = 0
  let mut reasons = 0
  let mut errors = 0
  let mut decision_grants = 0
  let mut decision_revocations = 0
  let mut enforcement_grants = 0
  let mut enforcement_revocations = 0
  let mut after_error_requests = 0
  for index in 0..<comparisons.length() {
    let item = comparisons[index]
    let decision_changed = item.decision_changed()
    let enforcement_changed = item.enforcement_changed()
    let reasons_changed = item.reasons_changed()
    let errors_changed = item.errors_changed()
    let decision_granted = item.decision_granted()
    let decision_revoked = item.decision_revoked()
    let enforcement_granted = item.enforcement_granted()
    let enforcement_revoked = item.enforcement_revoked()
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
    if !item.after.errors.is_empty() {
      after_error_requests += 1
    }
    if decision_granted {
      decision_grants += 1
    }
    if decision_revoked {
      decision_revocations += 1
    }
    if enforcement_granted {
      enforcement_grants += 1
    }
    if enforcement_revoked {
      enforcement_revocations += 1
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
        "decision_granted": decision_granted,
        "decision_revoked": decision_revoked,
        "enforcement_granted": enforcement_granted,
        "enforcement_revoked": enforcement_revoked,
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
      "decision_grants": decision_grants,
      "decision_revocations": decision_revocations,
      "enforcement_grants": enforcement_grants,
      "enforcement_revocations": enforcement_revocations,
      "after_error_requests": after_error_requests,
    }
    println(report.stringify())
  } else {
    println(
      "\{changed}/\{comparisons.length()} changed; decision=\{decisions} (grants=\{decision_grants}, revocations=\{decision_revocations}), enforcement=\{enforcement} (grants=\{enforcement_grants}, revocations=\{enforcement_revocations}), reasons=\{reasons}, errors=\{errors}, after errors=\{after_error_requests}",
    )
  }
  if (fail_on_change && changed > 0) ||
    (fail_decision_grant && decision_grants > 0) ||
    (fail_decision_revoke && decision_revocations > 0) ||
    (fail_enforcement_grant && enforcement_grants > 0) ||
    (fail_enforcement_revoke && enforcement_revocations > 0) ||
    (fail_after_error && after_error_requests > 0) {
    1
  } else {
    0
  }
}
