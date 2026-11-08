///|
fn run_explain_stages(
  policies : @engine.PolicySet,
  request : @engine.Request,
  entities : Array[@engine.TaggedEntity],
  json : Bool,
  strict : Bool,
) -> Int32 raise {
  let trace = @engine.authorize_details_with_tags(policies, request, entities)
  if json {
    let items : Array[Json] = []
    for policy in trace.policies {
      let fields : Map[String, Json] = {
        "policy_id": Json::string(policy.policy_id),
        "effect": Json::string(policy.effect),
      }
      match policy.outcome {
        Matched => fields["outcome"] = Json::string("matched")
        NotMatched => fields["outcome"] = Json::string("not_matched")
        EvaluationFailed(message) => {
          fields["outcome"] = Json::string("error")
          fields["message"] = Json::string(message)
        }
      }
      let stages : Array[Json] = []
      for stage in policy.stages {
        let item : Map[String, Json] = { "kind": Json::string(stage.kind) }
        match stage.outcome {
          StagePassed => item["outcome"] = Json::string("passed")
          StageFailed => item["outcome"] = Json::string("failed")
          StageSkipped => item["outcome"] = Json::string("skipped")
          StageError(message) => {
            item["outcome"] = Json::string("error")
            item["message"] = Json::string(message)
          }
        }
        stages.push(Json::object(item))
      }
      fields["stages"] = Json::array(stages)
      items.push(Json::object(fields))
    }
    let output : Json = {
      "response": @engine.response_to_json(trace.response),
      "policies": Json::array(items),
    }
    println(output.stringify())
  } else {
    println(
      "\{decision_label(trace.response)}: \{trace.response.reasons.join(", ")}",
    )
    for policy in trace.policies {
      match policy.outcome {
        Matched => println("\{policy.policy_id} (\{policy.effect}): matched")
        NotMatched =>
          println("\{policy.policy_id} (\{policy.effect}): not matched")
        EvaluationFailed(message) =>
          println("\{policy.policy_id} (\{policy.effect}): error: \{message}")
      }
      for stage in policy.stages {
        match stage.outcome {
          StagePassed => println("  \{stage.kind}: passed")
          StageFailed => println("  \{stage.kind}: failed")
          StageSkipped => println("  \{stage.kind}: skipped")
          StageError(message) => println("  \{stage.kind}: error: \{message}")
        }
      }
    }
  }
  if strict && !trace.response.errors.is_empty() {
    1
  } else {
    0
  }
}
