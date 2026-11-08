///|
fn run_explain(
  policies : @engine.PolicySet,
  request : @engine.Request,
  entities : Array[@engine.TaggedEntity],
  json : Bool,
  strict : Bool,
) -> Int32 raise {
  let trace = @engine.authorize_trace_with_tags(policies, request, entities)
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
    }
  }
  if strict && !trace.response.errors.is_empty() {
    1
  } else {
    0
  }
}
