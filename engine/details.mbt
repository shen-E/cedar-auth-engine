///|
/// A stage's effective result. An `unless` stage passes when its expression is false.
pub(all) enum StageOutcome {
  StagePassed
  StageFailed
  StageSkipped
  StageError(String)
} derive(Debug, Eq)

///|
pub extend StageOutcome with Debug::{to_repr}

///|
pub extend StageOutcome with Eq::{equal, not_equal}

///|
/// A scope or top-level condition, in evaluation order.
pub(all) struct PolicyStage {
  kind : String
  outcome : StageOutcome
} derive(Debug, Eq)

///|
pub extend PolicyStage with Debug::{to_repr}

///|
pub extend PolicyStage with Eq::{equal, not_equal}

///|
pub(all) struct DetailedPolicyTrace {
  policy_id : String
  effect : String
  outcome : PolicyOutcome
  stages : Array[PolicyStage]
} derive(Debug, Eq)

///|
pub extend DetailedPolicyTrace with Debug::{to_repr}

///|
pub extend DetailedPolicyTrace with Eq::{equal, not_equal}

///|
pub(all) struct AuthorizationDetails {
  response : Response
  policies : Array[DetailedPolicyTrace]
} derive(Debug)

///|
pub extend AuthorizationDetails with Debug::{to_repr}

///|
fn evaluate_stage(
  expression : Expr,
  unless : Bool,
  request : Request,
  context : EvaluationContext,
  budget : Ref[Int32],
  active : Ref[Bool],
) -> StageOutcome {
  if !active.val {
    return StageSkipped
  }
  let passed = try {
    let value = boolean(evaluate(expression, request, context, budget))
    if unless {
      !value
    } else {
      value
    }
  } catch {
    PolicyError(message) => {
      active.val = false
      return StageError(message)
    }
  }
  if passed {
    StagePassed
  } else {
    active.val = false
    StageFailed
  }
}

///|
fn details_in_graph(
  policies : PolicySet,
  request : Request,
  graph : EntityGraph,
) -> AuthorizationDetails {
  let context = EvaluationContext::new(graph)
  let traces : Array[DetailedPolicyTrace] = []
  let permits = []
  let forbids = []
  let errors = []
  for policy in policies.policies {
    let active = Ref(true)
    let budget = Ref(1000000)
    let stages : Array[PolicyStage] = []
    for
      (kind, expression) in [
        ("principal", policy.principal_scope),
        ("action", policy.action_scope),
        ("resource", policy.resource_expression),
      ] {
      stages.push({
        kind,
        outcome: evaluate_stage(
          expression, false, request, context, budget, active,
        ),
      })
    }
    for clause in policy.clauses {
      stages.push({
        kind: if clause.unless {
          "unless"
        } else {
          "when"
        },
        outcome: evaluate_stage(
          clause.expression,
          clause.unless,
          request,
          context,
          budget,
          active,
        ),
      })
    }
    let mut outcome : PolicyOutcome = Matched
    for stage in stages {
      match stage.outcome {
        StageFailed => outcome = NotMatched
        StageError(message) => outcome = EvaluationFailed(message)
        _ => ()
      }
    }
    match outcome {
      Matched =>
        if policy.forbid {
          forbids.push(policy.id)
        } else {
          permits.push(policy.id)
        }
      EvaluationFailed(message) =>
        errors.push({ policy_id: policy.id, message, })
      NotMatched => ()
    }
    traces.push({
      policy_id: policy.id,
      effect: if policy.forbid {
        "forbid"
      } else {
        "permit"
      },
      outcome,
      stages,
    })
  }
  {
    response: authorization_response(permits, forbids, errors),
    policies: traces,
  }
}

///|
/// Explain each scope and top-level condition, preserving short-circuit order.
pub fn EntityStore::authorize_details(
  self : EntityStore,
  policies : PolicySet,
  request : Request,
) -> AuthorizationDetails {
  details_in_graph(policies, request, self.graph)
}

///|
/// Validate a typed request before explaining authorization.
pub fn EntityStore::authorize_details_checked(
  self : EntityStore,
  policies : PolicySet,
  request : Request,
) -> AuthorizationDetails raise PolicyError {
  request.validate()
  self.authorize_details(policies, request)
}

///|
/// Explain authorization after validating a tagged entity graph.
pub fn authorize_details_with_tags(
  policies : PolicySet,
  request : Request,
  entities : Array[TaggedEntity],
) -> AuthorizationDetails raise PolicyError {
  details_in_graph(policies, request, build_entity_graph(entities))
}
