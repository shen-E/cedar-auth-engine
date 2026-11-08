///|
/// The outcome of evaluating a single policy for a request.
pub(all) enum PolicyOutcome {
  Matched
  NotMatched
  EvaluationFailed(String)
} derive(Debug, Eq)

///|
pub extend PolicyOutcome with Debug::{to_repr}

///|
pub extend PolicyOutcome with Eq::{equal, not_equal}

///|
/// A policy's effect and evaluation outcome in policy order.
pub(all) struct PolicyTrace {
  policy_id : String
  effect : String
  outcome : PolicyOutcome
} derive(Debug, Eq)

///|
pub extend PolicyTrace with Debug::{to_repr}

///|
pub extend PolicyTrace with Eq::{equal, not_equal}

///|
/// The authorization response and each policy's evaluation outcome.
pub(all) struct AuthorizationTrace {
  response : Response
  policies : Array[PolicyTrace]
} derive(Debug)

///|
pub extend AuthorizationTrace with Debug::{to_repr}

///|
fn trace_in_graph(
  policies : PolicySet,
  request : Request,
  graph : EntityGraph,
) -> AuthorizationTrace {
  let context = EvaluationContext::new(graph)
  let traces = []
  let permits = []
  let forbids = []
  let errors = []
  for policy in policies.policies {
    let outcome = try {
      if evaluate_policy(policy, request, context) {
        Matched
      } else {
        NotMatched
      }
    } catch {
      PolicyError(message) => EvaluationFailed(message)
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
    })
  }
  {
    response: authorization_response(permits, forbids, errors),
    policies: traces,
  }
}

///|
/// Evaluate every policy against this snapshot and return their outcomes.
pub fn EntityStore::authorize_trace(
  self : EntityStore,
  policies : PolicySet,
  request : Request,
) -> AuthorizationTrace {
  trace_in_graph(policies, request, self.graph)
}

///|
/// Validate a typed request before tracing authorization.
pub fn EntityStore::authorize_trace_checked(
  self : EntityStore,
  policies : PolicySet,
  request : Request,
) -> AuthorizationTrace raise PolicyError {
  request.validate()
  self.authorize_trace(policies, request)
}

///|
/// Trace authorization after validating a tagged entity graph.
pub fn authorize_trace_with_tags(
  policies : PolicySet,
  request : Request,
  entities : Array[TaggedEntity],
) -> AuthorizationTrace raise PolicyError {
  trace_in_graph(policies, request, build_entity_graph(entities))
}
