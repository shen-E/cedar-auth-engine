///|
/// Counts of Cedar decisions, policy errors and fail-closed enforcement.
pub(all) struct AuthorizationSummary {
  total : Int32
  cedar_allowed : Int32
  cedar_denied : Int32
  error_requests : Int32
  enforcement_allowed : Int32
  enforcement_denied : Int32
} derive(Debug, Eq)

///|
pub extend AuthorizationSummary with Debug::{to_repr}

///|
pub extend AuthorizationSummary with Eq::{equal, not_equal}

///|
fn summarize_authorization_in_graph(
  policies : PolicySet,
  requests : Array[Request],
  graph : EntityGraph,
) -> AuthorizationSummary {
  let context = EvaluationContext::new(graph)
  let mut cedar_allowed = 0
  let mut error_requests = 0
  let mut enforcement_allowed = 0
  for request in requests {
    let response = authorize_in_context(policies, request, context)
    if response.decision == Allow {
      cedar_allowed += 1
    }
    if !response.errors.is_empty() {
      error_requests += 1
    }
    if response.is_authorized() {
      enforcement_allowed += 1
    }
  }
  {
    total: requests.length(),
    cedar_allowed,
    cedar_denied: requests.length() - cedar_allowed,
    error_requests,
    enforcement_allowed,
    enforcement_denied: requests.length() - enforcement_allowed,
  }
}

///|
/// Summarize up to 32,768 requests without retaining individual responses.
pub fn EntityStore::authorize_batch_summary(
  self : EntityStore,
  policies : PolicySet,
  requests : Array[Request],
) -> AuthorizationSummary raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  summarize_authorization_in_graph(policies, requests, self.graph)
}

///|
/// Validate all typed requests before calculating their authorization summary.
pub fn EntityStore::authorize_batch_summary_checked(
  self : EntityStore,
  policies : PolicySet,
  requests : Array[Request],
) -> AuthorizationSummary raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  for request in requests {
    request.validate()
  }
  summarize_authorization_in_graph(policies, requests, self.graph)
}

///|
/// Summarize requests using one validated tagged entity graph.
pub fn authorize_batch_summary_with_tags(
  policies : PolicySet,
  requests : Array[Request],
  entities : Array[TaggedEntity],
) -> AuthorizationSummary raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  summarize_authorization_in_graph(
    policies,
    requests,
    build_entity_graph(entities),
  )
}
