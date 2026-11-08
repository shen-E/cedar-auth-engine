///|
/// Aggregate changes in a batch of authorization comparisons.
pub(all) struct ComparisonSummary {
  total : Int32
  changed : Int32
  decisions_changed : Int32
  enforcement_changed : Int32
  reasons_changed : Int32
  errors_changed : Int32
  decision_grants : Int32
  decision_revocations : Int32
  enforcement_grants : Int32
  enforcement_revocations : Int32
  after_error_requests : Int32
} derive(Debug, Eq)

///|
pub extend ComparisonSummary with Debug::{to_repr}

///|
pub extend ComparisonSummary with Eq::{equal, not_equal}

///|
/// Summarize up to 32,768 requests against one entity snapshot.
pub fn EntityStore::compare_summary(
  self : EntityStore,
  before : PolicySet,
  after : PolicySet,
  requests : Array[Request],
) -> ComparisonSummary raise PolicyError {
  self.compare_summary_with_entities(self, before, after, requests)
}

///|
/// Summarize comparisons without retaining per-request responses.
pub fn EntityStore::compare_summary_with_entities(
  self : EntityStore,
  after_entities : EntityStore,
  before : PolicySet,
  after : PolicySet,
  requests : Array[Request],
) -> ComparisonSummary raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  let before_context = EvaluationContext::new(self.graph)
  let after_context = EvaluationContext::new(after_entities.graph)
  let mut changed = 0
  let mut decisions_changed = 0
  let mut enforcement_changed = 0
  let mut reasons_changed = 0
  let mut errors_changed = 0
  let mut decision_grants = 0
  let mut decision_revocations = 0
  let mut enforcement_grants = 0
  let mut enforcement_revocations = 0
  let mut after_error_requests = 0
  for request in requests {
    let item : AuthorizationComparison = {
      before: authorize_in_context(before, request, before_context),
      after: authorize_in_context(after, request, after_context),
    }
    let decisions = item.decision_changed()
    let reasons = item.reasons_changed()
    let errors = item.errors_changed()
    if decisions || reasons || errors {
      changed += 1
    }
    if decisions {
      decisions_changed += 1
    }
    if item.enforcement_changed() {
      enforcement_changed += 1
    }
    if reasons {
      reasons_changed += 1
    }
    if errors {
      errors_changed += 1
    }
    if item.decision_granted() {
      decision_grants += 1
    }
    if item.decision_revoked() {
      decision_revocations += 1
    }
    if item.enforcement_granted() {
      enforcement_grants += 1
    }
    if item.enforcement_revoked() {
      enforcement_revocations += 1
    }
    if !item.after.errors.is_empty() {
      after_error_requests += 1
    }
  }
  {
    total: requests.length(),
    changed,
    decisions_changed,
    enforcement_changed,
    reasons_changed,
    errors_changed,
    decision_grants,
    decision_revocations,
    enforcement_grants,
    enforcement_revocations,
    after_error_requests,
  }
}
