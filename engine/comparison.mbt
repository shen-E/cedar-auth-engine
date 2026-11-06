///|
/// Responses to the same request under two policy sets.
pub(all) struct AuthorizationComparison {
  before : Response
  after : Response
}

///|
fn same_strings(left : Array[String], right : Array[String]) -> Bool {
  if left.length() != right.length() {
    return false
  }
  let counts : Map[String, Int32] = Map([])
  for value in left {
    counts[value] = counts.get(value).unwrap_or(0) + 1
  }
  for value in right {
    match counts.get(value) {
      Some(count) if count > 0 => counts[value] = count - 1
      _ => return false
    }
  }
  true
}

///|
fn diagnostic_keys(errors : Array[Diagnostic]) -> Array[String] {
  let keys = []
  for error in errors {
    keys.push(
      error.policy_id.length().to_string() +
      ":" +
      error.policy_id +
      error.message,
    )
  }
  keys
}

///|
/// Whether the Cedar decision differs.
pub fn AuthorizationComparison::decision_changed(
  self : AuthorizationComparison,
) -> Bool {
  self.before.decision != self.after.decision
}

///|
/// Whether fail-closed enforcement differs.
pub fn AuthorizationComparison::enforcement_changed(
  self : AuthorizationComparison,
) -> Bool {
  self.before.is_authorized() != self.after.is_authorized()
}

///|
/// Whether the Cedar decision changed from Deny to Allow, regardless of errors.
pub fn AuthorizationComparison::decision_granted(
  self : AuthorizationComparison,
) -> Bool {
  self.before.decision == Deny && self.after.decision == Allow
}

///|
/// Whether the Cedar decision changed from Allow to Deny, regardless of errors.
pub fn AuthorizationComparison::decision_revoked(
  self : AuthorizationComparison,
) -> Bool {
  self.before.decision == Allow && self.after.decision == Deny
}

///|
/// Whether fail-closed enforcement changed from denied to allowed.
pub fn AuthorizationComparison::enforcement_granted(
  self : AuthorizationComparison,
) -> Bool {
  !self.before.is_authorized() && self.after.is_authorized()
}

///|
/// Whether fail-closed enforcement changed from allowed to denied.
pub fn AuthorizationComparison::enforcement_revoked(
  self : AuthorizationComparison,
) -> Bool {
  self.before.is_authorized() && !self.after.is_authorized()
}

///|
/// Whether the determining policy IDs differ, ignoring order.
pub fn AuthorizationComparison::reasons_changed(
  self : AuthorizationComparison,
) -> Bool {
  !same_strings(self.before.reasons, self.after.reasons)
}

///|
/// Whether policy IDs or messages of evaluation errors differ, ignoring order.
pub fn AuthorizationComparison::errors_changed(
  self : AuthorizationComparison,
) -> Bool {
  !same_strings(
    diagnostic_keys(self.before.errors),
    diagnostic_keys(self.after.errors),
  )
}

///|
/// Whether any decision, determining reason, or evaluation error differs.
pub fn AuthorizationComparison::changed(self : AuthorizationComparison) -> Bool {
  self.decision_changed() || self.reasons_changed() || self.errors_changed()
}

///|
/// Compare up to 4,096 requests using one entity snapshot and two policy sets.
pub fn EntityStore::compare(
  self : EntityStore,
  before : PolicySet,
  after : PolicySet,
  requests : Array[Request],
) -> Array[AuthorizationComparison] raise PolicyError {
  self.compare_with_entities(self, before, after, requests)
}

///|
/// Compare up to 4,096 requests using separate before and after entity snapshots.
pub fn EntityStore::compare_with_entities(
  self : EntityStore,
  after_entities : EntityStore,
  before : PolicySet,
  after : PolicySet,
  requests : Array[Request],
) -> Array[AuthorizationComparison] raise PolicyError {
  if requests.length() > 4096 {
    raise PolicyError("request batch limit exceeded")
  }
  let before_context = EvaluationContext::new(self.graph)
  let after_context = EvaluationContext::new(after_entities.graph)
  let comparisons = []
  for request in requests {
    comparisons.push({
      before: authorize_in_context(before, request, before_context),
      after: authorize_in_context(after, request, after_context),
    })
  }
  comparisons
}
