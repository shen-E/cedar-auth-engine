///|
/// Return a new policy set without the policy identified by `id`.
pub fn PolicySet::remove(
  self : PolicySet,
  id : String,
) -> PolicySet raise PolicyError {
  self.remove_batch([id])
}

///|
/// Remove all specified policy IDs or raise an error without changing the set.
pub fn PolicySet::remove_batch(
  self : PolicySet,
  ids : Array[String],
) -> PolicySet raise PolicyError {
  if ids.length() > 4096 {
    raise PolicyError("policy removal limit exceeded")
  }
  let existing : Map[String, Bool] = Map([])
  for policy in self.policies {
    existing[policy.id] = true
  }
  let removed : Map[String, Bool] = Map([])
  for id in ids {
    if removed.contains(id) {
      raise PolicyError("duplicate removal id '\{id}'")
    }
    if !existing.contains(id) {
      raise PolicyError("unknown policy id '\{id}'")
    }
    removed[id] = true
  }
  let remaining = []
  for policy in self.policies {
    if !removed.contains(policy.id) {
      remaining.push(policy)
    }
  }
  make_policy_set(remaining)
}

///|
/// Return a new policy set with disjoint policies appended in their original order.
pub fn PolicySet::merge(
  self : PolicySet,
  additional : PolicySet,
) -> PolicySet raise PolicyError {
  if additional.policies.length() > 4096 - self.policies.length() {
    raise PolicyError("policy count limit exceeded")
  }
  let ids : Map[String, Bool] = Map([])
  for policy in self.policies {
    ids[policy.id] = true
  }
  for policy in additional.policies {
    if ids.contains(policy.id) {
      raise PolicyError("duplicate policy id '\{policy.id}'")
    }
  }
  let policies = self.policies.copy()
  for policy in additional.policies {
    policies.push(policy)
  }
  make_policy_set(policies)
}

///|
/// Replace existing IDs with policies from `updates`, keeping their positions.
pub fn PolicySet::replace(
  self : PolicySet,
  updates : PolicySet,
) -> PolicySet raise PolicyError {
  let existing : Map[String, Bool] = Map([])
  for policy in self.policies {
    existing[policy.id] = true
  }
  let by_id : Map[String, Policy] = Map([])
  for policy in updates.policies {
    if !existing.contains(policy.id) {
      raise PolicyError("unknown policy id '\{policy.id}'")
    }
    by_id[policy.id] = policy
  }
  let policies = []
  for policy in self.policies {
    policies.push(
      match by_id.get(policy.id) {
        Some(update) => update
        None => policy
      },
    )
  }
  make_policy_set(policies)
}
