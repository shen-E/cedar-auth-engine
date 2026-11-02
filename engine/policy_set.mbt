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
  if ids.length() > 1024 {
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
  { policies: remaining, }
}
