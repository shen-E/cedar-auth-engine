///|
// Each policy belongs to one index or the fallback list. The positions retain
// source order for merging during authorization.
fn make_policy_set(policies : Array[Policy]) -> PolicySet {
  let action_index : Map[String, Array[Int32]] = Map([])
  let principal_index : Map[String, Array[Int32]] = Map([])
  let fallback = []
  for i in 0..<policies.length() {
    let principal = match policies[i].principal_scope {
      Equal(Variable("principal"), Literal(EntityValue(uid))) => Some(uid)
      _ => None
    }
    match principal {
      Some(uid) => add_policy_position(principal_index, uid, i)
      None =>
        match policies[i].action_key {
          Some(uid) => add_policy_position(action_index, uid, i)
          None => fallback.push(i)
        }
    }
  }
  { policies, action_index, principal_index, fallback, }
}

///|
fn add_policy_position(
  index : Map[String, Array[Int32]],
  uid : EntityId,
  position : Int32,
) -> Unit {
  let key = entity_key(uid)
  match index.get(key) {
    Some(positions) => positions.push(position)
    None => index[key] = [position]
  }
}
