///|
// Index only provably safe exact-action scopes; preserve source positions so
// indexed and fallback policies can be evaluated in their original order.
fn make_policy_set(policies : Array[Policy]) -> PolicySet {
  let action_index : Map[String, Array[Int32]] = Map([])
  let fallback = []
  for i in 0..<policies.length() {
    match policies[i].action_key {
      Some(uid) => {
        let key = entity_key(uid)
        match action_index.get(key) {
          Some(positions) => positions.push(i)
          None => action_index[key] = [i]
        }
      }
      None => fallback.push(i)
    }
  }
  { policies, action_index, fallback, }
}
