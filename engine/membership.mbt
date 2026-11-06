///|
// Cache belongs to a single authorization operation and one entity graph.
priv struct EvaluationContext {
  graph : EntityGraph
  ancestry : Map[String, Map[String, Bool]]
  mut entries : Int32
  mut key_units : Int32
}

///|
fn EvaluationContext::new(graph : EntityGraph) -> EvaluationContext {
  { graph, ancestry: Map([]), entries: 0, key_units: 0, }
}

///|
fn EvaluationContext::is_descendant(
  self : EvaluationContext,
  child : EntityId,
  ancestor : EntityId,
) -> Bool {
  if child == ancestor {
    return true
  }
  // Long caller-supplied identifiers remain valid but are not retained.
  if child.kind.length() > 65536 ||
    child.id.length() > 65536 ||
    ancestor.kind.length() > 65536 ||
    ancestor.id.length() > 65536 ||
    child.kind.length() + child.id.length() > 65536 ||
    ancestor.kind.length() + ancestor.id.length() > 65536 {
    return is_descendant(self.graph, child, ancestor)
  }
  let child_key = entity_key(child)
  let ancestor_key = entity_key(ancestor)
  match self.ancestry.get(child_key) {
    Some(values) =>
      match values.get(ancestor_key) {
        Some(result) => return result
        None => ()
      }
    None => ()
  }
  let result = is_descendant(self.graph, child, ancestor)
  let cost = child_key.length() + ancestor_key.length()
  if self.entries < 4096 && cost <= 262144 - self.key_units {
    let values = match self.ancestry.get(child_key) {
      Some(existing) => existing
      None => {
        let fresh : Map[String, Bool] = Map([])
        self.ancestry[child_key] = fresh
        fresh
      }
    }
    values[ancestor_key] = result
    self.entries += 1
    self.key_units += cost
  }
  result
}
