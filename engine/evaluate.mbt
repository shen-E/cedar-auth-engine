///|
fn same_value(a : Value, b : Value) -> Bool {
  match (a, b) {
    (SetValue(xs), SetValue(ys)) => {
      for x in xs {
        if !ys.any(fn(y) { same_value(x, y) }) {
          return false
        }
      }
      for y in ys {
        if !xs.any(fn(x) { same_value(x, y) }) {
          return false
        }
      }
      true
    }
    (RecordValue(xs), RecordValue(ys)) => {
      if xs.length() != ys.length() {
        return false
      }
      for key, value in xs {
        match ys.get(key) {
          Some(other) => if !same_value(value, other) { return false }
          None => return false
        }
      }
      true
    }
    _ => a == b
  }
}

///|
fn find_entity(entities : Array[Entity], uid : EntityId) -> Entity? {
  for entity in entities {
    if entity.uid == uid {
      return Some(entity)
    }
  }
  None
}

///|
fn is_descendant(
  entities : Array[Entity],
  child : EntityId,
  ancestor : EntityId,
) -> Bool {
  let pending = [child]
  let visited : Array[EntityId] = []
  let mut i = 0
  while i < pending.length() {
    let current = pending[i]
    i += 1
    if current == ancestor {
      return true
    }
    if visited.contains(current) {
      continue
    }
    visited.push(current)
    match find_entity(entities, current) {
      Some(entity) =>
        for parent in entity.parents {
          if !pending.contains(parent) {
            pending.push(parent)
          }
        }
      None => ()
    }
  }
  false
}

///|
fn attribute(
  value : Value,
  name : String,
  entities : Array[Entity],
) -> Value? raise PolicyError {
  match value {
    RecordValue(fields) => fields.get(name)
    EntityValue(uid) =>
      match find_entity(entities, uid) {
        Some(entity) => entity.attrs.get(name)
        None => None
      }
    _ => raise PolicyError("attribute access requires an entity or record")
  }
}

///|
fn boolean(value : Value) -> Bool raise PolicyError {
  match value {
    BoolValue(b) => b
    _ => raise PolicyError("expected boolean")
  }
}

///|
fn evaluate(
  expr : Expr,
  request : Request,
  entities : Array[Entity],
) -> Value raise PolicyError {
  match expr {
    Literal(value) => value
    Variable("principal") => EntityValue(request.principal)
    Variable("action") => EntityValue(request.action)
    Variable("resource") => EntityValue(request.resource)
    Variable("context") => RecordValue(request.context)
    Variable(_) => raise PolicyError("unknown variable")
    IsType(value, kind) =>
      match evaluate(value, request, entities) {
        EntityValue(uid) => BoolValue(uid.kind == kind)
        _ => raise PolicyError("is requires an entity value")
      }
    Conditional(condition, when_true, when_false) =>
      if boolean(evaluate(condition, request, entities)) {
        evaluate(when_true, request, entities)
      } else {
        evaluate(when_false, request, entities)
      }
    Attribute(base, name) =>
      match attribute(evaluate(base, request, entities), name, entities) {
        Some(value) => value
        None => raise PolicyError("missing attribute '\{name}'")
      }
    Has(base, name) =>
      BoolValue(
        attribute(evaluate(base, request, entities), name, entities) is Some(_),
      )
    Not(inner) => BoolValue(!boolean(evaluate(inner, request, entities)))
    And(left, right) => {
      let first = boolean(evaluate(left, request, entities))
      if first {
        BoolValue(boolean(evaluate(right, request, entities)))
      } else {
        BoolValue(false)
      }
    }
    Or(left, right) => {
      let first = boolean(evaluate(left, request, entities))
      if first {
        BoolValue(true)
      } else {
        BoolValue(boolean(evaluate(right, request, entities)))
      }
    }
    Equal(left, right) =>
      BoolValue(
        same_value(
          evaluate(left, request, entities),
          evaluate(right, request, entities),
        ),
      )
    Compare(left, op, right) => {
      let l = evaluate(left, request, entities)
      let r = evaluate(right, request, entities)
      match (l, r) {
        (LongValue(a), LongValue(b)) =>
          BoolValue(
            match op {
              Less => a < b
              LessEqual => a <= b
              Greater => a > b
              GreaterEqual => a >= b
            },
          )
        _ => raise PolicyError("ordering requires signed 64-bit integers")
      }
    }
    SetCall(receiver, op, argument) => {
      let value = evaluate(receiver, request, entities)
      let arg = match argument {
        Some(expression) => Some(evaluate(expression, request, entities))
        None => None
      }
      match (value, op, arg) {
        (SetValue(values), IsEmpty, None) => BoolValue(values.is_empty())
        (SetValue(values), Contains, Some(needle)) =>
          BoolValue(values.any(fn(item) { same_value(item, needle) }))
        (SetValue(values), ContainsAll, Some(SetValue(needles))) =>
          BoolValue(
            needles.all(fn(needle) {
              values.any(fn(item) { same_value(item, needle) })
            }),
          )
        (SetValue(values), ContainsAny, Some(SetValue(needles))) =>
          BoolValue(
            needles.any(fn(needle) {
              values.any(fn(item) { same_value(item, needle) })
            }),
          )
        _ => raise PolicyError("set method received incompatible operand types")
      }
    }
    In(left, right) => {
      let l = evaluate(left, request, entities)
      let r = evaluate(right, request, entities)
      match (l, r) {
        (EntityValue(child), EntityValue(parent)) =>
          BoolValue(is_descendant(entities, child, parent))
        (EntityValue(child), SetValue(parents)) => {
          let mut found = false
          for item in parents {
            match item {
              EntityValue(parent) =>
                if is_descendant(entities, child, parent) {
                  found = true
                }
              _ =>
                raise PolicyError(
                  "entity membership requires entity references",
                )
            }
          }
          BoolValue(found)
        }
        _ =>
          raise PolicyError(
            "in requires an entity and entity or set of entities",
          )
      }
    }
    SetExpr(items) => {
      let values = []
      for item in items {
        values.push(evaluate(item, request, entities))
      }
      SetValue(values)
    }
    RecordExpr(fields) => {
      let values : Map[String, Value] = Map([])
      for field in fields {
        let (key, item) = field
        if values.contains(key) {
          raise PolicyError("duplicate record field '\{key}'")
        }
        values[key] = evaluate(item, request, entities)
      }
      RecordValue(values)
    }
  }
}

///|
pub fn authorize(
  policies : PolicySet,
  request : Request,
  entities : Array[Entity],
) -> Response raise PolicyError {
  if entities.length() > 4096 {
    raise PolicyError("entity limit exceeded")
  }
  let mut edges = 0
  let seen : Array[EntityId] = []
  for entity in entities {
    if seen.contains(entity.uid) {
      raise PolicyError("duplicate entity")
    }
    seen.push(entity.uid)
    edges += entity.parents.length()
    if edges > 65536 {
      raise PolicyError("entity parent limit exceeded")
    }
  }
  let permits = []
  let forbids = []
  let errors = []
  for policy in policies.policies {
    let matched = boolean(evaluate(policy.condition, request, entities)) catch {
      PolicyError(message) => {
        errors.push({ policy_id: policy.id, message, })
        false
      }
    }
    if matched {
      if policy.forbid {
        forbids.push(policy.id)
      } else {
        permits.push(policy.id)
      }
    }
  }
  if !forbids.is_empty() {
    { decision: Deny, reasons: forbids, errors, }
  } else if !permits.is_empty() {
    { decision: Allow, reasons: permits, errors, }
  } else {
    { decision: Deny, reasons: [], errors, }
  }
}
