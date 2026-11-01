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
fn find_entity(graph : EntityGraph, uid : EntityId) -> TaggedEntity? {
  match graph.index.get(entity_key(uid)) {
    Some(i) => Some(graph.entities[i])
    None => None
  }
}

///|
fn is_descendant(
  graph : EntityGraph,
  child : EntityId,
  ancestor : EntityId,
) -> Bool {
  let pending = [child]
  let visited : Map[String, Bool] = Map([])
  visited[entity_key(child)] = true
  let mut i = 0
  while i < pending.length() {
    let current = pending[i]
    i += 1
    if current == ancestor {
      return true
    }
    match find_entity(graph, current) {
      Some(entity) =>
        for parent in entity.entity.parents {
          let key = entity_key(parent)
          if !visited.contains(key) {
            visited[key] = true
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
  entities : EntityGraph,
) -> Value? raise PolicyError {
  match value {
    RecordValue(fields) => fields.get(name)
    EntityValue(uid) =>
      match find_entity(entities, uid) {
        Some(entity) => entity.entity.attrs.get(name)
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
  entities : EntityGraph,
) -> Value raise PolicyError {
  match expr {
    Literal(value) => value
    Variable("principal") => EntityValue(request.principal)
    Variable("action") => EntityValue(request.action)
    Variable("resource") => EntityValue(request.resource)
    Variable("context") => RecordValue(request.context)
    Variable(_) => raise PolicyError("unknown variable")
    Like(value, pattern) =>
      match evaluate(value, request, entities) {
        StringValue(text) => BoolValue(match_pattern(text, pattern))
        _ => raise PolicyError("like requires a string value")
      }
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
    HasPath(base, path) => {
      let mut current = evaluate(base, request, entities)
      for name in path {
        match attribute(current, name, entities) {
          Some(value) => current = value
          None => return BoolValue(false)
        }
      }
      BoolValue(true)
    }
    Not(inner) => BoolValue(!boolean(evaluate(inner, request, entities)))
    Negate(inner) =>
      match evaluate(inner, request, entities) {
        LongValue(value) => LongValue(checked_arithmetic(0L, Subtract, value))
        _ => raise PolicyError("arithmetic requires signed 64-bit integers")
      }
    Arithmetic(left, op, right) => {
      let l = evaluate(left, request, entities)
      let r = evaluate(right, request, entities)
      match (l, r) {
        (LongValue(a), LongValue(b)) => LongValue(checked_arithmetic(a, op, b))
        _ => raise PolicyError("arithmetic requires signed 64-bit integers")
      }
    }
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
    TagCall(receiver, presence, key) => {
      let value = evaluate(receiver, request, entities)
      let name = evaluate(key, request, entities)
      match (value, name) {
        (EntityValue(uid), StringValue(tag)) => {
          let found = match find_entity(entities, uid) {
            Some(entity) => entity.tags.get(tag)
            None => None
          }
          if presence {
            BoolValue(found is Some(_))
          } else {
            match found {
              Some(tag_value) => tag_value
              None => raise PolicyError("missing tag '\{tag}'")
            }
          }
        }
        _ => raise PolicyError("tag access requires an entity and a string key")
      }
    }
    IpConstructor(argument) =>
      match evaluate(argument, request, entities) {
        StringValue(text) => IpValue(IpAddress::parse(text))
        _ => raise PolicyError("ip requires a string value")
      }
    IpCall(receiver, op, argument) => {
      let value = evaluate(receiver, request, entities)
      let arg = match argument {
        Some(expression) => Some(evaluate(expression, request, entities))
        None => None
      }
      match (value, op, arg) {
        (IpValue(ip), IsIpv4, None) => BoolValue(ip.version == 4)
        (IpValue(ip), IsIpv6, None) => BoolValue(ip.version == 6)
        (IpValue(ip), IsLoopback, None) => BoolValue(ip_loopback(ip))
        (IpValue(ip), IsMulticast, None) => BoolValue(ip_multicast(ip))
        (IpValue(ip), IsInRange, Some(IpValue(range))) =>
          BoolValue(ip_in_range(ip, range))
        _ => raise PolicyError("IP method received incompatible operand types")
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
/// Authorize a request against entities without tags.
pub fn authorize(
  policies : PolicySet,
  request : Request,
  entities : Array[Entity],
) -> Response raise PolicyError {
  if entities.length() > 4096 {
    raise PolicyError("entity limit exceeded")
  }
  let tagged = []
  for entity in entities {
    tagged.push({ entity, tags: {}, })
  }
  authorize_with_tags(policies, request, tagged)
}

///|
/// Authorize a request against entities and their tags.
pub fn authorize_with_tags(
  policies : PolicySet,
  request : Request,
  entities : Array[TaggedEntity],
) -> Response raise PolicyError {
  let graph = build_entity_graph(entities)
  authorize_in_graph(policies, request, graph)
}

///|
/// Authorize up to 4,096 requests against entities without tags.
pub fn authorize_batch(
  policies : PolicySet,
  requests : Array[Request],
  entities : Array[Entity],
) -> Array[Response] raise PolicyError {
  if requests.length() > 4096 {
    raise PolicyError("request batch limit exceeded")
  }
  if entities.length() > 4096 {
    raise PolicyError("entity limit exceeded")
  }
  let tagged = []
  for entity in entities {
    tagged.push({ entity, tags: {}, })
  }
  authorize_batch_with_tags(policies, requests, tagged)
}

///|
/// Authorize up to 4,096 requests using one validated entity graph.
pub fn authorize_batch_with_tags(
  policies : PolicySet,
  requests : Array[Request],
  entities : Array[TaggedEntity],
) -> Array[Response] raise PolicyError {
  if requests.length() > 4096 {
    raise PolicyError("request batch limit exceeded")
  }
  let graph = build_entity_graph(entities)
  let responses = []
  for request in requests {
    responses.push(authorize_in_graph(policies, request, graph))
  }
  responses
}

///|
fn authorize_in_graph(
  policies : PolicySet,
  request : Request,
  graph : EntityGraph,
) -> Response {
  let permits = []
  let forbids = []
  let errors = []
  for policy in policies.policies {
    let matched = boolean(evaluate(policy.condition, request, graph)) catch {
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
