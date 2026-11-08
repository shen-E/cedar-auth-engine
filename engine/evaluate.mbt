///|
// A comparison budget is shared by all equality operations in one policy.
fn same_value(
  a : Value,
  b : Value,
  budget : Ref[Int32],
  depth : Int32,
) -> Bool raise PolicyError {
  if depth > 128 {
    raise PolicyError("value comparison nesting limit exceeded")
  }
  if budget.val <= 0 {
    raise PolicyError("value comparison budget exceeded")
  }
  budget.val -= 1
  match (a, b) {
    (SetValue(xs), SetValue(ys)) => {
      let covered = Array::make(ys.length(), false)
      for x in xs {
        let mut found = false
        for i in 0..<ys.length() {
          if same_value(x, ys[i], budget, depth + 1) {
            covered[i] = true
            found = true
            break
          }
        }
        if !found {
          return false
        }
      }
      for i in 0..<ys.length() {
        if !covered[i] && !set_contains(xs, ys[i], budget, depth + 1) {
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
          Some(other) =>
            if !same_value(value, other, budget, depth + 1) {
              return false
            }
          None => return false
        }
      }
      true
    }
    _ => a == b
  }
}

///|
fn set_contains(
  values : Array[Value],
  needle : Value,
  budget : Ref[Int32],
  depth : Int32,
) -> Bool raise PolicyError {
  for item in values {
    if same_value(item, needle, budget, depth) {
      return true
    }
  }
  false
}

///|
fn set_contains_all(
  values : Array[Value],
  needles : Array[Value],
  budget : Ref[Int32],
) -> Bool raise PolicyError {
  for needle in needles {
    if !set_contains(values, needle, budget, 0) {
      return false
    }
  }
  true
}

///|
fn set_contains_any(
  values : Array[Value],
  needles : Array[Value],
  budget : Ref[Int32],
) -> Bool raise PolicyError {
  for needle in needles {
    if set_contains(values, needle, budget, 0) {
      return true
    }
  }
  false
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
fn compare_long(a : Int64, op : CompareOp, b : Int64) -> Bool {
  match op {
    Less => a < b
    LessEqual => a <= b
    Greater => a > b
    GreaterEqual => a >= b
  }
}

///|
fn evaluate(
  expr : Expr,
  request : Request,
  entities : EvaluationContext,
  budget : Ref[Int32],
) -> Value raise PolicyError {
  match expr {
    Literal(value) => value
    Variable("principal") => EntityValue(request.principal)
    Variable("action") => EntityValue(request.action)
    Variable("resource") => EntityValue(request.resource)
    Variable("context") => RecordValue(request.context)
    Variable(_) => raise PolicyError("unknown variable")
    Slot(_) => raise PolicyError("unbound template slot")
    Like(value, pattern) =>
      match evaluate(value, request, entities, budget) {
        StringValue(text) => BoolValue(match_pattern(text, pattern))
        _ => raise PolicyError("like requires a string value")
      }
    IsType(value, kind) =>
      match evaluate(value, request, entities, budget) {
        EntityValue(uid) => BoolValue(uid.kind == kind)
        _ => raise PolicyError("is requires an entity value")
      }
    Conditional(condition, when_true, when_false) =>
      if boolean(evaluate(condition, request, entities, budget)) {
        evaluate(when_true, request, entities, budget)
      } else {
        evaluate(when_false, request, entities, budget)
      }
    Attribute(base, name) =>
      match
        attribute(
          evaluate(base, request, entities, budget),
          name,
          entities.graph,
        ) {
        Some(value) => value
        None => raise PolicyError("missing attribute '\{name}'")
      }
    HasPath(base, path) => {
      let mut current = evaluate(base, request, entities, budget)
      for name in path {
        match attribute(current, name, entities.graph) {
          Some(value) => current = value
          None => return BoolValue(false)
        }
      }
      BoolValue(true)
    }
    Not(inner) =>
      BoolValue(!boolean(evaluate(inner, request, entities, budget)))
    Negate(inner) =>
      match evaluate(inner, request, entities, budget) {
        LongValue(value) => LongValue(checked_arithmetic(0L, Subtract, value))
        _ => raise PolicyError("arithmetic requires signed 64-bit integers")
      }
    Arithmetic(left, op, right) => {
      let l = evaluate(left, request, entities, budget)
      let r = evaluate(right, request, entities, budget)
      match (l, r) {
        (LongValue(a), LongValue(b)) => LongValue(checked_arithmetic(a, op, b))
        _ => raise PolicyError("arithmetic requires signed 64-bit integers")
      }
    }
    And(left, right) => {
      let first = boolean(evaluate(left, request, entities, budget))
      if first {
        BoolValue(boolean(evaluate(right, request, entities, budget)))
      } else {
        BoolValue(false)
      }
    }
    Or(left, right) => {
      let first = boolean(evaluate(left, request, entities, budget))
      if first {
        BoolValue(true)
      } else {
        BoolValue(boolean(evaluate(right, request, entities, budget)))
      }
    }
    Equal(left, right) =>
      BoolValue(
        same_value(
          evaluate(left, request, entities, budget),
          evaluate(right, request, entities, budget),
          budget,
          0,
        ),
      )
    Compare(left, op, right) => {
      let l = evaluate(left, request, entities, budget)
      let r = evaluate(right, request, entities, budget)
      match (l, r) {
        (LongValue(a), LongValue(b)) => BoolValue(compare_long(a, op, b))
        (DurationValue(a), DurationValue(b)) =>
          BoolValue(compare_long(a.milliseconds, op, b.milliseconds))
        (DateTimeValue(a), DateTimeValue(b)) =>
          BoolValue(compare_long(a.milliseconds, op, b.milliseconds))
        _ => raise PolicyError("ordering requires compatible operand types")
      }
    }
    TagCall(receiver, presence, key) => {
      let value = evaluate(receiver, request, entities, budget)
      let name = evaluate(key, request, entities, budget)
      match (value, name) {
        (EntityValue(uid), StringValue(tag)) => {
          let found = match find_entity(entities.graph, uid) {
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
    DateTimeConstructor(argument) =>
      match evaluate(argument, request, entities, budget) {
        StringValue(text) => DateTimeValue(DateTime::parse(text))
        _ => raise PolicyError("datetime requires a string value")
      }
    DateTimeCall(receiver, operation, argument) => {
      let value = evaluate(receiver, request, entities, budget)
      let arg = match argument {
        Some(expression) =>
          Some(evaluate(expression, request, entities, budget))
        None => None
      }
      match (value, operation, arg) {
        (DateTimeValue(dt), Offset, Some(DurationValue(duration))) =>
          DateTimeValue({
            milliseconds: checked_arithmetic(
              dt.milliseconds,
              Add,
              duration.milliseconds,
            ),
          })
        (DateTimeValue(dt), DurationSince, Some(DateTimeValue(other))) =>
          DurationValue({
            milliseconds: checked_arithmetic(
              dt.milliseconds,
              Subtract,
              other.milliseconds,
            ),
          })
        (DateTimeValue(dt), ToDate, None) =>
          DateTimeValue({
            milliseconds: checked_arithmetic(
              dt.milliseconds,
              Subtract,
              datetime_time(dt.milliseconds),
            ),
          })
        (DateTimeValue(dt), ToTime, None) =>
          DurationValue({ milliseconds: datetime_time(dt.milliseconds), })
        _ =>
          raise PolicyError(
            "datetime method received incompatible operand types",
          )
      }
    }
    DurationConstructor(argument) =>
      match evaluate(argument, request, entities, budget) {
        StringValue(text) => DurationValue(Duration::parse(text))
        _ => raise PolicyError("duration requires a string value")
      }
    DurationCall(receiver, divisor) =>
      match evaluate(receiver, request, entities, budget) {
        DurationValue(duration) => LongValue(duration.milliseconds / divisor)
        _ => raise PolicyError("duration conversion requires a duration")
      }
    DecimalConstructor(argument) =>
      match evaluate(argument, request, entities, budget) {
        StringValue(text) => DecimalValue(Decimal::parse(text))
        _ => raise PolicyError("decimal requires a string value")
      }
    DecimalCall(receiver, operation, argument) => {
      let left = evaluate(receiver, request, entities, budget)
      let right = evaluate(argument, request, entities, budget)
      match (left, right) {
        (DecimalValue(a), DecimalValue(b)) =>
          BoolValue(
            match operation {
              Less => a.scaled < b.scaled
              LessEqual => a.scaled <= b.scaled
              Greater => a.scaled > b.scaled
              GreaterEqual => a.scaled >= b.scaled
            },
          )
        _ => raise PolicyError("decimal comparison requires decimal values")
      }
    }
    IpConstructor(argument) =>
      match evaluate(argument, request, entities, budget) {
        StringValue(text) => IpValue(IpAddress::parse(text))
        _ => raise PolicyError("ip requires a string value")
      }
    IpCall(receiver, op, argument) => {
      let value = evaluate(receiver, request, entities, budget)
      let arg = match argument {
        Some(expression) =>
          Some(evaluate(expression, request, entities, budget))
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
      let value = evaluate(receiver, request, entities, budget)
      let arg = match argument {
        Some(expression) =>
          Some(evaluate(expression, request, entities, budget))
        None => None
      }
      match (value, op, arg) {
        (SetValue(values), IsEmpty, None) => BoolValue(values.is_empty())
        (SetValue(values), Contains, Some(needle)) =>
          BoolValue(set_contains(values, needle, budget, 0))
        (SetValue(values), ContainsAll, Some(SetValue(needles))) =>
          BoolValue(set_contains_all(values, needles, budget))
        (SetValue(values), ContainsAny, Some(SetValue(needles))) =>
          BoolValue(set_contains_any(values, needles, budget))
        _ => raise PolicyError("set method received incompatible operand types")
      }
    }
    In(left, right) => {
      let l = evaluate(left, request, entities, budget)
      let r = evaluate(right, request, entities, budget)
      match (l, r) {
        (EntityValue(child), EntityValue(parent)) =>
          BoolValue(entities.is_descendant(child, parent))
        (EntityValue(child), SetValue(parents)) => {
          let mut found = false
          for item in parents {
            match item {
              EntityValue(parent) =>
                if entities.is_descendant(child, parent) {
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
        values.push(evaluate(item, request, entities, budget))
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
        values[key] = evaluate(item, request, entities, budget)
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
  if entities.length() > 16384 {
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
/// Authorize up to 32,768 requests against entities without tags.
pub fn authorize_batch(
  policies : PolicySet,
  requests : Array[Request],
  entities : Array[Entity],
) -> Array[Response] raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  if entities.length() > 16384 {
    raise PolicyError("entity limit exceeded")
  }
  let tagged = []
  for entity in entities {
    tagged.push({ entity, tags: {}, })
  }
  authorize_batch_with_tags(policies, requests, tagged)
}

///|
/// Authorize up to 32,768 requests using one validated entity graph.
pub fn authorize_batch_with_tags(
  policies : PolicySet,
  requests : Array[Request],
  entities : Array[TaggedEntity],
) -> Array[Response] raise PolicyError {
  if requests.length() > 32768 {
    raise PolicyError("request batch limit exceeded")
  }
  let graph = build_entity_graph(entities)
  let context = EvaluationContext::new(graph)
  let responses = []
  for request in requests {
    responses.push(authorize_in_context(policies, request, context))
  }
  responses
}

///|
fn authorize_in_graph(
  policies : PolicySet,
  request : Request,
  graph : EntityGraph,
) -> Response {
  authorize_in_context(policies, request, EvaluationContext::new(graph))
}

///|
fn authorize_in_context(
  policies : PolicySet,
  request : Request,
  context : EvaluationContext,
) -> Response {
  authorize_selected(policies, request, context, true)
}

///|
// The scan variant is also used by differential tests.
fn authorize_selected(
  policies : PolicySet,
  request : Request,
  context : EvaluationContext,
  indexed : Bool,
) -> Response {
  let permits = []
  let forbids = []
  let errors = []
  let actions = policies.action_index
    .get(entity_key(request.action))
    .unwrap_or([])
  let principals = policies.principal_index
    .get(entity_key(request.principal))
    .unwrap_or([])
  let resources = policies.resource_index
    .get(entity_key(request.resource))
    .unwrap_or([])
  let use_index = indexed &&
    actions.length() + principals.length() + resources.length() <
    policies.policies.length()
  let mut fallback_pos = 0
  let mut action_pos = 0
  let mut principal_pos = 0
  let mut resource_pos = 0
  let mut scan_pos = 0
  while (if use_index {
          fallback_pos < policies.fallback.length() ||
          action_pos < actions.length() ||
          principal_pos < principals.length() ||
          resource_pos < resources.length()
        } else {
          scan_pos < policies.policies.length()
        }) {
    let position = if !use_index {
      let next = scan_pos
      scan_pos += 1
      next
    } else {
      let mut next = policies.policies.length()
      if fallback_pos < policies.fallback.length() {
        next = policies.fallback[fallback_pos]
      }
      if action_pos < actions.length() && actions[action_pos] < next {
        next = actions[action_pos]
      }
      if principal_pos < principals.length() && principals[principal_pos] < next {
        next = principals[principal_pos]
      }
      if resource_pos < resources.length() && resources[resource_pos] < next {
        next = resources[resource_pos]
      }
      if fallback_pos < policies.fallback.length() &&
        policies.fallback[fallback_pos] == next {
        fallback_pos += 1
      } else if action_pos < actions.length() && actions[action_pos] == next {
        action_pos += 1
      } else if principal_pos < principals.length() &&
        principals[principal_pos] == next {
        principal_pos += 1
      } else {
        resource_pos += 1
      }
      next
    }
    let policy = policies.policies[position]
    let budget = Ref(1000000)
    let matched = boolean(evaluate(policy.condition, request, context, budget)) catch {
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
