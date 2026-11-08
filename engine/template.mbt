///|
/// One parsed Cedar policy template with principal and/or resource slots.
pub struct PolicyTemplate {
  priv policy : Policy
  priv principal_slot : Bool
  priv resource_slot : Bool
}

///|
/// Values supplied for the template slots. Unused slots must be absent.
pub(all) struct TemplateBindings {
  principal : EntityId?
  resource : EntityId?
}

///|
/// A policy ID and the values to bind to one template.
pub(all) struct TemplateLink {
  id : String
  bindings : TemplateBindings
}

///|
/// Parse exactly one policy template containing at least one supported slot.
pub fn parse_template(text : String) -> PolicyTemplate raise PolicyError {
  let (set, principal_slot, resource_slot) = parse_policy_data(text, true)
  if set.policies.length() != 1 {
    raise PolicyError("expected exactly one policy template")
  }
  if !principal_slot && !resource_slot {
    raise PolicyError("template must contain a slot")
  }
  { policy: set.policies[0], principal_slot, resource_slot, }
}

///|
/// Return required slot names in principal, resource order.
pub fn PolicyTemplate::slots(self : PolicyTemplate) -> Array[String] {
  let slots = []
  if self.principal_slot {
    slots.push("principal")
  }
  if self.resource_slot {
    slots.push("resource")
  }
  slots
}

///|
// Slots are accepted only in scope operands. Those operands are reached through
// the And, Equal, and In nodes created by the scope parser.
fn bind_scope_slots(
  expr : Expr,
  bindings : TemplateBindings,
) -> Expr raise PolicyError {
  match expr {
    Slot("principal") =>
      match bindings.principal {
        Some(uid) => Literal(EntityValue(uid))
        None => raise PolicyError("missing principal slot")
      }
    Slot("resource") =>
      match bindings.resource {
        Some(uid) => Literal(EntityValue(uid))
        None => raise PolicyError("missing resource slot")
      }
    Slot(_) => raise PolicyError("invalid template slot")
    And(left, right) =>
      And(bind_scope_slots(left, bindings), bind_scope_slots(right, bindings))
    Equal(left, right) =>
      Equal(bind_scope_slots(left, bindings), bind_scope_slots(right, bindings))
    In(left, right) =>
      In(bind_scope_slots(left, bindings), bind_scope_slots(right, bindings))
    _ => expr
  }
}

///|
/// Return a new policy set with one template link under the supplied policy ID.
pub fn PolicySet::link(
  self : PolicySet,
  template : PolicyTemplate,
  id : String,
  bindings : TemplateBindings,
) -> PolicySet raise PolicyError {
  self.link_batch(template, [{ id, bindings, }])
}

///|
/// Return a new policy set containing all links, or an error without changes.
pub fn PolicySet::link_batch(
  self : PolicySet,
  template : PolicyTemplate,
  links : Array[TemplateLink],
) -> PolicySet raise PolicyError {
  if links.length() > 4096 - self.policies.length() {
    raise PolicyError("policy count limit exceeded")
  }
  let seen : Map[String, Bool] = Map([])
  for policy in self.policies {
    seen[policy.id] = true
  }
  for link in links {
    let bindings = link.bindings
    if template.principal_slot != (bindings.principal is Some(_)) ||
      template.resource_slot != (bindings.resource is Some(_)) {
      raise PolicyError("template bindings must match required slots")
    }
    match bindings.principal {
      Some(uid) => uid.validate()
      None => ()
    }
    match bindings.resource {
      Some(uid) => uid.validate()
      None => ()
    }
    if seen.contains(link.id) {
      raise PolicyError("duplicate policy id '\{link.id}'")
    }
    seen[link.id] = true
  }
  let policies = self.policies.copy()
  for link in links {
    policies.push({
      id: link.id,
      forbid: template.policy.forbid,
      condition: bind_scope_slots(template.policy.condition, link.bindings),
      annotations: template.policy.annotations,
      action_key: template.policy.action_key,
      principal_scope: bind_scope_slots(
        template.policy.principal_scope,
        link.bindings,
      ),
      action_scope: template.policy.action_scope,
      resource_expression: bind_scope_slots(
        template.policy.resource_expression,
        link.bindings,
      ),
      clauses: template.policy.clauses.copy(),
      resource_scope: match template.policy.resource_scope {
        Some(scope) => Some(bind_scope_slots(scope, link.bindings))
        None => None
      },
    })
  }
  make_policy_set(policies)
}
