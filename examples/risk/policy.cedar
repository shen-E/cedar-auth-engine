// Review requires a reviewer role, a permitted department and a low risk score.
permit(principal, action == Action::"review", resource)
when {
  principal.roles.contains("reviewer") &&
  principal.departments.containsAny(resource.departments) &&
  context.risk <= resource.maxRisk
};

// Suspension applies even when the reviewer would otherwise be permitted.
forbid(principal, action, resource)
when { principal.roles.contains("suspended") };
