// A user may read tagged documents from their tenant and clearance group.
@id("tenant-read")
permit(principal is User, action == Action::"read", resource is Document)
when {
  resource.hasTag("tenant") && resource.getTag("tenant") == principal.tenant &&
  resource.hasTag(principal.clearanceKey) && resource.getTag(principal.clearanceKey) == true
};

// Quarantined documents stay blocked even when the user has clearance.
@id("quarantined")
forbid(principal, action, resource)
when { resource.hasTag("quarantined") && resource.getTag("quarantined") == true };
