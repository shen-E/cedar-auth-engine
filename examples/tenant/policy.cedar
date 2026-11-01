// Read documents owned by the same tenant, except suspended principals.
permit(principal, action == Action::"read", resource)
when { principal.tenant == resource.tenant && context.authenticated };
forbid(principal, action, resource)
when { principal.suspended == true };
