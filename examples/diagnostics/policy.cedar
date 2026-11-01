@id("department-read")
permit(principal is User, action == Action::"read", resource is Report)
when { principal.department == resource.department };

@id("suspended")
forbid(principal, action, resource)
when { principal.suspended };
