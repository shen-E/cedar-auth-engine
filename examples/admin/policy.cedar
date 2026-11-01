permit(principal in Role::"admin", action == Action::"delete", resource)
when { context.mfa && resource.owner == principal };
forbid(principal, action, resource)
when { resource.locked };
