@id("within-window")
permit(principal in Group::"employees", action == Action::"read", resource is Document)
when { context.now >= resource.opens && context.now < resource.closes };

@id("revoked")
forbid(principal, action == Action::"read", resource is Document)
when { resource.revoked };
