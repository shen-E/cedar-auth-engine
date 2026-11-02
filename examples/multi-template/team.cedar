@id("team") permit(principal in ?principal, action == Action::"read", resource in ?resource) when { context.authenticated };
