@id("direct") permit(principal == ?principal, action == Action::"read", resource == ?resource)
when { context.authenticated && context.mfa };
