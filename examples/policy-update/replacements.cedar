@id("revoked") forbid(principal, action, resource is File)
when { resource.revoked && !(context has override && context.override) };

@id("alice-report") permit(principal == User::"alice", action == Action::"read", resource == File::"report")
when { context.authenticated && context.mfa };
