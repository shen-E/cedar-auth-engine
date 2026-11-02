@id("revoked") forbid(principal, action, resource is File)
when { resource.revoked };

@id("blocked") forbid(principal, action, resource)
when { context has blocked && context.blocked };
