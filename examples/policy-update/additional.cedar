@id("emergency") forbid(principal, action, resource is File)
when { context has emergency && context.emergency };
