// Services accept authenticated requests from their configured network.
@id("network-permit")
@owner("platform-security")
permit(principal is User, action == Action::"connect", resource is Service)
when {
  context.mfa && context.sourceIp.isInRange(resource.allowedNetwork)
};

@id("suspension")
forbid(principal, action, resource)
when { principal.suspended };

// Loopback and multicast are not accepted as client source addresses.
@id("special-source")
forbid(principal, action == Action::"connect", resource)
when { context.sourceIp.isLoopback() || context.sourceIp.isMulticast() };
