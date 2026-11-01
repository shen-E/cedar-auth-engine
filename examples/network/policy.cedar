// Services accept authenticated requests from their configured network.
permit(principal is User, action == Action::"connect", resource is Service)
when {
  context.mfa && context.sourceIp.isInRange(resource.allowedNetwork)
};

forbid(principal, action, resource)
when { principal.suspended };
