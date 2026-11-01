// Read access requires a managed device with an acceptable risk score.
@id("device-access")
permit(principal is User, action == Action::"read", resource is Service)
when {
  principal.tenant == resource.tenant &&
  context has device.posture.managed && context.device.posture.managed &&
  context has device.posture.risk && context.device.posture.risk <= resource.maxRisk
};

@id("suspended")
forbid(principal, action, resource)
when { principal.suspended };
