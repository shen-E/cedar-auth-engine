// Members may download files within their remaining allowance.
permit(principal, action == Action::"download", resource is File)
when {
  principal.roles.contains("member") &&
  context.used >= 0 && resource.size >= 0 &&
  context.used + resource.size <= principal.quota
};

// Suspension overrides an otherwise permitted download.
forbid(principal, action, resource)
when { principal.roles.contains("suspended") };
