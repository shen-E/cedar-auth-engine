// Only documents with a declared classification can be read.
// Confidential documents additionally require MFA.
permit(principal is User, action == Action::"read", resource is Document)
when {
  resource has "security level" &&
  (if resource["security level"] == "confidential" then context.mfa else true)
};
