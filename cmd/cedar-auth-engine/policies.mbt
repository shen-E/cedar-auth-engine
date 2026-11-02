///|
priv struct PolicyInputs {
  templates : Array[String]
  links : Array[String]
  additions : Array[String]
  replacements : Array[String]
  removals : Array[String]
}

///|
fn policy_inputs() -> PolicyInputs {
  { templates: [], links: [], additions: [], replacements: [], removals: [], }
}

///|
fn PolicyInputs::validate(self : PolicyInputs) -> Unit raise CliError {
  if self.templates.length() != self.links.length() {
    raise CliError("--template and --links counts must match")
  }
  if self.templates.length() > 1024 {
    raise CliError("template pair limit exceeded")
  }
  if self.additions.length() > 1024 || self.replacements.length() > 1024 {
    raise CliError("policy file limit exceeded")
  }
  if self.removals.length() > 1024 {
    raise CliError("policy removal limit exceeded")
  }
}

///|
fn PolicyInputs::load(
  self : PolicyInputs,
  path : String,
) -> @engine.PolicySet raise {
  self.validate()
  let mut policies = @engine.parse_policies(read_text(path))
  for file in self.additions {
    policies = policies.merge(@engine.parse_policies(read_text(file)))
  }
  for i in 0..<self.templates.length() {
    policies = apply_template(policies, self.templates[i], self.links[i])
  }
  for file in self.replacements {
    policies = policies.replace(@engine.parse_policies(read_text(file)))
  }
  policies.remove_batch(self.removals)
}
