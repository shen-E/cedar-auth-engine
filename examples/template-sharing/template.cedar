@id("share") @owner("sharing") permit(principal == ?principal, action in [Action::"read", Action::"comment"], resource == ?resource) when { context.authenticated };
