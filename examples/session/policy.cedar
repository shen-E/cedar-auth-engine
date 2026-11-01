@id("active-session")
permit(principal in Group::"employees", action == Action::"view", resource is Dashboard)
when { context.session_age <= principal.max_session };

@id("invalid-session-age")
forbid(principal, action, resource)
when { context.session_age < duration("0ms") };
