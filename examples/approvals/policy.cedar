@id("within-limit")
permit(principal in Group::"finance", action == Action::"approve", resource is Invoice)
when { context.amount.lessThanOrEqual(principal.approval_limit) && resource.currency == context.currency };

@id("negative-amount")
forbid(principal, action == Action::"approve", resource is Invoice)
when { context.amount.lessThan(decimal("0.0")) };
