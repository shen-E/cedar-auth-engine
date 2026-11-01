// Billing reviewers can read documents whose names follow the invoice convention.
permit(principal in Group::"billing", action == Action::"read", resource is Document)
when { resource.name like "invoice-*.pdf" };
