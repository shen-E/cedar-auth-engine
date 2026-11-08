///|
fn print_comparison_summary(
  summary : @engine.ComparisonSummary,
  json : Bool,
) -> Unit {
  if json {
    let report : Json = {
      "total": summary.total,
      "changed": summary.changed,
      "decisions_changed": summary.decisions_changed,
      "enforcement_changed": summary.enforcement_changed,
      "reasons_changed": summary.reasons_changed,
      "errors_changed": summary.errors_changed,
      "decision_grants": summary.decision_grants,
      "decision_revocations": summary.decision_revocations,
      "enforcement_grants": summary.enforcement_grants,
      "enforcement_revocations": summary.enforcement_revocations,
      "after_error_requests": summary.after_error_requests,
    }
    println(report.stringify())
  } else {
    println(
      "\{summary.changed}/\{summary.total} changed; decision=\{summary.decisions_changed} (grants=\{summary.decision_grants}, revocations=\{summary.decision_revocations}), enforcement=\{summary.enforcement_changed} (grants=\{summary.enforcement_grants}, revocations=\{summary.enforcement_revocations}), reasons=\{summary.reasons_changed}, errors=\{summary.errors_changed}, after errors=\{summary.after_error_requests}",
    )
  }
}
