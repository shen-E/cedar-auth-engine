///|
fn print_authorization_summary(
  summary : @engine.AuthorizationSummary,
  json : Bool,
) -> Unit {
  if json {
    let report : Json = {
      "total": summary.total,
      "cedar_allowed": summary.cedar_allowed,
      "cedar_denied": summary.cedar_denied,
      "error_requests": summary.error_requests,
      "enforcement_allowed": summary.enforcement_allowed,
      "enforcement_denied": summary.enforcement_denied,
    }
    println(report.stringify())
  } else {
    println(
      "\{summary.total} requests; Cedar allow=\{summary.cedar_allowed}, deny=\{summary.cedar_denied}, errors=\{summary.error_requests}; enforcement allow=\{summary.enforcement_allowed}, deny=\{summary.enforcement_denied}",
    )
  }
}
