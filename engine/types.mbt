///|
pub suberror PolicyError {
  PolicyError(String)
} derive(Debug)

///|
pub impl Show for PolicyError with fn output(self, logger) {
  let PolicyError(message) = self
  logger.write_string(message)
}

///|
pub extend PolicyError with Show::{output, to_string}

///|
pub extend PolicyError with Debug::{to_repr}

///|
pub(all) struct EntityId {
  kind : String
  id : String
} derive(Eq, Debug)

///|
pub extend EntityId with Eq::{equal, not_equal}

///|
pub extend EntityId with Debug::{to_repr}

///|
pub(all) enum Value {
  BoolValue(Bool)
  LongValue(Int64)
  StringValue(String)
  EntityValue(EntityId)
  SetValue(Array[Value])
  RecordValue(Map[String, Value])
} derive(Eq, Debug)

///|
pub extend Value with Eq::{equal, not_equal}

///|
pub extend Value with Debug::{to_repr}

///|
pub(all) struct Entity {
  uid : EntityId
  attrs : Map[String, Value]
  parents : Array[EntityId]
} derive(Debug)

///|
pub extend Entity with Debug::{to_repr}

///|
pub(all) struct Request {
  principal : EntityId
  action : EntityId
  resource : EntityId
  context : Map[String, Value]
} derive(Debug)

///|
pub extend Request with Debug::{to_repr}

///|
pub(all) enum Decision {
  Allow
  Deny
} derive(Eq, Debug)

///|
pub extend Decision with Eq::{equal, not_equal}

///|
pub extend Decision with Debug::{to_repr}

///|
pub(all) struct Diagnostic {
  policy_id : String
  message : String
} derive(Debug)

///|
pub extend Diagnostic with Debug::{to_repr}

///|
pub(all) struct Response {
  decision : Decision
  reasons : Array[String]
  errors : Array[Diagnostic]
} derive(Debug)

///|
pub extend Response with Debug::{to_repr}

///|
priv enum Expr {
  Literal(Value)
  Variable(String)
  Attribute(Expr, String)
  Has(Expr, String)
  Not(Expr)
  And(Expr, Expr)
  Or(Expr, Expr)
  Equal(Expr, Expr)
  In(Expr, Expr)
  SetExpr(Array[Expr])
  RecordExpr(Array[(String, Expr)])
} derive(Debug)

///|
priv struct Policy {
  id : String
  forbid : Bool
  condition : Expr
}

///|
pub struct PolicySet {
  priv policies : Array[Policy]
}
