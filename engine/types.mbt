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
  IpValue(IpAddress)
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
/// An entity and its dynamic Cedar tags.
pub(all) struct TaggedEntity {
  entity : Entity
  tags : Map[String, Value]
} derive(Debug)

///|
pub extend TaggedEntity with Debug::{to_repr}

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
  HasPath(Expr, Array[String])
  Not(Expr)
  Negate(Expr)
  Arithmetic(Expr, ArithmeticOp, Expr)
  And(Expr, Expr)
  Or(Expr, Expr)
  Equal(Expr, Expr)
  In(Expr, Expr)
  IsType(Expr, String)
  Conditional(Expr, Expr, Expr)
  Like(Expr, Array[PatternPart])
  Compare(Expr, CompareOp, Expr)
  SetCall(Expr, SetOp, Expr?)
  TagCall(Expr, Bool, Expr)
  IpConstructor(Expr)
  IpCall(Expr, IpOp, Expr?)
  SetExpr(Array[Expr])
  RecordExpr(Array[(String, Expr)])
} derive(Debug)

///|
priv enum PatternPart {
  AnySequence
  PatternChar(Char)
} derive(Debug)

///|
priv enum ArithmeticOp {
  Add
  Subtract
  Multiply
} derive(Debug)

///|
priv enum CompareOp {
  Less
  LessEqual
  Greater
  GreaterEqual
} derive(Debug)

///|
priv enum IpOp {
  IsIpv4
  IsIpv6
  IsInRange
  IsLoopback
  IsMulticast
} derive(Debug)

///|
priv enum SetOp {
  Contains
  ContainsAll
  ContainsAny
  IsEmpty
} derive(Debug)

///|
priv struct Policy {
  id : String
  forbid : Bool
  condition : Expr
  annotations : Map[String, String]
}

///|
pub struct PolicySet {
  priv policies : Array[Policy]
}

///|
/// Metadata associated with a parsed policy.
pub(all) struct PolicyInfo {
  id : String
  effect : String
  annotations : Map[String, String]
} derive(Debug)

///|
pub extend PolicyInfo with Debug::{to_repr}

///|
/// List policies in source order. Annotation maps are independent copies.
pub fn PolicySet::metadata(self : PolicySet) -> Array[PolicyInfo] {
  let result = []
  for policy in self.policies {
    result.push({
      id: policy.id,
      effect: if policy.forbid {
        "forbid"
      } else {
        "permit"
      },
      annotations: policy.annotations.copy(),
    })
  }
  result
}
