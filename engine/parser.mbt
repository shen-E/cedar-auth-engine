///|
priv struct Parser {
  tokens : Array[String]
  mut pos : Int32
  mut depth : Int32
}

///|
fn tokenize(text : String) -> Array[String] raise PolicyError {
  let chars = text.to_array()
  if chars.length() > 1048576 {
    raise PolicyError("policy exceeds 1 MiB")
  }
  let out : Array[String] = []
  let mut i = 0
  while i < chars.length() {
    let c = chars[i]
    if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
      i += 1
    } else if c == '/' && i + 1 < chars.length() && chars[i + 1] == '/' {
      i += 2
      while i < chars.length() && chars[i] != '\n' {
        i += 1
      }
    } else if c == '"' {
      let b = StringBuilder()
      b.write_char(c)
      i += 1
      let mut closed = false
      while i < chars.length() {
        let current = chars[i]
        b.write_char(current)
        i += 1
        if current == '\\' {
          if i >= chars.length() {
            raise PolicyError("unterminated string escape")
          }
          b.write_char(chars[i])
          i += 1
        } else if current == '"' {
          closed = true
          break
        }
      }
      if !closed {
        raise PolicyError("unterminated string")
      }
      out.push(b.to_string())
    } else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
      let b = StringBuilder()
      while i < chars.length() {
        let d = chars[i]
        if (d >= 'a' && d <= 'z') ||
          (d >= 'A' && d <= 'Z') ||
          (d >= '0' && d <= '9') ||
          d == '_' {
          b.write_char(d)
          i += 1
        } else {
          break
        }
      }
      out.push(b.to_string())
    } else if c >= '0' && c <= '9' {
      let b = StringBuilder()
      b.write_char(c)
      i += 1
      while i < chars.length() && chars[i] >= '0' && chars[i] <= '9' {
        b.write_char(chars[i])
        i += 1
      }
      out.push(b.to_string())
    } else {
      let b = StringBuilder()
      b.write_char(c)
      i += 1
      if i < chars.length() &&
        (
          (c == ':' && chars[i] == ':') ||
          (c == '=' && chars[i] == '=') ||
          (c == '!' && chars[i] == '=') ||
          (c == '<' && chars[i] == '=') ||
          (c == '>' && chars[i] == '=') ||
          (c == '&' && chars[i] == '&') ||
          (c == '|' && chars[i] == '|')
        ) {
        b.write_char(chars[i])
        i += 1
      }
      out.push(b.to_string())
    }
    if out.length() > 2048 {
      raise PolicyError("policy token limit exceeded")
    }
  }
  out
}

///|
fn Parser::peek(self : Parser) -> String {
  self.tokens.get(self.pos).unwrap_or("")
}

///|
fn Parser::take(self : Parser) -> String raise PolicyError {
  let token = self.peek()
  if token == "" {
    raise PolicyError("unexpected end of policy")
  }
  self.pos += 1
  token
}

///|
fn Parser::accept(self : Parser, token : String) -> Bool {
  if self.peek() == token {
    self.pos += 1
    true
  } else {
    false
  }
}

///|
fn Parser::expect(self : Parser, token : String) -> Unit raise PolicyError {
  if !self.accept(token) {
    raise PolicyError(
      "expected '\{token}' at token \{self.pos}, found '\{self.peek()}'",
    )
  }
}

///|
fn quoted(token : String) -> String raise PolicyError {
  let value = @json.parse(token) catch {
    _ => raise PolicyError("invalid string literal")
  }
  match value {
    String(s) => s
    _ => raise PolicyError("expected string literal")
  }
}

///|
fn identifier(token : String) -> Bool {
  let chars = token.to_array()
  if chars.length() == 0 {
    return false
  }
  let c = chars[0]
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

///|
fn type_identifier(token : String) -> Bool {
  identifier(token) &&
  !["if", "then", "else", "in", "is", "has", "like", "true", "false", "__cedar"].contains(
    token,
  )
}

///|
fn Parser::type_path(self : Parser) -> String raise PolicyError {
  let first = self.take()
  if !type_identifier(first) {
    raise PolicyError("expected entity type")
  }
  let mut path = first
  while self.accept("::") {
    let part = self.take()
    if !type_identifier(part) {
      raise PolicyError("expected entity type after ::")
    }
    path = path + "::" + part
  }
  path
}

///|
fn Parser::primary(self : Parser) -> Expr raise PolicyError {
  self.depth += 1
  if self.depth > 128 {
    raise PolicyError("expression nesting limit exceeded")
  }
  let token = self.take()
  let result = match token {
    "(" => {
      let e = self.expression()
      self.expect(")")
      e
    }
    "[" => {
      let items = []
      if !self.accept("]") {
        items.push(self.expression())
        while self.accept(",") {
          items.push(self.expression())
        }
        self.expect("]")
      }
      SetExpr(items)
    }
    "{" => {
      let fields = []
      if !self.accept("}") {
        let key = self.take()
        let name = if key.has_prefix("\"") {
          cedar_quoted(key)
        } else if identifier(key) {
          key
        } else {
          raise PolicyError("invalid record key")
        }
        self.expect(":")
        fields.push((name, self.expression()))
        while self.accept(",") {
          let key = self.take()
          let name = if key.has_prefix("\"") {
            cedar_quoted(key)
          } else if identifier(key) {
            key
          } else {
            raise PolicyError("invalid record key")
          }
          self.expect(":")
          fields.push((name, self.expression()))
        }
        self.expect("}")
      }
      RecordExpr(fields)
    }
    "ip" | "decimal" | "duration" as function_name if self.accept("(") => {
      let argument = self.expression()
      self.expect(")")
      match function_name {
        "ip" => IpConstructor(argument)
        "decimal" => DecimalConstructor(argument)
        _ => DurationConstructor(argument)
      }
    }
    "true" => Literal(BoolValue(true))
    "false" => Literal(BoolValue(false))
    "principal" | "action" | "resource" | "context" => Variable(token)
    _ if token.has_prefix("\"") => Literal(StringValue(cedar_quoted(token)))
    _ if identifier(token) => {
      let mut kind = token
      self.expect("::")
      let mut part = self.take()
      while !part.has_prefix("\"") {
        if !identifier(part) {
          raise PolicyError("invalid entity type")
        }
        kind = kind + "::" + part
        self.expect("::")
        part = self.take()
      }
      Literal(EntityValue({ kind, id: cedar_quoted(part), }))
    }
    _ => {
      let number : Int64 = @json.from_json(Json::string(token)) catch {
        _ => raise PolicyError("invalid integer '\{token}'")
      }
      Literal(LongValue(number))
    }
  }
  self.depth -= 1
  result
}

///|
fn Parser::postfix(self : Parser) -> Expr raise PolicyError {
  let mut result = self.primary()
  let mut count = 0
  while self.peek() == "." || self.peek() == "[" {
    count += 1
    if count > 128 {
      raise PolicyError("postfix chain limit exceeded")
    }
    if self.accept("[") {
      let name = self.take()
      if !name.has_prefix("\"") {
        raise PolicyError("attribute index requires a string literal")
      }
      self.expect("]")
      result = Attribute(result, cedar_quoted(name))
      continue
    }
    self.expect(".")
    let name = self.take()
    if !identifier(name) {
      raise PolicyError("expected attribute name")
    }
    if self.accept("(") {
      if name == "hasTag" || name == "getTag" {
        self.depth += 1
        if self.depth > 128 {
          raise PolicyError("expression nesting limit exceeded")
        }
        let key = self.expression()
        self.depth -= 1
        self.expect(")")
        result = TagCall(result, name == "hasTag", key)
        continue
      }
      if name == "isIpv4" ||
        name == "isIpv6" ||
        name == "isInRange" ||
        name == "isLoopback" ||
        name == "isMulticast" {
        let operation = match name {
          "isIpv4" => IsIpv4
          "isIpv6" => IsIpv6
          "isLoopback" => IsLoopback
          "isMulticast" => IsMulticast
          _ => IsInRange
        }
        let arg = if operation is IsInRange {
          self.depth += 1
          if self.depth > 128 {
            raise PolicyError("expression nesting limit exceeded")
          }
          let value = self.expression()
          self.depth -= 1
          Some(value)
        } else {
          None
        }
        self.expect(")")
        result = IpCall(result, operation, arg)
        continue
      }
      if name == "toMilliseconds" ||
        name == "toSeconds" ||
        name == "toMinutes" ||
        name == "toHours" ||
        name == "toDays" {
        let divisor = match name {
          "toMilliseconds" => 1L
          "toSeconds" => 1000L
          "toMinutes" => 60000L
          "toHours" => 3600000L
          _ => 86400000L
        }
        self.expect(")")
        result = DurationCall(result, divisor)
        continue
      }
      if name == "lessThan" ||
        name == "lessThanOrEqual" ||
        name == "greaterThan" ||
        name == "greaterThanOrEqual" {
        let operation = match name {
          "lessThan" => Less
          "lessThanOrEqual" => LessEqual
          "greaterThan" => Greater
          _ => GreaterEqual
        }
        self.depth += 1
        if self.depth > 128 {
          raise PolicyError("expression nesting limit exceeded")
        }
        let arg = self.expression()
        self.depth -= 1
        self.expect(")")
        result = DecimalCall(result, operation, arg)
        continue
      }
      let operation = match name {
        "contains" => Contains
        "containsAll" => ContainsAll
        "containsAny" => ContainsAny
        "isEmpty" => IsEmpty
        _ => raise PolicyError("unsupported method '\{name}'")
      }
      let arg = if operation is IsEmpty {
        None
      } else {
        self.depth += 1
        if self.depth > 128 {
          raise PolicyError("expression nesting limit exceeded")
        }
        let value = self.expression()
        self.depth -= 1
        Some(value)
      }
      self.expect(")")
      result = SetCall(result, operation, arg)
    } else {
      result = Attribute(result, name)
    }
  }
  result
}

///|
fn Parser::unary(self : Parser) -> Expr raise PolicyError {
  let operator = self.peek()
  if operator != "!" && operator != "-" {
    return self.postfix()
  }
  let mut count = 0
  while self.accept(operator) {
    count += 1
    if count > 4 {
      raise PolicyError("too many unary operators")
    }
  }
  let mut expr = if operator == "-" && self.peek() == "9223372036854775808" {
    self.pos += 1
    count -= 1
    Literal(LongValue(-9223372036854775808L))
  } else {
    self.postfix()
  }
  for _ in 0..<count {
    expr = if operator == "!" { Not(expr) } else { Negate(expr) }
  }
  expr
}

///|
fn Parser::multiplication(self : Parser) -> Expr raise PolicyError {
  let mut result = self.unary()
  let mut count = 0
  while self.accept("*") {
    count += 1
    if count > 128 {
      raise PolicyError("arithmetic chain limit exceeded")
    }
    result = Arithmetic(result, Multiply, self.unary())
  }
  result
}

///|
fn Parser::addition(self : Parser) -> Expr raise PolicyError {
  let mut result = self.multiplication()
  let mut count = 0
  while self.peek() == "+" || self.peek() == "-" {
    let operator = self.take()
    count += 1
    if count > 128 {
      raise PolicyError("arithmetic chain limit exceeded")
    }
    let kind = if operator == "+" { Add } else { Subtract }
    result = Arithmetic(result, kind, self.multiplication())
  }
  result
}

///|
fn Parser::relation(self : Parser) -> Expr raise PolicyError {
  let left = self.addition()
  match self.peek() {
    "==" => {
      self.pos += 1
      Equal(left, self.addition())
    }
    "!=" => {
      self.pos += 1
      Not(Equal(left, self.addition()))
    }
    "in" => {
      self.pos += 1
      In(left, self.addition())
    }
    "<" | "<=" | ">" | ">=" as op => {
      self.pos += 1
      let kind = match op {
        "<" => Less
        "<=" => LessEqual
        ">" => Greater
        _ => GreaterEqual
      }
      Compare(left, kind, self.addition())
    }
    "has" => {
      self.pos += 1
      let name = self.take()
      let path = []
      if name.has_prefix("\"") {
        path.push(cedar_quoted(name))
      } else if type_identifier(name) {
        path.push(name)
        while self.accept(".") {
          let segment = self.take()
          if !type_identifier(segment) {
            raise PolicyError("expected identifier in has path")
          }
          path.push(segment)
          if path.length() > 128 {
            raise PolicyError("has path limit exceeded")
          }
        }
      } else {
        raise PolicyError("expected attribute after has")
      }
      HasPath(left, path)
    }
    "is" => {
      self.pos += 1
      let kind = self.type_path()
      let type_test = IsType(left, kind)
      if self.accept("in") {
        And(type_test, In(left, self.addition()))
      } else {
        type_test
      }
    }
    "like" => {
      self.pos += 1
      let token = self.take()
      Like(left, cedar_parts(token, pattern=true))
    }
    _ => left
  }
}

///|
fn Parser::conjunction(self : Parser) -> Expr raise PolicyError {
  let mut e = self.relation()
  while self.accept("&&") {
    e = And(e, self.relation())
  }
  e
}

///|
fn Parser::expression(self : Parser) -> Expr raise PolicyError {
  if self.accept("if") {
    self.depth += 1
    if self.depth > 128 {
      raise PolicyError("expression nesting limit exceeded")
    }
    let condition = self.expression()
    self.expect("then")
    let when_true = self.expression()
    self.expect("else")
    let when_false = self.expression()
    self.depth -= 1
    return Conditional(condition, when_true, when_false)
  }
  let mut e = self.conjunction()
  while self.accept("||") {
    e = Or(e, self.conjunction())
  }
  e
}

///|
fn Parser::scope(self : Parser, variable : String) -> Expr raise PolicyError {
  self.expect(variable)
  if self.accept("is") {
    if variable == "action" {
      raise PolicyError("action scope does not support is")
    }
    let type_test = IsType(Variable(variable), self.type_path())
    if self.accept("in") {
      let parent = self.primary()
      if !(parent is Literal(EntityValue(_))) {
        raise PolicyError("scope membership requires an entity literal")
      }
      And(type_test, In(Variable(variable), parent))
    } else {
      type_test
    }
  } else if self.accept("==") {
    let value = self.primary()
    if !(value is Literal(EntityValue(_))) {
      raise PolicyError("scope equality requires an entity literal")
    }
    Equal(Variable(variable), value)
  } else if self.accept("in") {
    let value = self.primary()
    match value {
      Literal(EntityValue(_)) => ()
      SetExpr(items) if variable == "action" =>
        for item in items {
          if !(item is Literal(EntityValue(_))) {
            raise PolicyError("action scope set requires entity literals")
          }
        }
      _ => raise PolicyError("scope membership requires an entity literal")
    }
    In(Variable(variable), value)
  } else {
    Literal(BoolValue(true))
  }
}

///|
pub fn parse_policies(text : String) -> PolicySet raise PolicyError {
  let parser = { tokens: tokenize(text), pos: 0, depth: 0, }
  let policies : Array[Policy] = []
  while parser.peek() != "" {
    let annotations : Map[String, String] = Map([])
    while parser.accept("@") {
      let name = parser.take()
      if !identifier(name) {
        raise PolicyError("expected annotation name")
      }
      if annotations.contains(name) {
        raise PolicyError("duplicate annotation '@\{name}'")
      }
      let value = if parser.accept("(") {
        let literal = parser.take()
        if !literal.has_prefix("\"") {
          raise PolicyError("annotation value must be a string literal")
        }
        let parsed = cedar_quoted(literal)
        parser.expect(")")
        parsed
      } else {
        ""
      }
      annotations[name] = value
    }
    let effect = parser.take()
    if effect != "permit" && effect != "forbid" {
      raise PolicyError("expected permit or forbid, found '\{effect}'")
    }
    parser.expect("(")
    let p = parser.scope("principal")
    parser.expect(",")
    let a = parser.scope("action")
    parser.expect(",")
    let r = parser.scope("resource")
    parser.expect(")")
    let mut condition = And(And(p, a), r)
    while parser.peek() == "when" || parser.peek() == "unless" {
      let unless = parser.take() == "unless"
      parser.expect("{")
      let e = parser.expression()
      parser.expect("}")
      condition = And(condition, if unless { Not(e) } else { e })
    }
    parser.expect(";")
    let id = annotations.get("id").unwrap_or("policy\{policies.length()}")
    if policies.any(fn(policy) { policy.id == id }) {
      raise PolicyError("duplicate policy id '\{id}'")
    }
    policies.push({ id, forbid: effect == "forbid", condition, annotations, })
    if policies.length() > 1024 {
      raise PolicyError("policy count limit exceeded")
    }
  }
  { policies, }
}
