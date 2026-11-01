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
    } else if (c >= '0' && c <= '9') ||
      (
        c == '-' &&
        i + 1 < chars.length() &&
        chars[i + 1] >= '0' &&
        chars[i + 1] <= '9'
      ) {
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
          quoted(key)
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
            quoted(key)
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
    "true" => Literal(BoolValue(true))
    "false" => Literal(BoolValue(false))
    "principal" | "action" | "resource" | "context" => Variable(token)
    _ if token.has_prefix("\"") => Literal(StringValue(quoted(token)))
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
      Literal(EntityValue({ kind, id: quoted(part), }))
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
  while self.accept(".") {
    let name = self.take()
    if !identifier(name) {
      raise PolicyError("expected attribute name")
    }
    if self.accept("(") {
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
  let mut count = 0
  while self.accept("!") {
    count += 1
    if count > 128 {
      raise PolicyError("expression nesting limit exceeded")
    }
  }
  let mut expr = self.postfix()
  for _ in 0..<count {
    expr = Not(expr)
  }
  expr
}

///|
fn Parser::relation(self : Parser) -> Expr raise PolicyError {
  let left = self.unary()
  match self.peek() {
    "==" => {
      self.pos += 1
      Equal(left, self.unary())
    }
    "!=" => {
      self.pos += 1
      Not(Equal(left, self.unary()))
    }
    "in" => {
      self.pos += 1
      In(left, self.unary())
    }
    "<" | "<=" | ">" | ">=" as op => {
      self.pos += 1
      let kind = match op {
        "<" => Less
        "<=" => LessEqual
        ">" => Greater
        _ => GreaterEqual
      }
      Compare(left, kind, self.unary())
    }
    "has" => {
      self.pos += 1
      let name = self.take()
      if !identifier(name) {
        raise PolicyError("expected attribute after has")
      }
      Has(left, name)
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
  let mut e = self.conjunction()
  while self.accept("||") {
    e = Or(e, self.conjunction())
  }
  e
}

///|
fn Parser::scope(self : Parser, variable : String) -> Expr raise PolicyError {
  self.expect(variable)
  if self.accept("==") {
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
  let policies = []
  while parser.peek() != "" {
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
    let id = "policy\{policies.length()}"
    policies.push({ id, forbid: effect == "forbid", condition, })
    if policies.length() > 1024 {
      raise PolicyError("policy count limit exceeded")
    }
  }
  { policies, }
}
