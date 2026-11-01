///|
fn hex_digit(c : Char) -> Int32? {
  let n = c.to_int()
  if c >= '0' && c <= '9' {
    Some(n - '0'.to_int())
  } else if c >= 'a' && c <= 'f' {
    Some(n - 'a'.to_int() + 10)
  } else if c >= 'A' && c <= 'F' {
    Some(n - 'A'.to_int() + 10)
  } else {
    None
  }
}

///|
fn push_wildcard(parts : Array[PatternPart]) -> Unit {
  if parts.is_empty() || !(parts[parts.length() - 1] is AnySequence) {
    parts.push(AnySequence)
  }
}

///|
fn cedar_parts(
  token : String,
  pattern~ : Bool,
) -> Array[PatternPart] raise PolicyError {
  let chars = token.to_array()
  if chars.length() < 2 || chars[0] != '"' || chars[chars.length() - 1] != '"' {
    raise PolicyError("expected a quoted string")
  }
  let out : Array[PatternPart] = []
  let mut i = 1
  let end = chars.length() - 1
  while i < end {
    let c = chars[i]
    i += 1
    if c == '*' && pattern {
      push_wildcard(out)
    } else if c != '\\' {
      out.push(PatternChar(c))
    } else {
      if i >= end {
        raise PolicyError("unterminated string escape")
      }
      let esc = chars[i]
      i += 1
      let value = match esc {
        '"' => '"'
        '\\' => '\\'
        'n' => '\n'
        'r' => '\r'
        't' => '\t'
        '0' => '\u{0}'
        '*' if pattern => '*'
        'x' => {
          if i + 2 > end {
            raise PolicyError("invalid hexadecimal escape")
          }
          let hi = match hex_digit(chars[i]) {
            Some(n) => n
            None => raise PolicyError("invalid hexadecimal escape")
          }
          let lo = match hex_digit(chars[i + 1]) {
            Some(n) => n
            None => raise PolicyError("invalid hexadecimal escape")
          }
          i += 2
          let point = hi * 16 + lo
          if point > 127 {
            raise PolicyError("hexadecimal escape must be ASCII")
          }
          match point.to_char() {
            Some(character) => character
            None => raise PolicyError("invalid character")
          }
        }
        'u' => {
          if i >= end || chars[i] != '{' {
            raise PolicyError("expected Unicode escape braces")
          }
          i += 1
          let mut point = 0
          let mut digits = 0
          while i < end && chars[i] != '}' {
            if chars[i] == '_' && digits > 0 {
              i += 1
              continue
            }
            let n = match hex_digit(chars[i]) {
              Some(n) => n
              None => raise PolicyError("invalid Unicode escape")
            }
            digits += 1
            if digits > 6 {
              raise PolicyError("Unicode escape exceeds six digits")
            }
            point = point * 16 + n
            i += 1
          }
          if digits == 0 || i >= end || chars[i] != '}' {
            raise PolicyError("invalid Unicode escape")
          }
          i += 1
          match point.to_char() {
            Some(character) => character
            None => raise PolicyError("invalid Unicode scalar")
          }
        }
        _ => raise PolicyError("unsupported string escape")
      }
      if pattern && value == '*' && esc != '*' {
        push_wildcard(out)
      } else {
        out.push(PatternChar(value))
      }
    }
  }
  out
}

///|
fn cedar_quoted(token : String) -> String raise PolicyError {
  let output = StringBuilder()
  for part in cedar_parts(token, pattern=false) {
    match part {
      PatternChar(c) => output.write_char(c)
      AnySequence => raise PolicyError("invalid string literal")
    }
  }
  output.to_string()
}
