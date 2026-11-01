///|
/// A Cedar fixed-point decimal, parsed without floating-point rounding.
pub struct Decimal {
  priv scaled : Int64
} derive(Eq, Debug)

///|
pub extend Decimal with Eq::{equal, not_equal}

///|
pub extend Decimal with Debug::{to_repr}

///|
/// Parse a signed decimal with one to four fractional digits.
pub fn Decimal::parse(text : String) -> Decimal raise PolicyError {
  let chars = text.to_array()
  let mut i = 0
  let negative = if !chars.is_empty() && chars[0] == '-' {
    i = 1
    true
  } else {
    false
  }
  let mut whole_digits = 0
  let mut fraction_digits = 0
  let mut separator = false
  let mut value = 0L
  while i < chars.length() {
    let c = chars[i]
    i += 1
    if c == '.' && !separator && whole_digits > 0 {
      separator = true
    } else if c >= '0' && c <= '9' {
      if separator {
        fraction_digits += 1
        if fraction_digits > 4 {
          raise PolicyError("invalid decimal")
        }
      } else {
        whole_digits += 1
      }
      let digit = (c.to_int() - '0'.to_int()).to_int64()
      value = checked_arithmetic(
        checked_arithmetic(value, Multiply, 10L),
        Subtract,
        digit,
      )
    } else {
      raise PolicyError("invalid decimal")
    }
  }
  if !separator || fraction_digits == 0 {
    raise PolicyError("invalid decimal")
  }
  for _ in fraction_digits..<4 {
    value = checked_arithmetic(value, Multiply, 10L)
  }
  if !negative {
    value = checked_arithmetic(0L, Subtract, value)
  }
  { scaled: value, }
}
