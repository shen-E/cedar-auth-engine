///|
/// A Cedar duration represented as signed milliseconds.
pub struct Duration {
  priv milliseconds : Int64
} derive(Eq, Debug)

///|
pub extend Duration with Eq::{equal, not_equal}

///|
pub extend Duration with Debug::{to_repr}

///|
/// Parse ordered duration components, from days down to milliseconds.
pub fn Duration::parse(text : String) -> Duration raise PolicyError {
  let chars = text.to_array()
  let mut i = 0
  let negative = if !chars.is_empty() && chars[0] == '-' {
    i = 1
    true
  } else {
    false
  }
  let mut previous = 6
  let mut total = 0L
  let mut components = 0
  while i < chars.length() {
    let start = i
    let mut quantity = 0L
    while i < chars.length() && chars[i] >= '0' && chars[i] <= '9' {
      let digit = (chars[i].to_int() - '0'.to_int()).to_int64()
      quantity = checked_arithmetic(
        checked_arithmetic(quantity, Multiply, 10L),
        Subtract,
        digit,
      )
      i += 1
    }
    if i == start || i >= chars.length() {
      raise PolicyError("invalid duration")
    }
    let unit = chars[i]
    i += 1
    let (rank, multiplier) = match unit {
      'd' => (5, 86400000L)
      'h' => (4, 3600000L)
      'm' if i < chars.length() && chars[i] == 's' => {
        i += 1
        (1, 1L)
      }
      'm' => (3, 60000L)
      's' => (2, 1000L)
      _ => raise PolicyError("invalid duration unit")
    }
    if rank >= previous {
      raise PolicyError("duration units must be ordered and unique")
    }
    previous = rank
    components += 1
    total = checked_arithmetic(
      total,
      Add,
      checked_arithmetic(quantity, Multiply, multiplier),
    )
  }
  if components == 0 {
    raise PolicyError("invalid duration")
  }
  if !negative {
    total = checked_arithmetic(0L, Subtract, total)
  }
  { milliseconds: total, }
}
