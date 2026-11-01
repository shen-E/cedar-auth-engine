///|
fn checked_arithmetic(
  a : Int64,
  op : ArithmeticOp,
  b : Int64,
) -> Int64 raise PolicyError {
  let min = -9223372036854775808L
  let max = 9223372036854775807L
  match op {
    Add => {
      if (b > 0L && a > max - b) || (b < 0L && a < min - b) {
        raise PolicyError("integer overflow")
      }
      a + b
    }
    Subtract => {
      if (b > 0L && a < min + b) || (b < 0L && a > max + b) {
        raise PolicyError("integer overflow")
      }
      a - b
    }
    Multiply => {
      if (a > 0L && b > 0L && a > max / b) ||
        (a > 0L && b < 0L && b < min / a) ||
        (a < 0L && b > 0L && a < min / b) ||
        (a < 0L && b < 0L && a < max / b) {
        raise PolicyError("integer overflow")
      }
      a * b
    }
  }
}
