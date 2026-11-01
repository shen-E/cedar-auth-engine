///|
/// A Cedar datetime represented as milliseconds since the Unix epoch.
pub struct DateTime {
  priv milliseconds : Int64
} derive(Eq, Debug)

///|
pub extend DateTime with Eq::{equal, not_equal}

///|
pub extend DateTime with Debug::{to_repr}

///|
fn datetime_digits(
  chars : Array[Char],
  start : Int32,
  count : Int32,
) -> Int32 raise PolicyError {
  let mut value = 0
  for i in start..<(start + count) {
    let c = chars[i]
    if c < '0' || c > '9' {
      raise PolicyError("invalid datetime")
    }
    value = value * 10 + c.to_int() - '0'.to_int()
  }
  value
}

///|
/// Parse a Cedar date or timestamp with a numeric offset or UTC designator.
pub fn DateTime::parse(text : String) -> DateTime raise PolicyError {
  let chars = text.to_array()
  if chars.length() != 10 &&
    chars.length() != 20 &&
    chars.length() != 24 &&
    chars.length() != 28 {
    raise PolicyError("invalid datetime format")
  }
  if chars[4] != '-' || chars[7] != '-' {
    raise PolicyError("invalid datetime format")
  }
  let year = datetime_digits(chars, 0, 4)
  let month = datetime_digits(chars, 5, 2)
  let day = datetime_digits(chars, 8, 2)
  if month < 1 || month > 12 {
    raise PolicyError("invalid datetime month")
  }
  let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
  let month_lengths = [
    31,
    if leap {
      29
    } else {
      28
    },
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ]
  if day < 1 || day > month_lengths[month - 1] {
    raise PolicyError("invalid datetime day")
  }
  let mut days = 365 * year +
    (year + 3) / 4 -
    (year + 99) / 100 +
    (year + 399) / 400 +
    day -
    1 -
    719528
  for i in 0..<(month - 1) {
    days += month_lengths[i]
  }
  let mut result = days.to_int64() * 86400000L
  if chars.length() == 10 {
    return { milliseconds: result, }
  }
  if chars[10] != 'T' || chars[13] != ':' || chars[16] != ':' {
    raise PolicyError("invalid datetime format")
  }
  let hour = datetime_digits(chars, 11, 2)
  let minute = datetime_digits(chars, 14, 2)
  let second = datetime_digits(chars, 17, 2)
  if hour > 23 || minute > 59 || second > 59 {
    raise PolicyError("invalid datetime time")
  }
  result += hour.to_int64() * 3600000L +
    minute.to_int64() * 60000L +
    second.to_int64() * 1000L
  let mut suffix = 19
  if chars[suffix] == '.' {
    if chars.length() != 24 && chars.length() != 28 {
      raise PolicyError("invalid datetime fraction")
    }
    result += datetime_digits(chars, 20, 3).to_int64()
    suffix = 23
  }
  if chars[suffix] == 'Z' {
    if suffix + 1 != chars.length() {
      raise PolicyError("invalid datetime timezone")
    }
  } else {
    if suffix + 5 != chars.length() ||
      (chars[suffix] != '+' && chars[suffix] != '-') {
      raise PolicyError("invalid datetime timezone")
    }
    let zone_hour = datetime_digits(chars, suffix + 1, 2)
    let zone_minute = datetime_digits(chars, suffix + 3, 2)
    if zone_hour > 23 || zone_minute > 59 {
      raise PolicyError("invalid datetime timezone")
    }
    let offset = zone_hour.to_int64() * 3600000L +
      zone_minute.to_int64() * 60000L
    if chars[suffix] == '+' {
      result -= offset
    } else {
      result += offset
    }
  }
  { milliseconds: result, }
}

///|
fn datetime_time(milliseconds : Int64) -> Int64 {
  let remainder = milliseconds % 86400000L
  if remainder < 0L {
    remainder + 86400000L
  } else {
    remainder
  }
}
