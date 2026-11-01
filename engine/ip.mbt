///|
/// A Cedar IP address or CIDR range, constructed from its textual form.
pub struct IpAddress {
  priv version : Int32
  priv bytes : Array[Int32]
  priv prefix : Int32
} derive(Eq, Debug)

///|
pub extend IpAddress with Eq::{equal, not_equal}

///|
pub extend IpAddress with Debug::{to_repr}

///|
fn ip_decimal(text : String, limit : Int32) -> Int32 raise PolicyError {
  let chars = text.to_array()
  if chars.is_empty() ||
    chars.length() > 3 ||
    (chars.length() > 1 && chars[0] == '0') {
    raise PolicyError("invalid IP decimal component")
  }
  let mut result = 0
  for c in chars {
    if c < '0' || c > '9' {
      raise PolicyError("invalid IP decimal component")
    }
    result = result * 10 + c.to_int() - '0'.to_int()
  }
  if result > limit {
    raise PolicyError("IP decimal component out of range")
  }
  result
}

///|
fn ip_hex(text : String) -> Int32 raise PolicyError {
  let chars = text.to_array()
  if chars.is_empty() || chars.length() > 4 {
    raise PolicyError("invalid IPv6 component")
  }
  let mut result = 0
  for c in chars {
    let digit = if c >= '0' && c <= '9' {
      c.to_int() - '0'.to_int()
    } else if c >= 'a' && c <= 'f' {
      c.to_int() - 'a'.to_int() + 10
    } else if c >= 'A' && c <= 'F' {
      c.to_int() - 'A'.to_int() + 10
    } else {
      raise PolicyError("invalid IPv6 component")
    }
    result = result * 16 + digit
  }
  result
}

///|
fn ipv6_groups(text : String) -> Array[Int32] raise PolicyError {
  let groups = []
  if text != "" {
    for component in text.split(":") {
      groups.push(ip_hex(component.to_owned()))
    }
  }
  groups
}

///|
/// Parse an IPv4 or IPv6 address, optionally followed by a CIDR prefix.
pub fn IpAddress::parse(text : String) -> IpAddress raise PolicyError {
  if text.length() > 64 {
    raise PolicyError("IP address is too long")
  }
  let pieces : Array[String] = []
  for piece in text.split("/") {
    pieces.push(piece.to_owned())
  }
  if pieces.is_empty() || pieces.length() > 2 {
    raise PolicyError("invalid IP address")
  }
  let address = pieces[0]
  let bytes : Array[Int32] = []
  let version = if address.contains(":") {
    let halves : Array[String] = []
    for half in address.split("::") {
      halves.push(half.to_owned())
    }
    if halves.length() > 2 {
      raise PolicyError("invalid IPv6 compression")
    }
    let left = ipv6_groups(halves[0])
    let right = if halves.length() == 2 { ipv6_groups(halves[1]) } else { [] }
    let total = left.length() + right.length()
    if (halves.length() == 1 && total != 8) ||
      (halves.length() == 2 && total >= 8) {
      raise PolicyError("invalid IPv6 length")
    }
    let groups = left
    if halves.length() == 2 {
      for _ in 0..<(8 - total) {
        groups.push(0)
      }
    }
    for group in right {
      groups.push(group)
    }
    for group in groups {
      bytes.push(group / 256)
      bytes.push(group % 256)
    }
    6
  } else {
    for part in address.split(".") {
      bytes.push(ip_decimal(part.to_owned(), 255))
    }
    if bytes.length() != 4 {
      raise PolicyError("invalid IPv4 length")
    }
    4
  }
  let max_prefix = if version == 4 { 32 } else { 128 }
  let prefix = if pieces.length() == 2 {
    ip_decimal(pieces[1], max_prefix)
  } else {
    max_prefix
  }
  { version, bytes, prefix, }
}

///|
fn ip_in_range(ip : IpAddress, range : IpAddress) -> Bool {
  if ip.version != range.version || ip.prefix < range.prefix {
    return false
  }
  let complete = range.prefix / 8
  for i in 0..<complete {
    if ip.bytes[i] != range.bytes[i] {
      return false
    }
  }
  let remaining = range.prefix % 8
  if remaining != 0 {
    let mut divisor = 1
    for _ in 0..<(8 - remaining) {
      divisor *= 2
    }
    if ip.bytes[complete] / divisor != range.bytes[complete] / divisor {
      return false
    }
  }
  true
}
