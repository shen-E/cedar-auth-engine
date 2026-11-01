///|
// Find each literal segment with KMP so repeated prefixes do not cause
// backtracking on long, attacker-controlled input.
fn find_segment(
  text : Array[Char],
  segment : Array[Char],
  start : Int32,
  end : Int32,
) -> Int32? {
  if segment.is_empty() {
    return Some(start)
  }
  let failure = Array::make(segment.length(), 0)
  let mut prefix = 0
  let mut i = 1
  while i < segment.length() {
    if segment[i] == segment[prefix] {
      prefix += 1
      failure[i] = prefix
      i += 1
    } else if prefix > 0 {
      prefix = failure[prefix - 1]
    } else {
      i += 1
    }
  }
  let mut matched = 0
  i = start
  while i < end {
    if text[i] == segment[matched] {
      i += 1
      matched += 1
      if matched == segment.length() {
        return Some(i - matched)
      }
    } else if matched > 0 {
      matched = failure[matched - 1]
    } else {
      i += 1
    }
  }
  None
}

///|
fn match_pattern(value : String, pattern : Array[PatternPart]) -> Bool {
  let segments : Array[Array[Char]] = [[]]
  for part in pattern {
    match part {
      AnySequence => segments.push([])
      PatternChar(c) => segments[segments.length() - 1].push(c)
    }
  }
  let text = value.to_array()
  let first = segments[0]
  if segments.length() == 1 {
    if first.length() != text.length() {
      return false
    }
    for i in 0..<first.length() {
      if first[i] != text[i] {
        return false
      }
    }
    return true
  }
  let last = segments[segments.length() - 1]
  if first.length() + last.length() > text.length() {
    return false
  }
  for i in 0..<first.length() {
    if first[i] != text[i] {
      return false
    }
  }
  let boundary = text.length() - last.length()
  for i in 0..<last.length() {
    if last[i] != text[boundary + i] {
      return false
    }
  }
  let mut position = first.length()
  for i in 1..<(segments.length() - 1) {
    match find_segment(text, segments[i], position, boundary) {
      Some(found) => position = found + segments[i].length()
      None => return false
    }
  }
  true
}
