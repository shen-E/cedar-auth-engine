///|
/// Validate the entity type name using Cedar's identifier and namespace rules.
/// Entity IDs themselves may be arbitrary strings, including empty strings.
pub fn EntityId::validate(self : EntityId) -> Unit raise PolicyError {
  for segment in self.kind.split("::") {
    let part = segment.to_owned()
    let chars = part.to_array()
    if chars.is_empty() || !type_identifier(part) {
      raise PolicyError("invalid entity type name")
    }
    for i in 1..<chars.length() {
      let c = chars[i]
      if !((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '_') {
        raise PolicyError("invalid entity type name")
      }
    }
  }
}
