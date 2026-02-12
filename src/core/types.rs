pub enum Primitive {
  Str,
  Int,
  Bool,
}

impl Primitive {
  pub fn from_str(s: &str) -> Option<Self> {
    match s {
      "!string" => Some(Primitive::Str),
      "!int" => Some(Primitive::Int),
      "!bool" => Some(Primitive::Bool),
      _ => None,
    }
  }
}