use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardiTree {
  pub types: HashMap<String, TypeDefinition>,
  pub api: HashMap<String, Endpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefinition {
  // Храним поля типа: "email" -> "!string"
  pub fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
  pub method: String,
  pub headers: Option<HashMap<String, String>>,
  pub response: String, // Ссылка на тип из types
}