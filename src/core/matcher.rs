use super::contract::TypeDefinition;

pub struct ValidationResult {
  pub is_valid: bool,
  pub errors: Vec<String>,
}

pub fn validate_response(expected_type: &TypeDefinition, actual_json: &serde_json::Value) -> ValidationResult {
  let mut errors = Vec::new();
  
  // Логика сверки полей:
  // 1. Проверить, что в JSON есть все поля из TypeDefinition
  // 2. Проверить, что типы данных совпадают (например, !string == JSON String)
  // 3. (Для параноиков) Проверить, нет ли в JSON ЛИШНИХ полей
  
  ValidationResult {
    is_valid: errors.is_empty(),
    errors,
  }
}