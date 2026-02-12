pub mod core;

#[cfg(test)]
mod tests {
  use crate::core::contract::TypeDefinition;
  use serde_json::json;
  use std::collections::HashMap;
  use super::core::matcher::validate_response;

  #[test]
  fn test_detect_extra_fields() {
    // 1. Ожидаем только id и email
    let mut fields = HashMap::new();
    fields.insert("id".to_string(), "!string".to_string());
    fields.insert("email".to_string(), "!string".to_string());
    let expected = TypeDefinition { fields };

    // 2. Реальность подкидывает "token" (дыра в безопасности!)
    let actual = json!({
      "id": "user_1",
      "email": "test@test.com",
      "token": "secret_session_token" 
    });

    print!("Actual: {} \n", actual);
    print!("Expected: {}", json!(expected));

    // 3. Просто вызываем функцию, без всяких серверов
    let result = validate_response(&expected, &actual);

    assert!(!result.is_valid);
    assert!(result.errors.iter().any(|e| e.contains("EXTRA FIELD")));
  }
}