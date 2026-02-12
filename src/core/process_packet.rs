use std::collections::BTreeSet;
use sha2::{Sha256, Digest};
use httparse;

pub fn process_packet(raw_data: &[u8]) {
    // 1. Ищем начало HTTP-запроса (GET, POST, PUT, DELETE, PATCH, OPTIONS)
    // Это надежнее, чем зашитый offset, так как заголовки IP/TCP могут меняться
    let methods: Vec<&[u8]> = vec![b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HTTP/"];
    
    let mut http_start = None;
    for method in methods {
        // needle.len() теперь будет динамическим (4, 5, 6...)
        if let Some(pos) = find_subsequence(raw_data, method) {
            http_start = Some(pos);
            break;
        }
    }

        // Если ничего не нашли или это начало ответа сервера (HTTP/) — выходим
    if http_start.is_none() || find_subsequence(raw_data, b"HTTP/").is_some_and(|p| p == http_start.unwrap()) {
        return; 
    }
    
    let payload = match http_start {
        Some(pos) => &raw_data[pos..],
        None => {
            // Если это не HTTP, выводим начало данных для диагностики
            if raw_data.len() > 34 { // Пропускаем минимум заголовков
                let sniff = String::from_utf8_lossy(&raw_data[34..std::cmp::min(raw_data.len(), 100)]);
                if sniff.chars().any(|c| c.is_alphanumeric()) {
                    println!("🔍 [RAW DATA SNIFF]: {}", sniff.trim());
                }
            }
            return;
        }
    };

    // 2. Теперь парсим то, что точно начинается как HTTP
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(payload) {
        Ok(httparse::Status::Complete(body_offset)) => {
            handle_http_request(req, payload, body_offset);
        }
        Ok(httparse::Status::Partial) => {
            println!("⏳ [HTTP PARTIAL]: Packet too small, waiting for next fragment...");
        }
        Err(e) => {
            println!("❌ [PARSE ERROR]: {:?} | Data: {:?}", e, String::from_utf8_lossy(&payload[..10]));
        }
    }
}

// Вспомогательная функция для поиска байтов в байте
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Вычленяет ключи из JSON, игнорируя значения.
fn extract_json_keys(body: &[u8]) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(obj) = value.as_object() {
            for k in obj.keys() {
                keys.insert(k.clone());
            }
        }
    }
    keys
}

fn handle_http_request(req: httparse::Request, payload: &[u8], body_offset: usize) {
    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");

    // 1. Ищем заголовок Host
    let mut host = "unknown_host".to_string();
    for header in req.headers {
        if header.name.to_lowercase() == "host" {
            host = String::from_utf8_lossy(header.value).to_string();
            break;
        }
    }

    let body = &payload[body_offset..];
    let fields = extract_json_keys(body);

    // 2. Передаем Host в генератор сигнатуры
    let signature = generate_signature(&host, method, path, &fields);

    println!("🎯 [HTTP CAPTURED]");
    println!("   Host: {}", host);
    println!("   Path: {} {}", method, path);
    println!("   Hash: {}", signature);
}

// Обновленная функция сигнатуры
fn generate_signature(host: &str, method: &str, path: &str, fields: &BTreeSet<String>) -> String {
    let fields_str = fields.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",");
    
    // Включаем HOST в начало Origin String
    let origin_string = format!("{}|{}|{}|{}", host, method.to_uppercase(), path, fields_str);

    let mut hasher = Sha256::new();
    hasher.update(origin_string.as_bytes());
    hex::encode(hasher.finalize())
}