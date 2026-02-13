use pcap::{Capture, Device};
use std::process::{Command};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Настройка цели (curl)
    let mut cmd = Command::new("curl");
    cmd.args(["-X", "POST", "-d", "password=123", "http://httpbin.org/post"]);

    // 2. Инициализация сниффера
    let device = Device::lookup()?.expect("No device found");
    let mut cap = Capture::from_device(device)?
        .immediate_mode(true)
        .timeout(100) // Важно для неблокирующего чтения
        .open()?;

    // 3. Запуск процесса
    let mut child = cmd.spawn()?;
    let target_pid = child.id();
    println!("🛡️  Guardi запущен. Мониторинг PID: {}", target_pid);

    let mut last_activity = Instant::now();
    let grace_period = Duration::from_secs(2); // Даем время после завершения

    // 4. Основной цикл захвата
    loop {
        // Проверяем пакеты
        if let Ok(packet) = cap.next_packet() {
            if let Some(payload) = packet.data.get(0..) {
                // Извлекаем порты (простейший парсинг TCP заголовка)
                // Байты 34-35 — исходный порт, 36-37 — порт назначения (для Ethernet + IPv4)
                if payload.len() > 38 {
                    let src_port = u16::from_be_bytes([payload[34], payload[35]]);
                    
                    // Проверяем, владеет ли наш PID этим портом
                    if is_port_owned_by_pid(target_pid, src_port) {
                        println!("🎯 Захвачен пакет от нашего процесса (Port: {})", src_port);
                        parse_http_payload(payload);
                        last_activity = Instant::now();
                    }
                }
            }
        }

        // Проверяем, жив ли процесс
        match child.try_wait() {
            Ok(Some(status)) => {
                if last_activity.elapsed() > grace_period {
                    println!("✅ Процесс завершен ({}). Тишина в эфире. Выходим.", status);
                    break;
                }
            }
            Ok(None) => (), // Еще работает
            Err(e) => println!("Ошибка ожидания: {}", e),
        }
    }

    Ok(())
}

fn is_port_owned_by_pid(pid: u32, port: u16) -> bool {
    // 1. Пытаемся получить объект процесса
    let prc = match procfs::process::Process::new(pid as i32) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // 2. Получаем список всех открытых файловых дескрипторов
    let fds = match prc.fd() {
        Ok(f) => f,
        Err(_) => return false,
    };

    for fd_res in fds {
        if let Ok(fd) = fd_res {
            // Проверяем, является ли дескриптор сокетом
            if let procfs::process::FDTarget::Socket(inode) = fd.target {
                
                // 3. Сначала проверяем таблицу TCP (IPv4)
                if let Ok(tcp_table) = procfs::net::tcp() {
                    if tcp_table.iter().any(|entry| {
                        entry.inode == inode && entry.local_address.port() == port
                    }) {
                        return true;
                    }
                }

                // 4. Затем проверяем таблицу TCP6 (IPv6)
                // Это важно, так как локальный адрес может быть ::1
                if let Ok(tcp6_table) = procfs::net::tcp6() {
                    if tcp6_table.iter().any(|entry| {
                        entry.inode == inode && entry.local_address.port() == port
                    }) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Парсинг HTTP данных (только Request)
fn parse_http_payload(data: &[u8]) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    
    // Ищем начало HTTP данных (после заголовков Ethernet/IP/TCP ~54 байта)
    let payload_offset = 54; 
    if data.len() > payload_offset {
        let http_part = &data[payload_offset..];
        if let Ok(httparse::Status::Complete(_)) = req.parse(http_part) {
            println!("   🔗 URL: {} {}", req.method.unwrap_or("?"), req.path.unwrap_or("?"));
            
            // Если есть тело (например, POST данные)
            if let Some(body_start) = find_subsequence(http_part, b"\r\n\r\n") {
                let body = &http_part[body_start + 4..];
                if !body.is_empty() {
                    println!("   📦 Body: {}", String::from_utf8_lossy(body));
                }
            }
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}