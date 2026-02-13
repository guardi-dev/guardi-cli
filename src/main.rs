use pcap::{Capture, Device};
use std::process::{Command};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("curl");
    cmd.args(["-X", "POST", "-d", "password=123", "http://httpbin.org/post"]);

    let device = Device::lookup()?.expect("No device found");
    let mut cap = Capture::from_device(device)?
        .immediate_mode(true)
        .timeout(200) // 200мс ожидания, чтобы цикл не блокировался навсегда
        .open()?;

    let mut child = cmd.spawn()?;
    let target_pid = child.id();
    println!("🛡️ Guardi мониторит PID: {}", target_pid);

    let mut process_finished = false;
    let mut finish_time: Option<Instant> = None;
    let grace_period = Duration::from_secs(2); // Ждем 2 сек после выхода процесса для "хвостов"

    loop {
        // 1. Пытаемся поймать пакет
        match cap.next_packet() {
            Ok(packet) => {
                let payload = packet.data;
                if payload.len() > 38 {
                    let src_port = u16::from_be_bytes([payload[34], payload[35]]);
                    if is_port_owned_by_pid(target_pid, src_port) {
                        println!("🎯 Пакет от PID {}: порт {}", target_pid, src_port);
                        parse_http_payload(payload);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Это нормально, пакетов просто нет в эти 200мс
            }
            Err(e) => {
                eprintln!("Ошибка pcap: {:?}", e);
                break;
            }
        }

        // 2. Проверяем состояние процесса
        if !process_finished {
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!("🏁 Процесс {} завершился с кодом {}. Собираю остатки данных...", target_pid, status);
                    process_finished = true;
                    finish_time = Some(Instant::now());
                }
                Ok(None) => (), // Процесс еще живет
                Err(e) => eprintln!("Ошибка проверки процесса: {}", e),
            }
        }

        // 3. Условие выхода: процесс завершен + прошло время "тишины"
        if process_finished {
            if let Some(time) = finish_time {
                if time.elapsed() > grace_period {
                    println!("✅ Все данные собраны. Завершение Guardi.");
                    break;
                }
            }
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