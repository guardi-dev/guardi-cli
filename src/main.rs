use colored::*;
use std::env;
use std::net::{IpAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::{Record, RData};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // update /etc/nsswitch.conf
    let nsswitch_path = "/etc/nsswitch.conf";
    let nss_content = fs::read_to_string(nsswitch_path).unwrap_or_default();
    let updated_nss = nss_content.replace("files dns", "dns files");
    fs::write(nsswitch_path, updated_nss).ok();

    // Парсим аргументы: guardi <cmd> --allow domain1,domain2
    let args: Vec<String> = env::args().collect();
    let allow_idx = args.iter().position(|r| r == "--allow")
        .expect("Usage: guardi <cmd> --allow domain1,domain2");

    let cmd_args = &args[1..allow_idx];
    let allowed_str = &args[allow_idx + 1];
    let allowed_domains: Arc<Vec<String>> = Arc::new(
        allowed_str.split(',').map(|s| s.trim().to_lowercase()).collect()
    );

    // 1. Настройка DNS-прокси
    // В контейнере обычно можно биндить 53 порт, если запускать от root (дефолт в Docker)
    let dns_addr = "127.0.0.1:53";
    let socket = UdpSocket::bind(dns_addr).await
        .expect("Не удалось занять порт 53. Попробуй запустить от root или проверь права.");
    
    let arc_socket = Arc::new(socket);
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    );

    println!("{}", "🛡️  Guardi: Network Monitoring Active".bold().cyan());
    println!("📡 Allowed domains: {}", allowed_str.green());

    // 2. Запуск DNS-обработчика в фоновом потоке
    let dns_socket = arc_socket.clone();
    let domains = allowed_domains.clone();
    
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            if let Ok((len, src)) = dns_socket.recv_from(&mut buf).await {
                let request = match Message::from_vec(&buf[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let mut response = request.clone();
                response.set_message_type(MessageType::Response);
                
                let query = &request.queries()[0];
                let name_full = query.name().to_string().to_lowercase();
                let name = name_full.trim_end_matches('.').to_string();

                let is_allowed = domains.iter().any(|d| name.contains(d)) || name == "localhost";

                if is_allowed {
                    // Разрешаем: идем в реальный DNS
                    if let Ok(lookup) = resolver.lookup_ip(&name_full).await {
                        println!("{} {} {}", "🟢".green(), "ALLOWED:".bold(), name.white());
                        for ip in lookup.iter() {
                            let rdata = match ip {
                                IpAddr::V4(ipv4) => RData::A(trust_dns_proto::rr::rdata::A(ipv4)),
                                IpAddr::V6(ipv6) => RData::AAAA(trust_dns_proto::rr::rdata::AAAA(ipv6)),
                            };
                            response.add_answer(Record::from_rdata(query.name().clone(), 60, rdata));
                        }
                    }
                } else {
                    // Блокируем: возвращаем NXDOMAIN (домен не найден)
                    println!("{} {} {}", "🔴".red(), "BLOCKED:".bold(), name.yellow());
                    response.set_response_code(ResponseCode::NXDomain);
                }

                let _ = dns_socket.send_to(&response.to_vec().unwrap(), &src).await;
            }
        }
    });

    // 3. Запуск целевого процесса
    let mut child = Command::new(&cmd_args[0])
        .args(&cmd_args[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Не удалось запустить целевую команду");

    // 4. Ожидание завершения
    let status = child.wait()?;
    println!("\n{}", format!("🏁 Процесс завершен с кодом: {}", status).bold().blue());

    Ok(())
}