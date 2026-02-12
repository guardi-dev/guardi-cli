mod core;

use pcap::{Capture};
use crate::core::process_packet::process_packet;

fn main() {
  // 1. Выбираем интерфейс (например, "lo0" или "any")

  let mut cap = Capture::from_device("any")
    .unwrap()
    .immediate_mode(true)
    .open()
    .unwrap();

  // For initial development we will handle all outgoing requests
  // and for example default pg database port
  let filter = "(dst net not 127.0.0.0/8) or (tcp port 5432 or tcp port 6379 or tcp port 8080)";
  cap.filter(filter, true).expect("BPF Filter Error");

  println!("Guardi Observer started. Watching for outgoing packets...");

  loop {
    match cap.next_packet() {
      Ok(packet) => process_packet(&packet.data),
      Err(pcap::Error::TimeoutExpired) => continue, // Это нормально
      Err(e) => {
        eprintln!("⚠️ PCAP ERROR: {:?}", e); // Это скажет, почему мы упали
        break;
      }
    }
  }
}