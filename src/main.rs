use clap::{Parser, Subcommand};
mod core;

#[derive(Parser)]
#[command(name = "guardi")]
#[command(about = "Guardi CLI: Contract Enforcement for AI-generated code", long_about = None)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  /// Проверить живой сервис на соответствие дереву
  Check {
    #[arg(short, long)]
    tree: String,
    #[arg(short, long)]
    url: String,
  },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();

  match &cli.command {
    Commands::Check { tree, url } => {
      println!("🔍 Загрузка контракта: {}", tree);
      // 1. Читаем файл
      let content = std::fs::read_to_string(tree)?;
      let contract: core::contract::GuardiTree = serde_yaml::from_str(&content)?;

      println!("🚀 Начинаю валидацию сервиса: {}", url);
      
      // 2. Проходим по всем эндпоинтам из дерева
      for (path, details) in contract.api {
        let full_url = format!("{}{}", url, path);
        println!("📡 Проверка {} {}...", details.method, full_url);
        
        // Здесь будет логика вызова через reqwest и сравнение типов
        // TODO: Реализовать логику сопоставления типов (Match)
      }
    }
  }

  Ok(())
}