use clap::Parser;

#[derive(Parser)]
#[command(name = "agentsight-local", about = "本地 AI agent 轨迹查看器")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 7397)]
    port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    agentsight_local::server::run_server(&cli.host, cli.port).await
}
