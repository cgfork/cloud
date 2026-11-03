mod aliyun;
mod cli;
mod config;
mod mfa;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;

use crate::cli::{AliyunCommand, Cli, Command};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Mfa(args) => println!("{}", mfa::generate(&args)?),
        Command::Aliyun { command } => {
            let config_path = cli.config.unwrap_or_else(config::default_path);
            let config = config::AppConfig::load(&config_path)?;

            match command {
                AliyunCommand::Sts(args) => {
                    let token: Value = aliyun::assume_role(&config.aliyun, &args)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&token)
                            .context("failed to format STS response")?
                    );
                }
            }
        }
    }

    Ok(())
}
