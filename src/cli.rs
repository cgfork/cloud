use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const DEFAULT_STS_ENDPOINT: &str = "sts.aliyuncs.com";
pub const DEFAULT_SESSION_NAME: &str = "cloud";
pub const DEFAULT_DURATION: &str = "1h";

#[derive(Debug, Parser)]
#[command(
    name = "cloud",
    version,
    about = "Cloud provider command line utilities"
)]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Aliyun cloud commands")]
    Aliyun {
        #[command(subcommand)]
        command: AliyunCommand,
    },
    #[command(about = "Generate a time-based one-time password")]
    Mfa(MfaArgs),
}

#[derive(Debug, Subcommand)]
pub enum AliyunCommand {
    #[command(about = "Acquire a temporary STS token with AssumeRole")]
    Sts(StsArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OtpAlgorithm {
    #[value(name = "sha1")]
    Sha1,
    #[value(name = "sha256")]
    Sha256,
    #[value(name = "sha512")]
    Sha512,
}

#[derive(Debug, Args)]
pub struct MfaArgs {
    #[arg(value_name = "SECRET", help = "Base32-encoded TOTP secret")]
    pub secret: String,
    #[arg(
        short,
        long,
        value_name = "DIGITS",
        default_value_t = 6,
        help = "Number of digits in the generated code"
    )]
    pub digits: usize,
    #[arg(
        short,
        long,
        value_name = "SECONDS",
        default_value_t = 30,
        help = "Time step period in seconds"
    )]
    pub period: u64,
    #[arg(
        short,
        long,
        value_enum,
        value_name = "ALGORITHM",
        default_value = "sha1",
        help = "Hash algorithm"
    )]
    pub algorithm: OtpAlgorithm,
}

#[derive(Debug, Args)]
pub struct StsArgs {
    #[arg(
        long,
        value_name = "ENDPOINT",
        default_value = DEFAULT_STS_ENDPOINT,
        help = "STS endpoint URL or host"
    )]
    pub endpoint: String,
    #[arg(long, value_name = "ARN", help = "RAM role ARN to assume")]
    pub role_arn: String,
    #[arg(
        long,
        value_name = "NAME",
        default_value = DEFAULT_SESSION_NAME,
        help = "Role session name"
    )]
    pub role_session_name: String,
    #[arg(
        long,
        value_name = "DURATION",
        default_value = DEFAULT_DURATION,
        value_parser = parse_duration,
        help = "Session duration (e.g. 12m, 12s, 1d)"
    )]
    pub duration: Duration,
    #[arg(long, value_name = "ID", help = "External ID for cross-account access")]
    pub external_id: Option<String>,
    #[arg(long, value_name = "JSON", help = "Inline session policy JSON")]
    pub policy: Option<String>,
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let input = value.trim();
    if input.is_empty() {
        return Err("duration cannot be empty".to_owned());
    }

    let mut total_seconds = 0u64;
    let mut remaining = input;
    let mut parsed_any = false;

    while !remaining.is_empty() {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        let number_len = remaining
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(remaining.len());
        if number_len == 0 {
            return Err(invalid_duration(input));
        }
        let number = remaining[..number_len]
            .parse::<u64>()
            .map_err(|_| invalid_duration(input))?;
        remaining = remaining[number_len..].trim_start();

        let unit_len = remaining
            .find(|character: char| !character.is_ascii_alphabetic())
            .unwrap_or(remaining.len());
        if unit_len == 0 {
            return Err(invalid_duration(input));
        }
        let unit = &remaining[..unit_len];
        remaining = &remaining[unit_len..];

        let multiplier = match unit {
            "s" | "sec" | "secs" | "second" | "seconds" => 1,
            "m" | "min" | "mins" | "minute" | "minutes" => 60,
            "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
            "d" | "day" | "days" => 24 * 60 * 60,
            "w" | "week" | "weeks" => 7 * 24 * 60 * 60,
            _ => return Err(invalid_duration(input)),
        };

        let seconds = number
            .checked_mul(multiplier)
            .and_then(|seconds| total_seconds.checked_add(seconds))
            .ok_or_else(|| format!("duration '{input}' is too large"))?;
        total_seconds = seconds;
        parsed_any = true;
    }

    if !parsed_any {
        return Err(invalid_duration(input));
    }

    Ok(Duration::from_secs(total_seconds))
}

fn invalid_duration(input: &str) -> String {
    format!("invalid duration '{input}'; expected values like 12m, 12s, or 1d")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("12m"), Ok(Duration::from_secs(720)));
        assert_eq!(parse_duration("12s"), Ok(Duration::from_secs(12)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86_400)));
        assert_eq!(parse_duration("1h 30m"), Ok(Duration::from_secs(5_400)));
    }

    #[test]
    fn rejects_invalid_duration() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("12").is_err());
        assert!(parse_duration("12x").is_err());
    }

    #[test]
    fn sts_duration_accepts_human_readable_value() {
        let cli = Cli::try_parse_from([
            "cloud",
            "aliyun",
            "sts",
            "--role-arn",
            "acs:ram::1234567890123456:role/example",
            "--duration",
            "12m",
        ])
        .unwrap();

        let Command::Aliyun {
            command: AliyunCommand::Sts(args),
        } = cli.command
        else {
            panic!("expected aliyun sts command");
        };
        assert_eq!(args.duration, Duration::from_secs(720));
    }

    #[test]
    fn mfa_options_parse() {
        let cli = Cli::try_parse_from([
            "cloud",
            "mfa",
            "TVWKH4OQUHL4BVRF",
            "--digits",
            "8",
            "--period",
            "60",
            "--algorithm",
            "sha256",
        ])
        .unwrap();

        let Command::Mfa(args) = cli.command else {
            panic!("expected mfa command");
        };
        assert_eq!(args.secret, "TVWKH4OQUHL4BVRF");
        assert_eq!(args.digits, 8);
        assert_eq!(args.period, 60);
        assert_eq!(args.algorithm, OtpAlgorithm::Sha256);
    }
}
