use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use config::{Config as ConfigBuilder, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub aliyun: AliyunConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AliyunConfig {
    pub access_key_id: Option<String>,
    pub access_key_secret: Option<String>,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = ConfigBuilder::builder()
            .add_source(File::from(path.to_path_buf()).required(false))
            .add_source(
                Environment::with_prefix("CLOUD")
                    .prefix_separator("_")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .with_context(|| format!("failed to load config from {}", path.display()))?
            .try_deserialize()
            .with_context(|| format!("invalid config in {}", path.display()))?;

        apply_env_aliases(&mut config);
        Ok(config)
    }
}

pub fn default_path() -> PathBuf {
    if let Some(path) = env::var_os("CLOUD_CONFIG") {
        return PathBuf::from(path);
    }

    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("cloud/config.yaml")
}

fn apply_env_aliases(config: &mut AppConfig) {
    set_string(
        &mut config.aliyun.access_key_id,
        &["ALIYUN_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID"],
    );
    set_string(
        &mut config.aliyun.access_key_secret,
        &[
            "ALIYUN_ACCESS_KEY_SECRET",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        ],
    );
}

fn set_string(target: &mut Option<String>, names: &[&str]) {
    if let Some(value) = env_value(names) {
        *target = Some(value);
    }
}

fn env_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn loads_yaml_config() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        fs::write(
            &path,
            r#"
aliyun:
  access_key_id: test-id
  access_key_secret: test-secret
"#,
        )
        .unwrap();

        let config = AppConfig::load(&path).unwrap();

        assert_eq!(config.aliyun.access_key_id.as_deref(), Some("test-id"));
        assert_eq!(
            config.aliyun.access_key_secret.as_deref(),
            Some("test-secret")
        );
    }

    #[test]
    fn missing_config_file_is_allowed() {
        let directory = tempdir().unwrap();
        let config = AppConfig::load(&directory.path().join("missing.yaml")).unwrap();

        assert!(config.aliyun.access_key_id.is_none());
        assert!(config.aliyun.access_key_secret.is_none());
    }
}
