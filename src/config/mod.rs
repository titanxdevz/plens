use crate::error::{PlensError, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_preset")]
    pub default_preset: String,

    #[serde(default)]
    pub default_profile: Option<String>,

    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    #[serde(default = "default_nmap_path")]
    pub nmap_path: String,

    #[serde(default = "default_theme")]
    pub theme: String,

    #[serde(default)]
    pub allowlist: Vec<String>,

    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    #[serde(default = "default_retention_scans")]
    pub retention_scans: u32,

    #[serde(default)]
    pub discord_webhook: Option<String>,

    #[serde(default)]
    pub generic_webhook: Option<String>,

    #[serde(default)]
    pub custom_rules_path: Option<String>,

    #[serde(default)]
    pub custom_profiles_dir: Option<String>,

    #[serde(default)]
    pub custom_presets_dir: Option<String>,
}

fn default_preset() -> String {
    "standard".to_string()
}

fn default_concurrency() -> usize {
    1000
}

fn default_timeout_ms() -> u64 {
    800
}

fn default_nmap_path() -> String {
    "nmap".to_string()
}

fn default_theme() -> String {
    "auto".to_string()
}

fn default_retention_days() -> u32 {
    90
}

fn default_retention_scans() -> u32 {
    500
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_preset: default_preset(),
            default_profile: None,
            concurrency: default_concurrency(),
            timeout_ms: default_timeout_ms(),
            nmap_path: default_nmap_path(),
            theme: default_theme(),
            allowlist: Vec::new(),
            retention_days: default_retention_days(),
            retention_scans: default_retention_scans(),
            discord_webhook: None,
            generic_webhook: None,
            custom_rules_path: None,
            custom_profiles_dir: None,
            custom_presets_dir: None,
        }
    }
}

impl Config {
    pub fn config_dir() -> PathBuf {
        if let Ok(dir) = env::var("PLENS_CONFIG_DIR") {
            return PathBuf::from(dir);
        }
        if let Some(proj_dirs) = ProjectDirs::from("com", "PortLens", "plens") {
            proj_dirs.config_dir().to_path_buf()
        } else {
            PathBuf::from(".config/plens")
        }
    }

    pub fn data_dir() -> PathBuf {
        if let Ok(dir) = env::var("PLENS_DATA_DIR") {
            return PathBuf::from(dir);
        }
        if let Some(proj_dirs) = ProjectDirs::from("com", "PortLens", "plens") {
            proj_dirs.data_dir().to_path_buf()
        } else {
            PathBuf::from(".local/share/plens")
        }
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn db_path() -> PathBuf {
        Self::data_dir().join("plens.db")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        let mut config = if path.exists() {
            let content = fs::read_to_string(&path).map_err(|e| PlensError::Config {
                message: format!("Failed to read {}: {}", path.display(), e),
            })?;
            toml::from_str::<Config>(&content).map_err(|e| PlensError::Config {
                message: format!("Failed to parse {}: {}", path.display(), e),
            })?
        } else {
            Config::default()
        };

        // Apply PLENS_* environment overrides
        if let Ok(preset) = env::var("PLENS_PRESET") {
            config.default_preset = preset;
        }
        if let Ok(profile) = env::var("PLENS_PROFILE") {
            config.default_profile = Some(profile);
        }
        if let Ok(conc) = env::var("PLENS_CONCURRENCY") {
            if let Ok(v) = conc.parse::<usize>() {
                config.concurrency = v;
            }
        }
        if let Ok(t) = env::var("PLENS_TIMEOUT_MS") {
            if let Ok(v) = t.parse::<u64>() {
                config.timeout_ms = v;
            }
        }
        if let Ok(nmap) = env::var("PLENS_NMAP_PATH") {
            config.nmap_path = nmap;
        }
        if let Ok(theme) = env::var("PLENS_THEME") {
            config.theme = theme;
        }
        if let Ok(allow) = env::var("PLENS_ALLOWLIST") {
            config.allowlist = allow
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(hook) = env::var("PLENS_DISCORD_WEBHOOK") {
            config.discord_webhook = Some(hook);
        }
        if let Ok(hook) = env::var("PLENS_WEBHOOK") {
            config.generic_webhook = Some(hook);
        }

        Ok(config)
    }

    pub fn save(&self, path: Option<&Path>) -> Result<()> {
        let target_path = match path {
            Some(p) => p.to_path_buf(),
            None => Self::config_path(),
        };

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).map_err(|e| PlensError::Config {
                message: format!("Failed to create directory {}: {}", parent.display(), e),
            })?;
        }

        let serialized = toml::to_string_pretty(self).map_err(|e| PlensError::Config {
            message: format!("Failed to serialize config: {}", e),
        })?;

        fs::write(&target_path, serialized).map_err(|e| PlensError::Config {
            message: format!("Failed to write config to {}: {}", target_path.display(), e),
        })?;

        Ok(())
    }
}
