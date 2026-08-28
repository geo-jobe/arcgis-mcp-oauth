use std::collections::{HashMap, HashSet};
use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("missing config file: {0}")]
    MissingFile(PathBuf),
    #[error("invalid environment variable `{name}`: {source}")]
    EnvVar {
        name: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("INTERNAL_API_KEY must be set")]
    MissingInternalApiKey,
    #[error("cimd_allow_private_addresses cannot be enabled in production")]
    UnsafeCimdProductionPolicy,
    #[error("invalid auth settings: {0}")]
    InvalidAuthSettings(String),
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ArcgisPortalConfig {
    pub key: String,
    pub label: String,
    pub portal_url: String,
    pub api_root: String,
    pub portal_apps: String,
    pub client_id: String,
    pub stories_root: String,
}

#[derive(Clone, Debug)]
pub struct PortalRegistry {
    portals: HashMap<String, ArcgisPortalConfig>,
    ordered: Vec<ArcgisPortalConfig>,
}

impl PortalRegistry {
    pub fn from_portals(portals: Vec<ArcgisPortalConfig>) -> Result<Self, String> {
        if portals.is_empty() {
            return Err("arcgis_portals must contain at least one portal".into());
        }

        let mut seen = HashSet::new();
        let mut map = HashMap::new();
        let mut ordered = Vec::with_capacity(portals.len());

        for portal in portals {
            if portal.key.trim().is_empty() {
                return Err("arcgis_portals entry has empty key".into());
            }
            if portal.label.trim().is_empty() {
                return Err(format!(
                    "arcgis_portals entry '{}' has empty label",
                    portal.key
                ));
            }
            if portal.portal_url.trim().is_empty() {
                return Err(format!(
                    "arcgis_portals entry '{}' has empty portal_url",
                    portal.key
                ));
            }
            if portal.client_id.trim().is_empty() {
                return Err(format!(
                    "arcgis_portals entry '{}' has empty client_id",
                    portal.key
                ));
            }
            if !seen.insert(portal.key.clone()) {
                return Err(format!("duplicate arcgis_portals key '{}'", portal.key));
            }

            ordered.push(portal.clone());
            map.insert(portal.key.clone(), portal);
        }

        Ok(Self {
            portals: map,
            ordered,
        })
    }

    pub fn get(&self, key: &str) -> Option<&ArcgisPortalConfig> {
        self.portals.get(key)
    }

    pub fn list(&self) -> &[ArcgisPortalConfig] {
        &self.ordered
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Settings {
    pub address: String,
    pub port: u16,
    pub public_base_url: String,
    #[serde(default)]
    pub cimd_allow_private_addresses: bool,
    #[serde(default)]
    pub auth: AuthSettings,
    pub arcgis_portals: Vec<ArcgisPortalConfig>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, rename_all = "snake_case")]
pub struct AuthSettings {
    pub mcp_access_token_lifetime_seconds: i64,
    pub session_max_age_seconds: i64,
    pub session_inactivity_timeout_seconds: i64,
    pub mcp_refresh_replay_window_seconds: i64,
    pub arcgis_access_refresh_buffer_seconds: i64,
    pub arcgis_refresh_renewal_buffer_seconds: i64,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            mcp_access_token_lifetime_seconds: 60 * 60,
            session_max_age_seconds: 90 * 24 * 60 * 60,
            session_inactivity_timeout_seconds: 30 * 24 * 60 * 60,
            mcp_refresh_replay_window_seconds: 30,
            arcgis_access_refresh_buffer_seconds: 5 * 60,
            arcgis_refresh_renewal_buffer_seconds: 24 * 60 * 60,
        }
    }
}

impl AuthSettings {
    pub fn validate(&self) -> Result<(), String> {
        let values = [
            (
                "mcp_access_token_lifetime_seconds",
                self.mcp_access_token_lifetime_seconds,
            ),
            ("session_max_age_seconds", self.session_max_age_seconds),
            (
                "session_inactivity_timeout_seconds",
                self.session_inactivity_timeout_seconds,
            ),
            (
                "mcp_refresh_replay_window_seconds",
                self.mcp_refresh_replay_window_seconds,
            ),
            (
                "arcgis_access_refresh_buffer_seconds",
                self.arcgis_access_refresh_buffer_seconds,
            ),
            (
                "arcgis_refresh_renewal_buffer_seconds",
                self.arcgis_refresh_renewal_buffer_seconds,
            ),
        ];
        if let Some((name, _)) = values.into_iter().find(|(_, value)| *value <= 0) {
            return Err(format!("{name} must be greater than zero"));
        }
        if self.session_inactivity_timeout_seconds > self.session_max_age_seconds {
            return Err(
                "session_inactivity_timeout_seconds cannot exceed session_max_age_seconds".into(),
            );
        }
        if self.mcp_refresh_replay_window_seconds >= self.mcp_access_token_lifetime_seconds {
            return Err("mcp_refresh_replay_window_seconds must be shorter than mcp_access_token_lifetime_seconds".into());
        }
        let now = chrono::Utc::now().timestamp();
        for (name, value) in values {
            if now.checked_add(value).is_none() {
                return Err(format!("{name} is too large"));
            }
        }
        Ok(())
    }
}

pub fn get_config() -> Result<(Settings, String), ConfigError> {
    dotenvy::dotenv().ok();
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let config_dir = base_path.join("config");

    let env: Environment = std::env::var("APP_ENV")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENV");

    tracing::info!(environment = env.as_str(), "Configuration loaded");

    let env_file = format!("{}.toml", env.as_str());
    let config_path = config_dir.join(&env_file);
    let contents = std::fs::read_to_string(&config_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ConfigError::MissingFile(config_path)
        } else {
            ConfigError::Io(e)
        }
    })?;

    let mut settings: Settings = toml::from_str(&contents)?;
    apply_env_overrides(&mut settings)?;
    settings
        .auth
        .validate()
        .map_err(ConfigError::InvalidAuthSettings)?;
    if matches!(env, Environment::Production) && settings.cimd_allow_private_addresses {
        return Err(ConfigError::UnsafeCimdProductionPolicy);
    }

    let internal_api_key =
        std::env::var("INTERNAL_API_KEY").map_err(|_| ConfigError::MissingInternalApiKey)?;

    Ok((settings, internal_api_key))
}

fn apply_env_overrides(settings: &mut Settings) -> Result<(), ConfigError> {
    if let Ok(value) = std::env::var("ADDRESS") {
        settings.address = value;
    } else if let Ok(value) = std::env::var("AUTH_ADDRESS") {
        settings.address = value;
    }
    if let Ok(value) = std::env::var("PORT") {
        settings.port = value.parse().map_err(|e| ConfigError::EnvVar {
            name: "PORT".into(),
            source: Box::new(e),
        })?;
    } else if let Ok(value) = std::env::var("AUTH_PORT") {
        settings.port = value.parse().map_err(|e| ConfigError::EnvVar {
            name: "AUTH_PORT".into(),
            source: Box::new(e),
        })?;
    }
    if let Ok(value) = std::env::var("PUBLIC_BASE_URL") {
        settings.public_base_url = value;
    } else if let Ok(value) = std::env::var("ARCGIS_PUBLIC_BASE_URL") {
        settings.public_base_url = value;
    }
    if let Ok(value) = std::env::var("CIMD_ALLOW_PRIVATE_ADDRESSES") {
        settings.cimd_allow_private_addresses = value.parse().map_err(|e| ConfigError::EnvVar {
            name: "CIMD_ALLOW_PRIVATE_ADDRESSES".into(),
            source: Box::new(e),
        })?;
    }
    Ok(())
}

pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl std::convert::TryFrom<String> for Environment {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "local" => Ok(Environment::Local),
            "production" => Ok(Environment::Production),
            _ => Err(format!("{} is not a valid environment", value)),
        }
    }
}

impl Settings {
    pub fn socket_address(&self) -> Result<SocketAddr, AddrParseError> {
        format!("{}:{}", self.address, self.port).parse()
    }

    pub fn portal_registry(&self) -> Result<PortalRegistry, String> {
        PortalRegistry::from_portals(self.arcgis_portals.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::AuthSettings;

    #[test]
    fn auth_settings_reject_zero_and_inconsistent_durations() {
        let settings = AuthSettings {
            mcp_access_token_lifetime_seconds: 0,
            ..AuthSettings::default()
        };
        assert!(settings.validate().is_err());

        let settings = AuthSettings {
            session_inactivity_timeout_seconds: AuthSettings::default().session_max_age_seconds + 1,
            ..AuthSettings::default()
        };
        assert!(settings.validate().is_err());

        let settings = AuthSettings {
            mcp_refresh_replay_window_seconds: AuthSettings::default()
                .mcp_access_token_lifetime_seconds,
            ..AuthSettings::default()
        };
        assert!(settings.validate().is_err());
    }
}
