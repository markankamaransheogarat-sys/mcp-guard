use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{GuardError, Result};

/// Top-level `mcp-guard.toml` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Logical server name used in audit logs and per-server overrides.
    pub server: String,
    /// Tool allowlist / denylist policy.
    pub tools: ToolPolicy,
    /// Filesystem path-jail and sensitive file policy.
    pub paths: PathPolicy,
    /// Network / URL and SSRF policy.
    pub network: NetworkPolicy,
    /// Rate limiting and loop-breaker policy.
    pub rate_limit: RateLimitPolicy,
    /// Output sanitizer (secret redaction + prompt injection defense).
    pub sanitizer: SanitizerPolicy,
    /// Structured JSONL audit logging configuration.
    pub audit: AuditPolicy,
    /// Optional per-server overrides keyed by server name.
    pub servers: BTreeMap<String, ServerOverride>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            server: "default".to_string(),
            tools: ToolPolicy::default(),
            paths: PathPolicy::default(),
            network: NetworkPolicy::default(),
            rate_limit: RateLimitPolicy::default(),
            sanitizer: SanitizerPolicy::default(),
            audit: AuditPolicy::default(),
            servers: BTreeMap::new(),
        }
    }
}

impl PolicyConfig {
    /// Load policy from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw).map_err(|source| GuardError::TomlParse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        Ok(cfg)
    }

    /// Return a new `PolicyConfig` with any `[servers.<name>]` override applied.
    pub fn for_server(&self, name: &str) -> Self {
        let mut effective = self.clone();
        effective.server = name.to_string();
        if let Some(ov) = self.servers.get(name) {
            if let Some(tools) = &ov.tools {
                effective.tools = tools.clone();
            }
            if let Some(paths) = &ov.paths {
                effective.paths = paths.clone();
            }
            if let Some(network) = &ov.network {
                effective.network = network.clone();
            }
            if let Some(rate_limit) = &ov.rate_limit {
                effective.rate_limit = rate_limit.clone();
            }
            if let Some(sanitizer) = &ov.sanitizer {
                effective.sanitizer = sanitizer.clone();
            }
        }
        effective
    }
}

/// Optional per-server policy overrides.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerOverride {
    pub tools: Option<ToolPolicy>,
    pub paths: Option<PathPolicy>,
    pub network: Option<NetworkPolicy>,
    pub rate_limit: Option<RateLimitPolicy>,
    pub sanitizer: Option<SanitizerPolicy>,
}

/// Tool allowlist and denylist rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolPolicy {
    /// If non-empty, only tools matching this list are allowed.
    pub allow: Vec<String>,
    /// Tools explicitly denied (takes precedence over `allow`).
    pub deny: Vec<String>,
    /// Filter denied / non-allowlisted tools out of `tools/list` server responses.
    #[serde(default = "default_true")]
    pub filter_tools_list: bool,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            filter_tools_list: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Filesystem path-jail and sensitive path rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PathPolicy {
    /// Allowed root directories. Empty means no directory restriction beyond denied patterns.
    pub allowed_dirs: Vec<PathBuf>,
    /// Additional glob patterns to deny.
    pub denied_patterns: Vec<String>,
    /// Enforce hard default bans on `~/.ssh`, `~/.aws`, `~/.gnupg`, `**/.env*`, `*credentials*`.
    pub deny_default_sensitive: bool,
    /// Whether symlinks resolving outside `allowed_dirs` are rejected (always false = reject escape).
    pub allow_symlink_escape: bool,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            allowed_dirs: Vec::new(),
            denied_patterns: Vec::new(),
            deny_default_sensitive: true,
            allow_symlink_escape: false,
        }
    }
}

/// Network / URL policy and SSRF protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkPolicy {
    /// If non-empty, only these domains (or `*.domain`) are permitted.
    pub allowed_domains: Vec<String>,
    /// Domains explicitly blocked.
    pub denied_domains: Vec<String>,
    /// Block loopback, private RFC1918, link-local, and cloud metadata IPs.
    pub block_private_ips: bool,
    /// Resolve domain names via DNS and block if any resolved IP is private/metadata.
    pub resolve_dns: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            block_private_ips: true,
            resolve_dns: false,
        }
    }
}

/// Rate limit and repeated-call loop-breaker settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitPolicy {
    /// Maximum tool calls allowed per 60-second sliding window (0 = unlimited).
    pub max_calls_per_minute: u32,
    /// Maximum identical `(tool, args)` calls within `loop_window_secs` before breaking (0 = disabled).
    pub loop_breaker_threshold: u32,
    /// Sliding window in seconds for loop-breaker detection.
    pub loop_window_secs: u64,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_calls_per_minute: 120,
            loop_breaker_threshold: 5,
            loop_window_secs: 60,
        }
    }
}

/// How prompt-injection patterns in tool outputs are handled.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum InjectionMode {
    /// Wrap suspicious content with warning tags so the LLM treats it as untrusted data.
    #[default]
    Tag,
    /// Replace/block the response with a policy denial.
    Block,
    /// Disable prompt-injection scanning.
    Off,
}

/// Output sanitizer and secret redaction configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SanitizerPolicy {
    /// Redact known secret patterns (AWS, GitHub, OpenAI, Anthropic, JWT, PEM).
    pub redact_secrets: bool,
    /// Redact high-entropy token-like strings.
    pub detect_high_entropy: bool,
    /// Shannon entropy threshold (bits/char) for high-entropy detection.
    pub entropy_threshold: f64,
    /// Action when prompt injection is detected in tool output.
    pub prompt_injection_mode: InjectionMode,
}

impl Default for SanitizerPolicy {
    fn default() -> Self {
        Self {
            redact_secrets: true,
            detect_high_entropy: true,
            entropy_threshold: 4.5,
            prompt_injection_mode: InjectionMode::Tag,
        }
    }
}

/// Audit log configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditPolicy {
    /// Whether JSONL audit logging is enabled.
    pub enabled: bool,
    /// Path to the JSONL audit log file.
    pub path: PathBuf,
    /// Rotate when file exceeds this size in bytes.
    pub max_file_bytes: u64,
    /// Number of rotated `.1`, `.2`, ... files to retain.
    pub max_rotated_files: usize,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        let default_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mcp-guard")
            .join("audit.jsonl");
        Self {
            enabled: true,
            path: default_path,
            max_file_bytes: 10 * 1024 * 1024, // 10 MiB
            max_rotated_files: 5,
        }
    }
}
