use std::path::{Component, Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::PathPolicy;
use crate::error::{GuardError, Result};

/// Validates filesystem paths against traversal, symlink escape, sensitive defaults, and path-jails.
#[derive(Debug, Clone)]
pub struct PathValidator {
    allowed_dirs: Vec<PathBuf>,
    denied_globs: GlobSet,
    deny_default_sensitive: bool,
    allow_symlink_escape: bool,
    home_dir: Option<PathBuf>,
}

impl PathValidator {
    /// Build a `PathValidator` from a `PathPolicy`.
    pub fn new(policy: &PathPolicy) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pat in &policy.denied_patterns {
            builder.add(Glob::new(pat)?);
        }
        let denied_globs = builder.build()?;

        let allowed_dirs = policy
            .allowed_dirs
            .iter()
            .map(|p| resolve_existing_or_lexical(p))
            .collect();

        Ok(Self {
            allowed_dirs,
            denied_globs,
            deny_default_sensitive: policy.deny_default_sensitive,
            allow_symlink_escape: policy.allow_symlink_escape,
            home_dir: dirs::home_dir().map(|p| normalize_canonical(&p)),
        })
    }

    /// Validate a raw path or `file://` URI string.
    pub fn check(&self, raw: &str) -> Result<()> {
        if raw.contains('\0') {
            return Err(GuardError::PolicyDenied(
                "null byte in path argument".to_string(),
            ));
        }

        let stripped = strip_file_scheme(raw);
        let expanded = expand_tilde(stripped, self.home_dir.as_deref());

        // Check for raw `..` traversal when no allowed_dirs are configured or before resolution.
        let has_parent_ref = Path::new(&expanded)
            .components()
            .any(|c| matches!(c, Component::ParentDir));

        let resolved = resolve_existing_or_lexical(&expanded);
        let resolved_str = resolved.to_string_lossy().replace('\\', "/");

        // 1. Hard default sensitive bans
        if self.deny_default_sensitive {
            if let Some(reason) = self.check_default_sensitive(&resolved, &resolved_str) {
                return Err(GuardError::PolicyDenied(reason));
            }
        }

        // 2. User-configured denied globs
        if self.denied_globs.is_match(&resolved) || self.denied_globs.is_match(&resolved_str) {
            return Err(GuardError::PolicyDenied(format!(
                "path '{raw}' matches denied pattern"
            )));
        }

        // 3. Path-jail enforcement
        if !self.allowed_dirs.is_empty() {
            let in_jail = self
                .allowed_dirs
                .iter()
                .any(|root| resolved.starts_with(root));
            if !in_jail {
                let reason = if has_parent_ref {
                    format!("path traversal outside allowed directories: '{raw}'")
                } else if !self.allow_symlink_escape && is_symlink_involved(&expanded) {
                    format!("symlink escape outside allowed directories: '{raw}'")
                } else {
                    format!("path '{raw}' is outside allowed directories")
                };
                return Err(GuardError::PolicyDenied(reason));
            }
        } else if has_parent_ref {
            // Even without an explicit jail, block explicit `..` traversal into sensitive/system dirs
            // when it escapes the current working directory.
            if let Ok(cwd) = std::env::current_dir() {
                let cwd_norm = normalize_canonical(&cwd);
                if !resolved.starts_with(&cwd_norm) {
                    return Err(GuardError::PolicyDenied(format!(
                        "path traversal outside workspace: '{raw}'"
                    )));
                }
            }
        }

        Ok(())
    }

    fn check_default_sensitive(&self, resolved: &Path, resolved_slash: &str) -> Option<String> {
        // Check ~/.ssh, ~/.aws, ~/.gnupg
        if let Some(home) = &self.home_dir {
            for dir in [".ssh", ".aws", ".gnupg"] {
                let sensitive = home.join(dir);
                if resolved.starts_with(&sensitive) {
                    return Some(format!(
                        "access to sensitive directory '~/{dir}' is denied by default"
                    ));
                }
            }
        }

        // Also catch `/.ssh/`, `/.aws/`, `/.gnupg/` anywhere in path
        let lower = resolved_slash.to_ascii_lowercase();
        for seg in ["/.ssh/", "/.aws/", "/.gnupg/"] {
            if lower.contains(seg) || lower.ends_with(seg.trim_end_matches('/')) {
                return Some(format!(
                    "access to sensitive directory '{seg}' is denied by default"
                ));
            }
        }

        // Check **/.env*
        if let Some(file_name) = resolved.file_name().and_then(|n| n.to_str()) {
            let fname_lower = file_name.to_ascii_lowercase();
            if fname_lower == ".env" || fname_lower.starts_with(".env.") {
                return Some(format!(
                    "access to environment file '{file_name}' is denied by default"
                ));
            }
            if fname_lower.contains("credentials") {
                return Some(format!(
                    "access to credentials file '{file_name}' is denied by default"
                ));
            }
        }

        None
    }
}

fn strip_file_scheme(raw: &str) -> &str {
    if let Some(rest) = raw.strip_prefix("file://") {
        // Handle `file:///C:/...` on Windows or `file:///etc/...` on Unix
        if cfg!(windows) && rest.starts_with('/') && rest.as_bytes().get(2) == Some(&b':') {
            &rest[1..]
        } else {
            rest
        }
    } else {
        raw
    }
}

fn expand_tilde(raw: &str, home: Option<&Path>) -> PathBuf {
    if raw == "~" {
        if let Some(h) = home {
            return h.to_path_buf();
        }
    } else if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        if let Some(h) = home {
            return h.join(rest);
        }
    }
    PathBuf::from(raw)
}

fn is_symlink_involved(path: &Path) -> bool {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if let Ok(meta) = std::fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

/// Resolve as much of `path` as exists on disk via `canonicalize` (catching symlinks),
/// then lexically append any non-existent trailing components.
pub fn resolve_existing_or_lexical(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };

    let lexical = lexical_normalize(&abs);

    // Walk up until we find an existing ancestor to canonicalize.
    let mut existing = lexical.clone();
    let mut tail = Vec::new();
    while !existing.exists() {
        if let Some(name) = existing.file_name().map(|s| s.to_os_string()) {
            tail.push(name);
            if !existing.pop() {
                break;
            }
        } else {
            break;
        }
    }

    let mut base = if existing.exists() {
        match std::fs::canonicalize(&existing) {
            Ok(c) => normalize_canonical(&c),
            Err(_) => existing,
        }
    } else {
        lexical
    };

    for part in tail.into_iter().rev() {
        base.push(part);
    }
    normalize_canonical(&base)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn normalize_canonical(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn blocks_null_bytes_and_default_sensitive_files() {
        let dir = TempDir::new().unwrap();
        let policy = PathPolicy {
            allowed_dirs: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let v = PathValidator::new(&policy).unwrap();

        assert!(v.check("foo\0bar").is_err());
        assert!(v.check("~/.ssh/id_rsa").is_err());
        assert!(v.check("~/.aws/credentials").is_err());
        assert!(v.check(&dir.path().join(".env").to_string_lossy()).is_err());
        assert!(v
            .check(&dir.path().join(".env.production").to_string_lossy())
            .is_err());
        assert!(v
            .check(&dir.path().join("my_credentials.json").to_string_lossy())
            .is_err());

        let ok_file = dir.path().join("src").join("main.rs");
        assert!(v.check(&ok_file.to_string_lossy()).is_ok());
    }

    #[test]
    fn blocks_path_traversal_outside_jail() {
        let dir = TempDir::new().unwrap();
        let policy = PathPolicy {
            allowed_dirs: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let v = PathValidator::new(&policy).unwrap();

        let escape = dir
            .path()
            .join("sub")
            .join("..")
            .join("..")
            .join("etc")
            .join("passwd");
        assert!(v.check(&escape.to_string_lossy()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn blocks_symlink_escape() {
        let jail = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "top-secret").unwrap();

        let link = jail.path().join("escape_link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let policy = PathPolicy {
            allowed_dirs: vec![jail.path().to_path_buf()],
            ..Default::default()
        };
        let v = PathValidator::new(&policy).unwrap();
        assert!(v.check(&link.to_string_lossy()).is_err());
    }
}
