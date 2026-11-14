use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use crate::config::AuditPolicy;
use crate::error::Result;

/// Audit decision recorded for each MCP request/response cycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    Allow,
    Deny,
    Redact,
}

/// Structured JSONL audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: DateTime<Utc>,
    pub server: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub decision: AuditDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub latency_us: u64,
}

/// Thread-safe JSONL audit logger with size-based file rotation.
#[derive(Debug)]
pub struct AuditLogger {
    policy: AuditPolicy,
    lock: Mutex<()>,
}

impl AuditLogger {
    /// Create a new `AuditLogger`, ensuring the parent directory exists if enabled.
    pub fn new(policy: AuditPolicy) -> Result<Self> {
        if policy.enabled {
            if let Some(parent) = policy.path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
        }
        Ok(Self {
            policy,
            lock: Mutex::new(()),
        })
    }

    /// Write an `AuditRecord` to the JSONL log, rotating if needed.
    pub fn log(&self, record: &AuditRecord) -> Result<()> {
        if !self.policy.enabled {
            return Ok(());
        }
        let line = serde_json::to_string(record)?;
        let _guard = self.lock.lock().expect("audit logger mutex poisoned");

        self.rotate_if_needed()?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.policy.path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    fn rotate_if_needed(&self) -> Result<()> {
        let Ok(meta) = fs::metadata(&self.policy.path) else {
            return Ok(());
        };
        if self.policy.max_file_bytes == 0 || meta.len() < self.policy.max_file_bytes {
            return Ok(());
        }

        let max_keep = self.policy.max_rotated_files;
        if max_keep == 0 {
            fs::remove_file(&self.policy.path)?;
            return Ok(());
        }

        for i in (1..max_keep).rev() {
            let src = rotated_path(&self.policy.path, i);
            let dst = rotated_path(&self.policy.path, i + 1);
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }

        let first = rotated_path(&self.policy.path, 1);
        let _ = fs::rename(&self.policy.path, first);
        Ok(())
    }
}

fn rotated_path(base: &Path, idx: usize) -> PathBuf {
    PathBuf::from(format!("{}.{idx}", base.display()))
}

/// Read the last `tail` entries from the JSONL audit log.
pub fn read_tail(path: &Path, tail: usize) -> Result<Vec<AuditRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<AuditRecord>(&line) {
            records.push(rec);
        }
    }
    if records.len() > tail {
        let start = records.len() - tail;
        Ok(records.split_off(start))
    } else {
        Ok(records)
    }
}

/// Print colored audit records to stdout.
pub fn print_audit_tail(path: &Path, tail: usize) -> Result<()> {
    let records = read_tail(path, tail)?;
    if records.is_empty() {
        println!(
            "{}",
            format!("No audit records found at {}", path.display()).dimmed()
        );
        return Ok(());
    }

    for rec in records {
        let ts = rec.timestamp.format("%Y-%m-%d %H:%M:%S");
        let decision = match rec.decision {
            AuditDecision::Allow => "ALLOW ".green().bold().to_string(),
            AuditDecision::Deny => "DENY  ".red().bold().to_string(),
            AuditDecision::Redact => "REDACT".yellow().bold().to_string(),
        };
        let tool = rec.tool.as_deref().unwrap_or("-");
        let reason = rec.reason.as_deref().unwrap_or("");
        let latency = format!("{}us", rec.latency_us);
        if reason.is_empty() {
            println!(
                "{} {} [{}] {} ({}) {}",
                ts.dimmed(),
                decision,
                rec.server.cyan(),
                rec.method.bold(),
                tool,
                latency.dimmed()
            );
        } else {
            println!(
                "{} {} [{}] {} ({}) {} — {}",
                ts.dimmed(),
                decision,
                rec.server.cyan(),
                rec.method.bold(),
                tool,
                latency.dimmed(),
                reason
            );
        }
    }
    Ok(())
}
