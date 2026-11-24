#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use mcp_guard::audit::print_audit_tail;
use mcp_guard::config::{AuditPolicy, PolicyConfig};
use mcp_guard::error::Result;
use mcp_guard::init::run_init;
use mcp_guard::proxy::http::run_http_proxy;
use mcp_guard::proxy::stdio::run_stdio_proxy;
use mcp_guard::proxy::GuardContext;

#[derive(Debug, Parser)]
#[command(
    name = "mcp-guard",
    version,
    about = "Local security firewall and capability sandbox for Model Context Protocol (MCP) servers"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a starter mcp-guard.toml (optionally importing from Claude/Cursor config)
    Init {
        /// Path to an existing claude_desktop_config.json or .cursor/mcp.json
        #[arg(long)]
        from: Option<PathBuf>,
        /// Output policy file path
        #[arg(long, short, default_value = "mcp-guard.toml")]
        output: PathBuf,
        /// Overwrite existing policy file
        #[arg(long)]
        force: bool,
    },
    /// Wrap a stdio MCP server process behind the mcp-guard firewall
    Wrap {
        /// Path to mcp-guard.toml policy file
        #[arg(long, short, default_value = "mcp-guard.toml")]
        policy: PathBuf,
        /// Logical server name (selects [servers.<name>] override if present)
        #[arg(long, short, default_value = "default")]
        server: String,
        /// Child MCP server command and arguments
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Start an SSE / Streamable HTTP reverse proxy in front of an upstream MCP server
    Listen {
        /// Local socket address to bind (e.g. 127.0.0.1:8787)
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
        /// Upstream MCP server base URL (e.g. http://127.0.0.1:3000)
        #[arg(long)]
        upstream: String,
        /// Path to mcp-guard.toml policy file
        #[arg(long, short, default_value = "mcp-guard.toml")]
        policy: PathBuf,
        /// Logical server name (selects [servers.<name>] override if present)
        #[arg(long, short, default_value = "default")]
        server: String,
    },
    /// Validate a policy file (TOML syntax, globs, regexes, and allowed_dirs)
    Check {
        /// Path to mcp-guard.toml policy file
        #[arg(long, short, default_value = "mcp-guard.toml")]
        policy: PathBuf,
        /// Optional logical server name to validate effective [servers.<name>] override
        #[arg(long, short)]
        server: Option<String>,
    },
    /// Inspect recent audit log entries
    Audit {
        /// Path to audit JSONL file (defaults to platform local data dir or policy setting)
        #[arg(long)]
        log: Option<PathBuf>,
        /// Number of recent entries to display
        #[arg(long, default_value_t = 50)]
        tail: usize,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("mcp-guard error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Init {
            from,
            output,
            force,
        } => {
            run_init(from.as_deref(), &output, force)?;
            Ok(0)
        }
        Commands::Wrap {
            policy,
            server,
            command,
        } => {
            let cfg = load_or_default(&policy)?.for_server(&server);
            let ctx = GuardContext::new(&cfg)?;
            run_stdio_proxy(ctx, &command).await
        }
        Commands::Listen {
            bind,
            upstream,
            policy,
            server,
        } => {
            let cfg = load_or_default(&policy)?.for_server(&server);
            let ctx = GuardContext::new(&cfg)?;
            run_http_proxy(ctx, bind, upstream).await?;
            Ok(0)
        }
        Commands::Check { policy, server } => {
            let base = PolicyConfig::from_file(&policy)?;
            let effective = match server.as_deref() {
                Some(name) => base.for_server(name),
                None => base,
            };
            let _ctx = GuardContext::new(&effective)?;
            let missing_dirs: Vec<_> = effective
                .paths
                .allowed_dirs
                .iter()
                .filter(|d| !d.exists())
                .collect();
            for dir in &missing_dirs {
                eprintln!(
                    "warning: allowed_dirs path does not exist: {}",
                    dir.display()
                );
            }
            println!(
                "OK: {} valid (server='{}', allowed_dirs={}, tools.allow={}, tools.deny={}, block_private_ips={}, resolve_dns={})",
                policy.display(),
                effective.server,
                effective.paths.allowed_dirs.len(),
                effective.tools.allow.len(),
                effective.tools.deny.len(),
                effective.network.block_private_ips,
                effective.network.resolve_dns,
            );
            Ok(0)
        }
        Commands::Audit { log, tail } => {
            let path = log.unwrap_or_else(|| AuditPolicy::default().path);
            print_audit_tail(&path, tail)?;
            Ok(0)
        }
    }
}

fn load_or_default(path: &PathBuf) -> Result<PolicyConfig> {
    if path.exists() {
        PolicyConfig::from_file(path)
    } else {
        Ok(PolicyConfig::default())
    }
}
