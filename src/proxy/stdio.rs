use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::error::{GuardError, Result};
use crate::proxy::{ClientAction, GuardContext};

/// Run the `stdio` MCP proxy by spawning `command[0]` with `command[1..]`.
pub async fn run_stdio_proxy(ctx: GuardContext, command: &[String]) -> Result<i32> {
    if command.is_empty() {
        return Err(GuardError::Config(
            "no child MCP server command provided after '--'".to_string(),
        ));
    }

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn()?;
    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| GuardError::HttpProxy("failed to capture child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| GuardError::HttpProxy("failed to capture child stdout".to_string()))?;

    let client_in = tokio::io::stdin();
    let client_out = tokio::io::stdout();

    run_stdio_streams(ctx, client_in, client_out, child_stdin, child_stdout).await?;

    let status = child.wait().await?;
    Ok(status.code().unwrap_or(0))
}

/// Run the `stdio` JSON-RPC 2.0 proxy over arbitrary async streams.
pub async fn run_stdio_streams<CI, CO, SI, SO>(
    ctx: GuardContext,
    client_in: CI,
    mut client_out: CO,
    mut server_in: SI,
    server_out: SO,
) -> Result<()>
where
    CI: AsyncRead + Unpin + Send + 'static,
    CO: AsyncWrite + Unpin + Send + 'static,
    SI: AsyncWrite + Unpin + Send + 'static,
    SO: AsyncRead + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<String>(256);

    // Task 1: serialize all writes to client_out
    let writer_task = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if client_out.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if client_out.write_all(b"\n").await.is_err() {
                break;
            }
            if client_out.flush().await.is_err() {
                break;
            }
        }
    });

    // Task 2: read from client_in -> evaluate policy -> forward to server_in OR reply immediately
    let ctx_in = ctx.clone();
    let tx_deny = tx.clone();
    let client_reader_task = tokio::spawn(async move {
        let mut reader = BufReader::new(client_in);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        continue;
                    }
                    match ctx_in.process_client_line(trimmed) {
                        ClientAction::Forward(fwd) => {
                            if server_in.write_all(fwd.as_bytes()).await.is_err() {
                                break;
                            }
                            if server_in.write_all(b"\n").await.is_err() {
                                break;
                            }
                            if server_in.flush().await.is_err() {
                                break;
                            }
                        }
                        ClientAction::ImmediateReply(reply) => {
                            if tx_deny.send(reply).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        let _ = server_in.shutdown().await;
    });

    // Task 3: read from server_out -> sanitize -> forward to client_out
    let server_reader_task = tokio::spawn(async move {
        let mut reader = BufReader::new(server_out);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        continue;
                    }
                    let sanitized = ctx.process_server_line(trimmed);
                    if tx.send(sanitized).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let _ = client_reader_task.await;
    let _ = server_reader_task.await;
    let _ = writer_task.await;
    Ok(())
}
