FROM rust:1.83-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked 2>/dev/null || cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/mcp-guard /usr/local/bin/mcp-guard
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mcp-guard"]
