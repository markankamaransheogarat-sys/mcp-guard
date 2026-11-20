# Пресс-релиз: mcp-guard v0.1.0

**Дата:** 20 ноября 2026  
**Репозиторий:** https://github.com/markankamaransheogarat-sys/mcp-guard  
**Лицензия:** MIT OR Apache-2.0  

## Заголовок
**mcp-guard v0.1.0 — локальный security-файрвол и capability-sandbox для MCP-серверов на безопасном Rust (`#![forbid(unsafe_code)]`)**

## Ключевые возможности
- **Stdio и HTTP/SSE прокси** с суб-миллисекундным оверхедом.
- **Path-jail & SSRF-защита**: блокировка обхода путей, null-байтов и внутренних IP-диапазонов.
- **Редакция секретов и защита от prompt-injection** (AWS, GitHub, OpenAI, JWT, PEM, скрытые Unicode-теги).
- **Rate-limit / loop-breaker** и JSONL-аудит (`audit.jsonl`).
- **13/13 unit и integration тестов проходят**.
