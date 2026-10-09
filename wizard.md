---
wizard: 0.2
id: transcriber
name: Transcriber
type: service
version: 0.9.0-rc.3.cpu
summary: Shared local speech-to-text with word timings and an OpenAI-compatible API.
license: WTFPL
source: https://github.com/oscarhenrycollins/transcriber
runtime:
  kind: runtipi
  config: runtipi/config.json
  compose: runtipi/docker-compose.yml
mcp:
  path: /mcp
  port: 8000
  transport: streamable-http
skill: SKILL.md
provides:
- transcription
- speech-to-text-engine
needs:
- files
health: /health
---

# Transcriber

Shared local speech-to-text with word timings and an OpenAI-compatible API.
