# Transcriber

Shared local speech-to-text with word timings and an OpenAI-compatible API.

A [Wizard app](https://apps.aiwizards.com): install it from the Wizard Apps screen, or with the Wizard App Manager on any box running stock [Runtipi](https://runtipi.io).

- `wizard.md`: what the app is and what it gives the agent (spec: wizard.md v0.2).
- `runtipi/`: stock Runtipi `config.json` and `docker-compose.yml`.
- `mcp/`: the app's MCP front (`front.py` + `tools.py`), inlined into the compose file by `python3 mcp/inline.py`. It serves `/mcp` and passes everything else unchanged to the upstream container.
- `SKILL.md`: the skill the agent loads when this app is installed.
- `.github/workflows/publish.yml`: every push to `main` re-publishes to the index at apps.aiwizards.com.

