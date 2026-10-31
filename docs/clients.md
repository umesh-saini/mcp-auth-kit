# Connecting AI clients

Your MCP URL is `<issuerUrl>/mcp` (or whatever `path` you mounted). Remote clients such as Claude and ChatGPT need it to be **public HTTPS**. For local testing, use a tunnel:

```bash
npx cloudflared tunnel --url http://localhost:3000     # or: ngrok http 3000
# then set issuerUrl / BASE_URL to the https URL it prints, and restart
```

## Claude (claude.ai, Desktop, iOS/Android)

Settings → **Connectors** → **Add custom connector** → paste the URL → **Connect**. Claude registers itself, opens your login + consent page, and the tools appear in the chat's tool menu.

## Claude Code

```bash
claude mcp add --transport http notes https://your-host/mcp
```

Run `/mcp` inside Claude Code and pick the server to sign in. With a personal token instead:

```bash
claude mcp add --transport http notes https://your-host/mcp --header "Authorization: Bearer notes_pat_…"
```

## ChatGPT

Enable developer mode (Settings → Connectors → Advanced), then **Create** a connector with your MCP URL and *OAuth* authentication.

## Cursor

`~/.cursor/mcp.json`:

```json
{ "mcpServers": { "notes": { "url": "https://your-host/mcp" } } }
```

## VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`:

```json
{ "servers": { "notes": { "type": "http", "url": "https://your-host/mcp" } } }
```

## MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Choose **Streamable HTTP**, enter the URL, and use **Open Auth Settings → Quick OAuth Flow** to walk through each OAuth step. This is useful for debugging.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Client says "no authorization server found" | The `/.well-known/*` routes are not at your site root, or a proxy strips them. `curl https://your-host/.well-known/oauth-protected-resource/mcp` should return JSON. |
| `Issuer URL must be HTTPS` at startup | `issuerUrl` is `http://` and not localhost. Use your public HTTPS origin. |
| Redirect loop on the consent page | `getUser` returns null after login. Check that your session cookie is set on the same host as `issuerUrl`. |
| "This connection request expired" | More than 15 minutes passed, the request was already answered, or `MemoryStore` was reset by a restart. |
| 401 right after connecting | The token was issued by one instance and checked by another, which has a different `MemoryStore`. Use a shared database store. |
| Rate-limit errors behind a proxy | Set `app.set('trust proxy', 1)`. |
