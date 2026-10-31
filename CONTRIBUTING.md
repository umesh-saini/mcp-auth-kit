# Contributing

Thanks for helping. Bug reports, new storage adapters, framework adapters (Fastify, Hono, Next.js) and docs fixes are all welcome.

## Setup

```bash
git clone https://github.com/umeshsaini8085/mcp-auth-kit && cd mcp-auth-kit
npm install
npm test          # full OAuth flow against a real HTTP server, ~2 s
npm run example   # the notes demo on http://localhost:3000/mcp
```

## Guidelines

- **Every protocol change needs a test** in `test/flow.test.ts`. The tests drive the real endpoints with `fetch` and the official MCP client, so they catch what unit tests miss.
- Keep runtime dependencies at zero. `@modelcontextprotocol/sdk` and `express` are peer dependencies.
- Security-sensitive changes (tokens, consent, crypto) get extra review. Explain the threat model in the PR.
- Run `npm run typecheck && npm test` before pushing. CI runs Node 20, 22, 24 and Express 4 and 5.

## Releasing (maintainers)

1. Update `CHANGELOG.md` and bump `version` in `package.json`.
2. `git tag vX.Y.Z && git push --tags`. The Release workflow publishes to npm with provenance.
