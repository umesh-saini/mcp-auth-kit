# Changelog

## 0.1.0

First release, extracted from SangeetFlow's production MCP connector.

- OAuth 2.1 authorization server for MCP: authorization code + PKCE, dynamic client registration, RFC 8414 / RFC 9728 metadata, revocation, RFC 8707 resource checks.
- Built-in consent page with CSRF protection and anti-framing headers; `consentUrl` for custom UIs.
- Refresh-token rotation, personal access tokens, connected-apps listing and revocation.
- `mount()`: stateless Streamable HTTP MCP endpoint with CORS and per-request servers.
- `OAuthStore` interface, `MemoryStore`, and MongoDB / Postgres / Redis adapter recipes.
- Tool helpers: `ok`, `fail`, `withAuth`, `authOf`.
