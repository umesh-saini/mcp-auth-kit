# Security model

What `mcp-oauth-starter` defends against, and what is still your job.

## Threats the kit handles

| Threat | Defence |
|---|---|
| **Authorization-code interception** (a malicious app on the device grabs the redirect) | PKCE S256 is mandatory (the MCP SDK rejects requests without it). Codes are single-use (`takeGrant` is atomic), expire in 5 minutes, and are bound to the client and the `redirect_uri`. |
| **Consent CSRF** (an attacker starts a flow with their own client, then tricks a signed-in victim into approving it) | The consent form carries an HMAC of `request id + user id`. A token minted for one user is useless for another, and other sites cannot read it. |
| **Clickjacking** the "Allow" button | `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY` on the consent page. |
| **Phishing through dynamic registration** (anyone can register a client called "Claude") | The consent page shows the **redirect host** the browser will return to, next to the client name. Client names are HTML-escaped. |
| **Stolen database dump** | Only SHA-256 hashes of access tokens, refresh tokens and codes are stored. Confidential client secrets are AES-256-GCM encrypted with a key derived from `secret`. |
| **Stolen refresh token** | Rotation: every refresh issues a new pair and invalidates the old refresh token, so a thief and the real client cannot both keep using it. Refresh tokens are bound to their client. |
| **Long-lived access tokens** | Access tokens last 1 hour by default. |
| **Token confusion** (a token for another service sent to yours) | Tokens carry a prefix (`<prefix>_at_`) and are looked up by hash. RFC 8707 resource indicators for other origins are refused. |
| **Suspended users keep access** | `isUserActive` is checked on every request and every refresh. |
| **Leaky consent page** | `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, no third-party resources. |

## Your responsibilities

- **Your login.** `getUser` is trusted. Use secure, `HttpOnly`, `SameSite=Lax` (or stricter) session cookies.
- **Open redirects on your login page.** When you send users back to `returnTo`, accept only relative paths that start with a single `/` (see the example app).
- **Authorization inside tools.** The kit tells you *who* is calling (`userId`, `scopes`). Every tool must still check that this user may touch the record it is asked to touch.
- **Prompt injection.** An AI app acts with the user's permissions, and content it reads (emails, web pages) may try to make it misuse them. Mark destructive tools with `annotations: { destructiveHint: true }` so clients ask for confirmation, and require explicit arguments for irreversible actions.
- **HTTPS** everywhere in production, and `trust proxy` behind load balancers.
- **The `secret`.** Keep it in a secret manager. Rotating it invalidates stored client secrets (affected clients re-register) and open consent forms.
- **Rate limiting** on `/mcp` (the OAuth endpoints are rate-limited by the SDK).

## Reporting

Please report vulnerabilities privately. See [SECURITY.md](../SECURITY.md).
