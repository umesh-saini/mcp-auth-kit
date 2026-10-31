import type { Request, Response } from 'express';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import { InvalidGrantError, InvalidScopeError, InvalidTargetError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { decrypt, encrypt, randomToken, sha256 } from './crypto.js';
import type { AuthUser, OAuthStore, PublicTokenInfo, TokenRecord } from './types.js';

export interface McpAuthOptions {
  /** Public origin of your app, e.g. https://api.example.com. Must be https:// (http://localhost is allowed). */
  issuerUrl: string | URL;
  /** Where clients, grants and tokens live. `new MemoryStore()` for development. */
  store: OAuthStore;
  /** A long random string (32+ chars). Signs consent-form CSRF tokens and encrypts client secrets at rest. */
  secret: string;
  /** Your app's signed-in user for this request, or null. Used by the built-in consent page. */
  getUser?: (req: Request) => AuthUser | null | undefined | Promise<AuthUser | null | undefined>;
  /** Signed-out users are sent here with `?returnTo=<consent page>`. Without it they see a "please sign in" page. */
  loginUrl?: string;
  /**
   * Your own consent UI. When set, authorization requests redirect to `${consentUrl}?request=<id>`
   * and you call `getConsentRequest` / `approveConsent` / `denyConsent` yourself. Default: the built-in page.
   */
  consentUrl?: string;
  /** Scopes your server understands. Default ['mcp']. Clients that ask for none get all of them. */
  scopes?: string[];
  /** Your product name, shown on the consent page and in the protected-resource metadata. */
  serviceName?: string;
  /** Prefix for issued tokens (`<prefix>_at_…`, `<prefix>_rt_…`, `<prefix>_pat_…`), handy for secret scanners. Default 'mcp'. */
  tokenPrefix?: string;
  /** Access-token lifetime in seconds. Default 3600. */
  accessTokenTtl?: number;
  /** Refresh-token lifetime in seconds. Default 60 days. Each refresh rotates it. */
  refreshTokenTtl?: number;
  /** Return false to reject tokens of suspended or deleted users. */
  isUserActive?: (userId: string) => boolean | Promise<boolean>;
}

/** Everything a connected AI app's request carries once its token is verified. */
export interface McpAuthExtra {
  userId: string;
  tokenId: string;
  kind: 'oauth' | 'pat';
}

/** What a consent screen needs to show. */
export interface ConsentRequestInfo {
  requestId: string;
  clientId: string;
  clientName: string;
  clientUri: string;
  /** Host the browser goes back to after approval (e.g. claude.ai). Show it: it is how users spot a fake app. */
  redirectHost: string;
  scopes: string[];
}

const REQUEST_TTL_MS = 15 * 60_000;
const CODE_TTL_MS = 5 * 60_000;
const ENC = 'enc:';

export interface McpAuthCore {
  readonly options: Required<Pick<McpAuthOptions, 'scopes' | 'serviceName' | 'tokenPrefix' | 'accessTokenTtl' | 'refreshTokenTtl'>> & McpAuthOptions;
  readonly issuer: URL;
  /** The SDK provider: plug it into `mcpAuthRouter` / `requireBearerAuth` if you wire routes yourself. */
  readonly provider: OAuthServerProvider;
  getConsentRequest(requestId: string): Promise<ConsentRequestInfo | null>;
  /** Approves a pending request for `userId`; returns the URL to send the browser to. */
  approveConsent(requestId: string, userId: string): Promise<string>;
  /** Denies a pending request; returns the URL to send the browser to. */
  denyConsent(requestId: string): Promise<string>;
  /** Creates a non-expiring personal access token. The plain token is returned once; only its hash is stored. */
  createPersonalToken(userId: string, name: string): Promise<{ token: string; record: PublicTokenInfo }>;
  /** Connected apps and personal tokens of a user, without secrets. */
  listTokens(userId: string): Promise<PublicTokenInfo[]>;
  /** Disconnects an app or deletes a personal token. Returns false if it is not this user's. */
  revokeTokenById(userId: string, tokenId: string): Promise<boolean>;
}

export function publicToken(t: TokenRecord): PublicTokenInfo {
  const { accessHash: _a, refreshHash: _r, ...rest } = t;
  return rest;
}

export function createAuthCore(input: McpAuthOptions): McpAuthCore {
  if (!input.secret || input.secret.length < 32) throw new Error('mcp-oauth-starter: `secret` must be at least 32 characters (e.g. `openssl rand -base64 48`).');
  const options = {
    scopes: ['mcp'],
    serviceName: 'MCP server',
    tokenPrefix: 'mcp',
    accessTokenTtl: 3600,
    refreshTokenTtl: 60 * 24 * 3600,
    ...input,
  };
  const { store, secret, tokenPrefix: prefix } = options;
  const issuer = new URL(options.issuerUrl);
  const tokenPattern = new RegExp(`^${prefix.replace(/[^a-zA-Z0-9]/g, '\\$&')}_(at|pat)_`);

  const clientsStore: OAuthRegisteredClientsStore = {
    async getClient(clientId) {
      const client = await store.getClient(clientId);
      if (!client) return undefined;
      const s = client.client_secret;
      return s?.startsWith(ENC) ? { ...client, client_secret: decrypt(secret, s.slice(ENC.length)) } : client;
    },
    async registerClient(client) {
      const full = client as OAuthClientInformationFull;
      await store.saveClient(full.client_secret ? { ...full, client_secret: ENC + encrypt(secret, full.client_secret) } : full);
      return full;
    },
  };

  async function issueTokens(id: string | null, base: Pick<TokenRecord, 'userId' | 'clientId' | 'name' | 'scopes' | 'resource'> & { createdAt?: Date }): Promise<OAuthTokens> {
    const access = `${prefix}_at_${randomToken(32)}`;
    const refresh = `${prefix}_rt_${randomToken(32)}`;
    const now = Date.now();
    await store.saveToken({
      ...base,
      id: id ?? randomToken(12),
      kind: 'oauth',
      accessHash: sha256(access),
      last4: access.slice(-4),
      createdAt: base.createdAt ?? new Date(now),
      expiresAt: new Date(now + options.accessTokenTtl * 1000),
      refreshHash: sha256(refresh),
      refreshExpiresAt: new Date(now + options.refreshTokenTtl * 1000),
    });
    return { access_token: access, token_type: 'bearer', expires_in: options.accessTokenTtl, refresh_token: refresh, scope: base.scopes.join(' ') };
  }

  function checkScopes(requested: string[] | undefined): string[] {
    if (!requested?.length) return [...options.scopes];
    const unknown = requested.filter((s) => !options.scopes.includes(s));
    if (unknown.length) throw new InvalidScopeError(`Unsupported scope: ${unknown.join(' ')}`);
    return requested;
  }

  const provider: OAuthServerProvider = {
    get clientsStore() {
      return clientsStore;
    },

    /** Parks the validated request and sends the browser to the consent page. */
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) {
      // RFC 8707: this authorization server only issues tokens for its own origin.
      if (params.resource && params.resource.origin !== issuer.origin) throw new InvalidTargetError(`Unknown resource: ${params.resource.href}`);
      const scopes = checkScopes(params.scopes);
      const id = randomToken(18);
      await store.saveGrant({
        kind: 'request',
        key: id,
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        state: params.state ?? '',
        scopes,
        resource: params.resource?.href ?? '',
        expiresAt: new Date(Date.now() + REQUEST_TTL_MS),
      });
      const target = new URL(options.consentUrl ?? '/oauth/consent', issuer);
      target.searchParams.set('request', id);
      res.redirect(302, target.href);
    },

    async challengeForAuthorizationCode(client, code) {
      const grant = await store.getGrant(sha256(code));
      if (!grant || grant.kind !== 'code' || grant.clientId !== client.client_id || grant.expiresAt < new Date()) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }
      return grant.codeChallenge;
    },

    async exchangeAuthorizationCode(client, code, _verifier, redirectUri, resource) {
      // Single use: the code is removed as it is redeemed (the SDK already checked PKCE).
      const grant = await store.takeGrant(sha256(code));
      if (!grant || grant.kind !== 'code' || grant.clientId !== client.client_id || grant.expiresAt < new Date() || !grant.userId) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }
      if (redirectUri && redirectUri !== grant.redirectUri) throw new InvalidGrantError('redirect_uri does not match');
      if (resource && grant.resource && resource.href !== grant.resource) throw new InvalidGrantError('resource does not match');
      return issueTokens(null, {
        userId: grant.userId,
        clientId: client.client_id,
        name: client.client_name || 'AI assistant',
        scopes: grant.scopes,
        resource: grant.resource,
      });
    },

    /** Rotates both tokens; the old refresh token stops working immediately. */
    async exchangeRefreshToken(client, refreshToken, scopes) {
      const doc = await store.findTokenByRefreshHash(sha256(refreshToken));
      if (!doc || doc.clientId !== client.client_id || !doc.refreshExpiresAt || doc.refreshExpiresAt < new Date()) {
        throw new InvalidGrantError('Invalid or expired refresh token');
      }
      if (scopes?.some((s) => !doc.scopes.includes(s))) throw new InvalidScopeError('A refresh cannot add scopes');
      if (options.isUserActive && !(await options.isUserActive(doc.userId))) throw new InvalidGrantError('Account is not active');
      return issueTokens(doc.id, { ...doc, scopes: scopes?.length ? scopes : doc.scopes });
    },

    async verifyAccessToken(token: string): Promise<AuthInfo> {
      if (!tokenPattern.test(token)) throw new InvalidTokenError('Unknown token');
      const doc = await store.findTokenByAccessHash(sha256(token));
      if (!doc || (doc.expiresAt && doc.expiresAt < new Date())) throw new InvalidTokenError('Token expired or revoked');
      if (options.isUserActive && !(await options.isUserActive(doc.userId))) throw new InvalidTokenError('Account is not active');
      if (!doc.lastUsedAt || Date.now() - +doc.lastUsedAt > 5 * 60_000) {
        const at = new Date();
        (store.touchToken ? store.touchToken(doc.id, at) : store.saveToken({ ...doc, lastUsedAt: at })).catch(() => undefined);
      }
      const extra: McpAuthExtra = { userId: doc.userId, tokenId: doc.id, kind: doc.kind };
      return {
        token,
        clientId: doc.clientId || 'personal-token',
        scopes: doc.scopes.length ? doc.scopes : [...options.scopes],
        // Personal tokens never expire, but the SDK's bearer check needs an expiry: report a rolling window.
        expiresAt: Math.floor((doc.expiresAt ? +doc.expiresAt : Date.now() + options.accessTokenTtl * 1000) / 1000),
        ...(doc.resource ? { resource: new URL(doc.resource) } : {}),
        extra: { ...extra },
      };
    },

    async revokeToken(client, request: OAuthTokenRevocationRequest) {
      const hash = sha256(request.token);
      const doc = (await store.findTokenByAccessHash(hash)) ?? (await store.findTokenByRefreshHash(hash));
      // RFC 7009: unknown tokens are not an error.
      if (doc && doc.clientId === client.client_id) await store.deleteToken(doc.id);
    },
  };

  async function pending(requestId: string) {
    const grant = requestId ? await store.getGrant(requestId) : undefined;
    if (!grant || grant.kind !== 'request' || grant.expiresAt < new Date()) return null;
    const client = await clientsStore.getClient(grant.clientId);
    return client ? { grant, client } : null;
  }

  const expired = () => Object.assign(new Error('This connection request expired. Start the connection again from your AI app.'), { status: 404 });

  return {
    options,
    issuer,
    provider,

    async getConsentRequest(requestId) {
      const p = await pending(requestId);
      if (!p) return null;
      return {
        requestId,
        clientId: p.client.client_id,
        clientName: p.client.client_name || 'An AI assistant',
        clientUri: p.client.client_uri ?? '',
        redirectHost: new URL(p.grant.redirectUri).host || p.grant.redirectUri,
        scopes: p.grant.scopes,
      };
    },

    async approveConsent(requestId, userId) {
      const grant = await store.takeGrant(requestId);
      if (!grant || grant.kind !== 'request' || grant.expiresAt < new Date()) throw expired();
      const code = randomToken(32);
      await store.saveGrant({ ...grant, kind: 'code', key: sha256(code), userId, expiresAt: new Date(Date.now() + CODE_TTL_MS) });
      const target = new URL(grant.redirectUri);
      target.searchParams.set('code', code);
      if (grant.state) target.searchParams.set('state', grant.state);
      return target.href;
    },

    async denyConsent(requestId) {
      const grant = await store.takeGrant(requestId);
      if (!grant || grant.kind !== 'request') throw expired();
      const target = new URL(grant.redirectUri);
      target.searchParams.set('error', 'access_denied');
      target.searchParams.set('error_description', 'The user denied access');
      if (grant.state) target.searchParams.set('state', grant.state);
      return target.href;
    },

    async createPersonalToken(userId, name) {
      const token = `${prefix}_pat_${randomToken(32)}`;
      const record: TokenRecord = {
        id: randomToken(12),
        kind: 'pat',
        userId,
        clientId: '',
        name: name.trim().slice(0, 80) || 'Personal token',
        accessHash: sha256(token),
        last4: token.slice(-4),
        scopes: [...options.scopes],
        resource: '',
        createdAt: new Date(),
      };
      await store.saveToken(record);
      return { token, record: publicToken(record) };
    },

    async listTokens(userId) {
      return (await store.listTokens(userId)).map(publicToken);
    },

    async revokeTokenById(userId, tokenId) {
      const mine = (await store.listTokens(userId)).some((t) => t.id === tokenId);
      if (mine) await store.deleteToken(tokenId);
      return mine;
    },
  };
}
