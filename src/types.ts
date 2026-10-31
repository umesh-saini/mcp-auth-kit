import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

/** The signed-in user of your app, as returned by `getUser(req)`. */
export interface AuthUser {
  id: string;
  /** Shown on the built-in consent page ("Signed in as …"). */
  name?: string;
}

/**
 * A pending consent request ('request': the AI app asked, the user has not answered yet) or an
 * issued authorization code ('code', stored by its SHA-256). Both are short-lived.
 */
export interface GrantRecord {
  kind: 'request' | 'code';
  /** Request id, or sha256(code). */
  key: string;
  clientId: string;
  /** Set once the user approves (always set on codes). */
  userId?: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  scopes: string[];
  resource: string;
  expiresAt: Date;
}

/**
 * A bearer credential for the MCP endpoint.
 *  - 'oauth': issued to a connected app; carries a rotating refresh token. This record is the
 *    "connected app" a user sees in their settings and can revoke.
 *  - 'pat': a personal access token for clients configured with an `Authorization` header.
 * Only hashes are stored, never the tokens themselves.
 */
export interface TokenRecord {
  id: string;
  kind: 'oauth' | 'pat';
  userId: string;
  clientId: string;
  /** Client name (oauth) or the label the user typed (pat). */
  name: string;
  accessHash: string;
  /** Last 4 characters of the access token, so users can tell tokens apart. */
  last4: string;
  scopes: string[];
  resource: string;
  createdAt: Date;
  /** Access-token expiry. Personal tokens have none. */
  expiresAt?: Date;
  refreshHash?: string;
  refreshExpiresAt?: Date;
  lastUsedAt?: Date;
}

/** Token metadata that is safe to send to a browser (no hashes). */
export type PublicTokenInfo = Omit<TokenRecord, 'accessHash' | 'refreshHash'>;

/**
 * Persistence for clients, grants and tokens. Implement it on top of your database
 * (see docs/storage.md for MongoDB, Postgres and Redis versions); `MemoryStore` is for
 * development and tests.
 *
 * The kit checks expiry dates itself, so TTL cleanup in the store is optional housekeeping.
 */
export interface OAuthStore {
  getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;
  saveClient(client: OAuthClientInformationFull): Promise<void>;

  saveGrant(grant: GrantRecord): Promise<void>;
  getGrant(key: string): Promise<GrantRecord | undefined>;
  /** Get and delete in one step. Must be atomic: it is what makes authorization codes single-use. */
  takeGrant(key: string): Promise<GrantRecord | undefined>;

  /** Insert or replace by `id`. */
  saveToken(token: TokenRecord): Promise<void>;
  findTokenByAccessHash(hash: string): Promise<TokenRecord | undefined>;
  findTokenByRefreshHash(hash: string): Promise<TokenRecord | undefined>;
  listTokens(userId: string): Promise<TokenRecord[]>;
  deleteToken(id: string): Promise<void>;
  /** Optional: record usage without rewriting the whole token. */
  touchToken?(id: string, at: Date): Promise<void>;
}
