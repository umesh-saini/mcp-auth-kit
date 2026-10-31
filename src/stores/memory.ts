import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { GrantRecord, OAuthStore, TokenRecord } from '../types.js';

/**
 * In-process store for development, tests and single-instance demos. Everything is lost on
 * restart (connected apps simply sign in again). Use a database-backed store in production.
 */
export class MemoryStore implements OAuthStore {
  private clients = new Map<string, OAuthClientInformationFull>();
  private grants = new Map<string, GrantRecord>();
  private tokens = new Map<string, TokenRecord>();

  async getClient(clientId: string) {
    return this.clients.get(clientId);
  }
  async saveClient(client: OAuthClientInformationFull) {
    this.clients.set(client.client_id, structuredClone(client));
  }

  async saveGrant(grant: GrantRecord) {
    this.sweep();
    this.grants.set(grant.key, { ...grant });
  }
  async getGrant(key: string) {
    return this.grants.get(key);
  }
  async takeGrant(key: string) {
    const grant = this.grants.get(key);
    this.grants.delete(key);
    return grant;
  }

  async saveToken(token: TokenRecord) {
    this.tokens.set(token.id, { ...token });
  }
  async findTokenByAccessHash(hash: string) {
    for (const t of this.tokens.values()) if (t.accessHash === hash) return t;
    return undefined;
  }
  async findTokenByRefreshHash(hash: string) {
    for (const t of this.tokens.values()) if (t.refreshHash === hash) return t;
    return undefined;
  }
  async listTokens(userId: string) {
    return [...this.tokens.values()].filter((t) => t.userId === userId).sort((a, b) => +b.createdAt - +a.createdAt);
  }
  async deleteToken(id: string) {
    this.tokens.delete(id);
  }
  async touchToken(id: string, at: Date) {
    const t = this.tokens.get(id);
    if (t) t.lastUsedAt = at;
  }

  /** Drops expired grants and dead tokens so a long-running dev server does not grow forever. */
  private sweep() {
    const now = Date.now();
    for (const [k, g] of this.grants) if (+g.expiresAt < now) this.grants.delete(k);
    for (const [k, t] of this.tokens) if (t.refreshExpiresAt && +t.refreshExpiresAt < now) this.tokens.delete(k);
  }
}
