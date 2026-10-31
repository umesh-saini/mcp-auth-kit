# Storage adapters

`mcp-auth-kit` stores three kinds of records through the `OAuthStore` interface:

| Record | What | Lifetime |
|---|---|---|
| **Client** | An AI app that registered itself (RFC 7591 metadata) | Forever (clients re-register freely) |
| **Grant** | A pending consent request, or an issued authorization code (stored by SHA-256) | 15 min / 5 min |
| **Token** | A connected app (access + refresh hashes) or a personal token | Until the refresh token expires / forever for PATs |

The kit checks every expiry date itself, so TTL indexes are only housekeeping. The one hard requirement is that **`takeGrant` is atomic** (get + delete in one operation). That is what keeps authorization codes single-use.

`MemoryStore` is fine for development and tests. Below are adapters for common databases. Copy one into your project and adjust names.

---

## MongoDB (Mongoose)

This is the store SangeetFlow runs in production.

```ts
import { Schema, model } from 'mongoose';
import type { OAuthStore, TokenRecord, GrantRecord } from '@umesh-saini/mcp-auth-kit';

const Client = model('OAuthClient', new Schema({
  _id: String,                                   // client_id
  info: { type: Schema.Types.Mixed, required: true },
}, { timestamps: true }));

const grantSchema = new Schema({
  _id: String,                                   // request id or sha256(code)
  kind: String, clientId: String, userId: String, redirectUri: String, codeChallenge: String,
  state: String, scopes: [String], resource: String, expiresAt: Date,
});
grantSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Grant = model('OAuthGrant', grantSchema);

const tokenSchema = new Schema({
  _id: String,
  kind: String, userId: { type: String, index: true }, clientId: String, name: String,
  accessHash: { type: String, unique: true }, last4: String, scopes: [String], resource: String,
  createdAt: Date, expiresAt: Date, refreshHash: { type: String, unique: true, sparse: true },
  refreshExpiresAt: Date, lastUsedAt: Date,
});
tokenSchema.index({ refreshExpiresAt: 1 }, { expireAfterSeconds: 0 }); // dead connections disappear
const Token = model('OAuthToken', tokenSchema);

const grant = (d: any): GrantRecord | undefined => d && { ...d, key: d._id };
const token = (d: any): TokenRecord | undefined => d && { ...d, id: d._id };

export const mongoStore: OAuthStore = {
  getClient: async (id) => (await Client.findById(id).lean())?.info as any,
  saveClient: async (c) => void (await Client.updateOne({ _id: c.client_id }, { info: c }, { upsert: true })),

  saveGrant: async (g) => void (await Grant.updateOne({ _id: g.key }, { ...g, key: undefined }, { upsert: true })),
  getGrant: async (key) => grant(await Grant.findById(key).lean()),
  takeGrant: async (key) => grant(await Grant.findByIdAndDelete(key).lean()),   // atomic

  saveToken: async (t) => void (await Token.replaceOne({ _id: t.id }, { ...t, _id: t.id }, { upsert: true })),
  findTokenByAccessHash: async (h) => token(await Token.findOne({ accessHash: h }).lean()),
  findTokenByRefreshHash: async (h) => token(await Token.findOne({ refreshHash: h }).lean()),
  listTokens: async (userId) => (await Token.find({ userId }).sort({ createdAt: -1 }).lean()).map((d) => token(d)!),
  deleteToken: async (id) => void (await Token.deleteOne({ _id: id })),
  touchToken: async (id, at) => void (await Token.updateOne({ _id: id }, { lastUsedAt: at })),
};
```

---

## PostgreSQL (`pg`)

```sql
create table oauth_clients (
  client_id text primary key,
  info      jsonb not null,
  created_at timestamptz not null default now()
);

create table oauth_grants (
  key            text primary key,
  kind           text not null check (kind in ('request', 'code')),
  client_id      text not null,
  user_id        text,
  redirect_uri   text not null,
  code_challenge text not null,
  state          text not null default '',
  scopes         text[] not null default '{}',
  resource       text not null default '',
  expires_at     timestamptz not null
);

create table oauth_tokens (
  id                 text primary key,
  kind               text not null check (kind in ('oauth', 'pat')),
  user_id            text not null,
  client_id          text not null default '',
  name               text not null default '',
  access_hash        text not null unique,
  last4              text not null default '',
  scopes             text[] not null default '{}',
  resource           text not null default '',
  created_at         timestamptz not null,
  expires_at         timestamptz,
  refresh_hash       text unique,
  refresh_expires_at timestamptz,
  last_used_at       timestamptz
);
create index on oauth_tokens (user_id);
-- Housekeeping (cron / pg_cron): delete from oauth_grants where expires_at < now();
--                                delete from oauth_tokens where refresh_expires_at < now();
```

```ts
import pg from 'pg';
import type { OAuthStore, TokenRecord, GrantRecord } from '@umesh-saini/mcp-auth-kit';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const toGrant = (r: any): GrantRecord | undefined => r && ({
  kind: r.kind, key: r.key, clientId: r.client_id, userId: r.user_id ?? undefined, redirectUri: r.redirect_uri,
  codeChallenge: r.code_challenge, state: r.state, scopes: r.scopes, resource: r.resource, expiresAt: r.expires_at,
});
const toToken = (r: any): TokenRecord | undefined => r && ({
  id: r.id, kind: r.kind, userId: r.user_id, clientId: r.client_id, name: r.name, accessHash: r.access_hash,
  last4: r.last4, scopes: r.scopes, resource: r.resource, createdAt: r.created_at,
  expiresAt: r.expires_at ?? undefined, refreshHash: r.refresh_hash ?? undefined,
  refreshExpiresAt: r.refresh_expires_at ?? undefined, lastUsedAt: r.last_used_at ?? undefined,
});
const one = async (sql: string, params: unknown[]) => (await pool.query(sql, params)).rows[0];

export const pgStore: OAuthStore = {
  getClient: async (id) => (await one('select info from oauth_clients where client_id = $1', [id]))?.info,
  saveClient: async (c) => void (await pool.query(
    'insert into oauth_clients (client_id, info) values ($1, $2) on conflict (client_id) do update set info = excluded.info',
    [c.client_id, c])),

  saveGrant: async (g) => void (await pool.query(
    `insert into oauth_grants (key, kind, client_id, user_id, redirect_uri, code_challenge, state, scopes, resource, expires_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [g.key, g.kind, g.clientId, g.userId ?? null, g.redirectUri, g.codeChallenge, g.state, g.scopes, g.resource, g.expiresAt])),
  getGrant: async (key) => toGrant(await one('select * from oauth_grants where key = $1', [key])),
  takeGrant: async (key) => toGrant(await one('delete from oauth_grants where key = $1 returning *', [key])), // atomic

  saveToken: async (t) => void (await pool.query(
    `insert into oauth_tokens (id, kind, user_id, client_id, name, access_hash, last4, scopes, resource, created_at,
       expires_at, refresh_hash, refresh_expires_at, last_used_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     on conflict (id) do update set access_hash = excluded.access_hash, last4 = excluded.last4, scopes = excluded.scopes,
       expires_at = excluded.expires_at, refresh_hash = excluded.refresh_hash,
       refresh_expires_at = excluded.refresh_expires_at, last_used_at = excluded.last_used_at`,
    [t.id, t.kind, t.userId, t.clientId, t.name, t.accessHash, t.last4, t.scopes, t.resource, t.createdAt,
     t.expiresAt ?? null, t.refreshHash ?? null, t.refreshExpiresAt ?? null, t.lastUsedAt ?? null])),
  findTokenByAccessHash: async (h) => toToken(await one('select * from oauth_tokens where access_hash = $1', [h])),
  findTokenByRefreshHash: async (h) => toToken(await one('select * from oauth_tokens where refresh_hash = $1', [h])),
  listTokens: async (userId) =>
    (await pool.query('select * from oauth_tokens where user_id = $1 order by created_at desc', [userId])).rows.map((r) => toToken(r)!),
  deleteToken: async (id) => void (await pool.query('delete from oauth_tokens where id = $1', [id])),
  touchToken: async (id, at) => void (await pool.query('update oauth_tokens set last_used_at = $2 where id = $1', [id, at])),
};
```

Prisma or Drizzle users: same columns, and use `delete … returning` (`prisma.oauthGrant.delete`) for `takeGrant`.

---

## Redis (`ioredis`)

Good for grants (they are short-lived). Keep clients and tokens in your main database, or in Redis too:

```ts
import Redis from 'ioredis';
import type { OAuthStore } from '@umesh-saini/mcp-auth-kit';

const redis = new Redis(process.env.REDIS_URL!);
const revive = (s: string | null) => s ? JSON.parse(s, (k, v) => (/At$/.test(k) && v ? new Date(v) : v)) : undefined;

export const redisGrants: Pick<OAuthStore, 'saveGrant' | 'getGrant' | 'takeGrant'> = {
  saveGrant: async (g) => void (await redis.set(`oauth:grant:${g.key}`, JSON.stringify(g), 'PXAT', +g.expiresAt)),
  getGrant: async (key) => revive(await redis.get(`oauth:grant:${key}`)),
  takeGrant: async (key) => revive(await redis.getdel(`oauth:grant:${key}`)), // atomic (Redis ≥ 6.2)
};

// Combine with another store: { ...pgStore, ...redisGrants }
```

---

## Writing your own

1. Implement the 10 methods of `OAuthStore` (`touchToken` is optional).
2. Run the kit's test suite against it. Copy `test/flow.test.ts` and pass your store to `startApp({ store })`.
3. Make sure `takeGrant` cannot return the same grant twice under concurrency.
