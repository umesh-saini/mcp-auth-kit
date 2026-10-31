import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthCore, createMcpAuth, MemoryStore } from '../src/index.js';
import { decrypt, encrypt } from '../src/crypto.js';
import { fail, ok, withAuth } from '../src/tools.js';
import { register, SECRET, startApp } from './helpers.js';

test('refuses a short secret', () => {
  assert.throws(() => createAuthCore({ issuerUrl: 'http://localhost', store: new MemoryStore(), secret: 'short' }), /at least 32/);
});

test('the built-in consent page needs getUser (or a custom consentUrl)', () => {
  const auth = createMcpAuth({ issuerUrl: 'http://localhost:1', store: new MemoryStore(), secret: SECRET });
  assert.throws(() => auth.router(), /getUser/);
  const custom = createMcpAuth({ issuerUrl: 'http://localhost:1', store: new MemoryStore(), secret: SECRET, consentUrl: 'http://localhost:5173/connect' });
  assert.doesNotThrow(() => custom.router());
});

test('encryption round-trips and fails with the wrong secret', () => {
  const enc = encrypt(SECRET, 'hello');
  assert.notEqual(enc, 'hello');
  assert.equal(decrypt(SECRET, enc), 'hello');
  assert.throws(() => decrypt('another-secret-another-secret-another', enc));
});

test('confidential client secrets are encrypted at rest', async () => {
  const app = await startApp();
  try {
    const client = await register(app.base, { token_endpoint_auth_method: 'client_secret_post' });
    assert.ok(client.client_secret);
    const raw = await app.store.getClient(client.client_id);
    assert.ok(raw?.client_secret?.startsWith('enc:'), 'stored encrypted');
    assert.ok(!raw!.client_secret!.includes(client.client_secret!));
    const viaProvider = await app.auth.provider.clientsStore.getClient(client.client_id);
    assert.equal(viaProvider?.client_secret, client.client_secret);
  } finally {
    await app.close();
  }
});

test('a custom consent UI drives the flow through approveConsent', async () => {
  const store = new MemoryStore();
  const auth = createAuthCore({ issuerUrl: 'http://localhost:3000', store, secret: SECRET, consentUrl: 'http://localhost:5173/connect' });
  let redirected = '';
  const res = { redirect: (_s: number, url: string) => (redirected = url) } as never;
  await store.saveClient({ client_id: 'c1', client_name: 'Cursor', redirect_uris: ['cursor://callback'] });
  await auth.provider.authorize({ client_id: 'c1', redirect_uris: ['cursor://callback'] }, { codeChallenge: 'abc', redirectUri: 'cursor://callback', state: 's1' }, res);
  const target = new URL(redirected);
  assert.equal(target.origin + target.pathname, 'http://localhost:5173/connect');
  const id = target.searchParams.get('request')!;

  const info = await auth.getConsentRequest(id);
  assert.equal(info?.clientName, 'Cursor');
  assert.deepEqual(info?.scopes, ['mcp']);

  const back = new URL(await auth.approveConsent(id, 'user-1'));
  assert.equal(back.protocol, 'cursor:');
  assert.ok(back.searchParams.get('code'));
  assert.equal(back.searchParams.get('state'), 's1');
  await assert.rejects(auth.approveConsent(id, 'user-1'), /expired/);
});

test('tool helpers', async () => {
  assert.deepEqual(ok({ a: 1 }), { content: [{ type: 'text', text: '{\n  "a": 1\n}' }] });
  assert.equal(fail('nope').isError, true);
  const tool = withAuth(async (_a: object, c) => ok(c.userId));
  assert.equal((await tool({}, {})).isError, true, 'no auth info → readable tool error');
  const r = await tool({}, { authInfo: { token: 't', clientId: 'c', scopes: [], extra: { userId: 'u9', tokenId: 'x', kind: 'pat' } } });
  assert.equal(r.content[0].text, 'u9');
});
