import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { answerConsent, callTool, connect, consentPage, pkce, rawMcp, register, startApp, startAuthorize, tokenRequest, REDIRECT } from './helpers.js';

describe('OAuth 2.1 flow end to end', () => {
  let app: Awaited<ReturnType<typeof startApp>>;
  before(async () => (app = await startApp()));
  after(() => app.close());

  test('publishes authorization-server and protected-resource metadata', async () => {
    const as = (await (await fetch(`${app.base}/.well-known/oauth-authorization-server`)).json()) as Record<string, any>;
    assert.equal(as.issuer, `${app.base}/`);
    assert.ok(as.registration_endpoint, 'dynamic client registration is advertised');
    assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(as.scopes_supported, ['notes', 'notes:write']);

    const pr = (await (await fetch(`${app.base}/.well-known/oauth-protected-resource/mcp`)).json()) as Record<string, any>;
    assert.equal(pr.resource, `${app.base}/mcp`);
    assert.deepEqual(pr.authorization_servers, [`${app.base}/`]);
  });

  test('an unauthenticated MCP call gets 401 pointing at the resource metadata', async () => {
    const res = await rawMcp(app.base);
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate') ?? '', /resource_metadata="[^"]+\/\.well-known\/oauth-protected-resource\/mcp"/);
  });

  test('register → authorize → consent → token → tools/call as the signed-in user', async () => {
    const { tokens, status } = await connect(app.base, 'alice');
    assert.equal(status, 200);
    assert.match(tokens.access_token, /^tst_at_/);
    assert.match(tokens.refresh_token, /^tst_rt_/);
    assert.equal(tokens.token_type.toLowerCase(), 'bearer');
    assert.equal(tokens.scope, 'notes notes:write');

    const res = await callTool(app.base, tokens.access_token, 'whoami');
    assert.deepEqual(res.data, { userId: 'alice', viaContext: 'alice', kind: 'oauth' });
  });

  test('the consent page shows the app, the user, the redirect host and is not frameable', async () => {
    const client = await register(app.base, { client_name: 'Claude' });
    const { location } = await startAuthorize(app.base, client.client_id, pkce().challenge);
    const requestId = new URL(location).searchParams.get('request')!;
    const { res, html, csrf } = await consentPage(app.base, requestId, 'bob');
    assert.equal(res.status, 200);
    assert.ok(csrf);
    assert.match(html, /Claude wants to use your Notes account/);
    assert.match(html, /User bob/);
    assert.match(html, /localhost:9999/);
    assert.match(res.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  });

  test('client names are HTML-escaped on the consent page', async () => {
    const client = await register(app.base, { client_name: '<script>alert(1)</script>' });
    const { location } = await startAuthorize(app.base, client.client_id, pkce().challenge);
    const { html } = await consentPage(app.base, new URL(location).searchParams.get('request')!);
    assert.ok(!html.includes('<script>alert(1)</script>'));
    assert.ok(html.includes('&lt;script&gt;'));
  });

  test('signed-out users are sent to the login page and come back to consent', async () => {
    const client = await register(app.base);
    const { location } = await startAuthorize(app.base, client.client_id, pkce().challenge);
    const consent = new URL(location);
    const res = await fetch(consent, { redirect: 'manual' });
    assert.equal(res.status, 302);
    const login = new URL(res.headers.get('location')!, app.base);
    assert.equal(login.pathname, '/login');
    assert.equal(login.searchParams.get('returnTo'), consent.pathname + consent.search);
  });

  test('denying redirects back with access_denied and the state', async () => {
    const client = await register(app.base);
    const { location } = await startAuthorize(app.base, client.client_id, pkce().challenge);
    const requestId = new URL(location).searchParams.get('request')!;
    const { csrf } = await consentPage(app.base, requestId);
    const answer = await answerConsent(app.base, requestId, csrf, 'deny');
    assert.equal(answer.res.status, 303);
    const back = new URL(answer.location);
    assert.equal(back.origin + back.pathname, REDIRECT);
    assert.equal(back.searchParams.get('error'), 'access_denied');
    assert.equal(back.searchParams.get('state'), 'xyz');
    // Answered requests are gone.
    assert.equal((await consentPage(app.base, requestId)).res.status, 404);
  });

  test('the consent form rejects a missing CSRF token and one minted for another user', async () => {
    const client = await register(app.base);
    const { location } = await startAuthorize(app.base, client.client_id, pkce().challenge);
    const requestId = new URL(location).searchParams.get('request')!;
    const { csrf: attackerCsrf } = await consentPage(app.base, requestId, 'attacker');
    assert.equal((await answerConsent(app.base, requestId, '', 'approve', 'victim')).res.status, 403);
    assert.equal((await answerConsent(app.base, requestId, attackerCsrf, 'approve', 'victim')).res.status, 403);
  });

  test('PKCE: a wrong code_verifier is rejected, and codes are single-use', async () => {
    const client = await register(app.base);
    const { verifier, challenge } = pkce();
    const { location } = await startAuthorize(app.base, client.client_id, challenge);
    const requestId = new URL(location).searchParams.get('request')!;
    const { csrf } = await consentPage(app.base, requestId);
    const code = new URL((await answerConsent(app.base, requestId, csrf, 'approve')).location).searchParams.get('code')!;
    const base = { grant_type: 'authorization_code', code, client_id: client.client_id, redirect_uri: REDIRECT };

    const wrong = await tokenRequest(app.base, { ...base, code_verifier: pkce().verifier });
    assert.equal(wrong.status, 400);
    assert.equal(wrong.json.error, 'invalid_grant');

    const right = await tokenRequest(app.base, { ...base, code_verifier: verifier });
    assert.equal(right.status, 200);
    const again = await tokenRequest(app.base, { ...base, code_verifier: verifier });
    assert.equal(again.status, 400);
    assert.equal(again.json.error, 'invalid_grant');
  });

  test('refresh rotates both tokens and retires the old ones', async () => {
    const { client, tokens } = await connect(app.base, 'carol');
    const refreshed = await tokenRequest(app.base, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
    assert.equal(refreshed.status, 200);
    assert.notEqual(refreshed.json.access_token, tokens.access_token);
    assert.notEqual(refreshed.json.refresh_token, tokens.refresh_token);

    const reuse = await tokenRequest(app.base, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
    assert.equal(reuse.status, 400);
    assert.equal((await rawMcp(app.base, tokens.access_token)).status, 401);
    assert.equal((await callTool(app.base, refreshed.json.access_token, 'whoami')).data.userId, 'carol');
    // Still one connected app, not two.
    assert.equal((await app.auth.listTokens('carol')).length, 1);
  });

  test('a refresh token only works for the client it was issued to', async () => {
    const { tokens } = await connect(app.base, 'dave');
    const other = await register(app.base);
    const res = await tokenRequest(app.base, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: other.client_id });
    assert.equal(res.status, 400);
  });

  test('the revocation endpoint disconnects the app', async () => {
    const { client, tokens } = await connect(app.base, 'erin');
    const res = await fetch(`${app.base}/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokens.refresh_token, client_id: client.client_id }),
    });
    assert.equal(res.status, 200);
    assert.equal((await rawMcp(app.base, tokens.access_token)).status, 401);
    assert.equal((await app.auth.listTokens('erin')).length, 0);
  });

  test('scopes: unknown scopes are refused, a subset is honoured', async () => {
    const client = await register(app.base);
    const bad = await startAuthorize(app.base, client.client_id, pkce().challenge, { scope: 'admin' });
    const badUrl = new URL(bad.location);
    assert.equal(badUrl.searchParams.get('error'), 'invalid_scope');

    const { tokens } = await connect(app.base, 'frank', { scope: 'notes' });
    assert.equal(tokens.scope, 'notes');
  });

  test('a resource for another origin is refused (RFC 8707)', async () => {
    const client = await register(app.base);
    const { location } = await startAuthorize(app.base, client.client_id, pkce().challenge, { resource: 'https://evil.example/mcp' });
    assert.equal(new URL(location).searchParams.get('error'), 'invalid_target');
  });

  test('/mcp is stateless: POST only, with CORS preflight', async () => {
    const res = await fetch(`${app.base}/mcp`);
    assert.equal(res.status, 405);
    assert.equal(res.headers.get('allow'), 'POST');
    const pre = await fetch(`${app.base}/mcp`, { method: 'OPTIONS' });
    assert.equal(pre.status, 204);
    assert.match(pre.headers.get('access-control-expose-headers') ?? '', /WWW-Authenticate/);
  });
});

describe('personal access tokens and account checks', () => {
  test('personal tokens work on /mcp and can be revoked by their owner only', async () => {
    const app = await startApp();
    try {
      const { token, record } = await app.auth.createPersonalToken('gina', 'CLI');
      assert.match(token, /^tst_pat_/);
      assert.equal(record.last4, token.slice(-4));
      assert.ok(!('accessHash' in record));
      assert.deepEqual((await callTool(app.base, token, 'whoami')).data, { userId: 'gina', viaContext: 'gina', kind: 'pat' });

      assert.equal(await app.auth.revokeTokenById('someone-else', record.id), false);
      assert.equal((await rawMcp(app.base, token)).status, 200);
      assert.equal(await app.auth.revokeTokenById('gina', record.id), true);
      assert.equal((await rawMcp(app.base, token)).status, 401);
    } finally {
      await app.close();
    }
  });

  test('isUserActive=false locks out existing tokens', async () => {
    const banned = new Set<string>();
    const app = await startApp({ isUserActive: (id) => !banned.has(id) });
    try {
      const { tokens } = await connect(app.base, 'hank');
      assert.equal((await rawMcp(app.base, tokens.access_token)).status, 200);
      banned.add('hank');
      assert.equal((await rawMcp(app.base, tokens.access_token)).status, 401);
    } finally {
      await app.close();
    }
  });

  test('tokens with a foreign prefix are rejected without a store lookup', async () => {
    const app = await startApp();
    try {
      assert.equal((await rawMcp(app.base, 'ghp_somethingelse')).status, 401);
    } finally {
      await app.close();
    }
  });
});
