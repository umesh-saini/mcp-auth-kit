import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createMcpAuth, MemoryStore, ok, withAuth, type CreateMcpAuthOptions } from '../src/index.js';

export const SECRET = 'test-secret-test-secret-test-secret-123';
export const REDIRECT = 'http://localhost:9999/callback';

/** Starts an app on a random port. The signed-in user comes from the `x-test-user` header. */
export async function startApp(overrides: Partial<CreateMcpAuthOptions> = {}) {
  const server = http.createServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const store = new MemoryStore();
  const auth = createMcpAuth({
    issuerUrl: base,
    store,
    secret: SECRET,
    serviceName: 'Notes',
    scopes: ['notes', 'notes:write'],
    tokenPrefix: 'tst',
    getUser: (req) => {
      const id = req.header('x-test-user');
      return id ? { id, name: `User ${id}` } : null;
    },
    loginUrl: '/login',
    ...overrides,
  });
  const app = express();
  auth.mount(app, {
    onError: () => undefined,
    createServer: ({ userId }) => {
      const mcp = new McpServer({ name: 'notes', version: '1.0.0' });
      mcp.registerTool('whoami', { description: 'Who is calling', inputSchema: {} }, withAuth(async (_a, caller) => ok({ userId: caller.userId, viaContext: userId, kind: caller.kind })));
      mcp.registerTool('echo', { inputSchema: { text: z.string() } }, async ({ text }) => ok(text));
      return mcp;
    },
  });
  server.on('request', app);
  return { base, auth, store, close: () => new Promise<void>((r) => server.close(() => r())) };
}

export function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export async function register(base: string, extra: Record<string, unknown> = {}) {
  const res = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Test Agent', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], ...extra }),
  });
  if (res.status !== 201) throw new Error(`register ${res.status}: ${await res.text()}`);
  return (await res.json()) as { client_id: string; client_secret?: string };
}

/** GET /authorize → the consent request id. */
export async function startAuthorize(base: string, clientId: string, challenge: string, params: Record<string, string> = {}) {
  const url = new URL(`${base}/authorize`);
  url.search = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', ...params }).toString();
  const res = await fetch(url, { redirect: 'manual' });
  return { res, location: res.headers.get('location') ?? '' };
}

export async function consentPage(base: string, requestId: string, user = 'u1') {
  const res = await fetch(`${base}/oauth/consent?request=${requestId}`, { headers: { 'x-test-user': user }, redirect: 'manual' });
  const html = await res.text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? '';
  return { res, html, csrf };
}

export async function answerConsent(base: string, requestId: string, csrf: string, decision: 'approve' | 'deny', user = 'u1') {
  const res = await fetch(`${base}/oauth/consent`, {
    method: 'POST',
    headers: { 'x-test-user': user, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request: requestId, csrf, decision }),
    redirect: 'manual',
  });
  return { res, location: res.headers.get('location') ?? '' };
}

export async function tokenRequest(base: string, body: Record<string, string>) {
  const res = await fetch(`${base}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
  return { status: res.status, json: (await res.json()) as Record<string, any> };
}

/** The whole browser dance: register → authorize → approve → exchange the code. */
export async function connect(base: string, user = 'u1', params: Record<string, string> = {}) {
  const client = await register(base);
  const { verifier, challenge } = pkce();
  const { location } = await startAuthorize(base, client.client_id, challenge, params);
  const requestId = new URL(location).searchParams.get('request')!;
  const { csrf } = await consentPage(base, requestId, user);
  const answer = await answerConsent(base, requestId, csrf, 'approve', user);
  const code = new URL(answer.location).searchParams.get('code')!;
  const tokens = await tokenRequest(base, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: client.client_id, redirect_uri: REDIRECT });
  return { client, verifier, code, tokens: tokens.json, status: tokens.status };
}

/** Calls a tool through the official MCP client over Streamable HTTP. */
export async function callTool(base: string, token: string, name: string, args: Record<string, unknown> = {}) {
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  await client.connect(transport);
  try {
    const result = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
    return { ...result, data: JSON.parse(result.content[0].text) };
  } finally {
    await client.close();
  }
}

export const rawMcp = (base: string, token?: string) =>
  fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
