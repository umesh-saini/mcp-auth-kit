/**
 * A complete remote MCP server with OAuth 2.1 in ~100 lines: a per-user notes app.
 *
 *   npm run example
 *   npx @modelcontextprotocol/inspector   → connect to http://localhost:3000/mcp
 *
 * The login here is a demo (type any name). In your app, `getUser` reads your real session.
 */
import crypto from 'node:crypto';
import express from 'express';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createMcpAuth, MemoryStore, ok, fail } from '../../src/index.js';

const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT}`;
const SECRET = process.env.AUTH_SECRET ?? crypto.randomBytes(32).toString('base64url');

// ---- Your app: users, sessions, data ---------------------------------------------------------
const sessions = new Map<string, string>(); // session id → user name
const notes = new Map<string, string[]>(); // user → notes

function sessionUser(req: express.Request): string | null {
  const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
  return (sid && sessions.get(sid)) || null;
}

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get('/login', (req, res) => {
  const returnTo = String(req.query.returnTo ?? '/');
  res.type('html').send(`<!doctype html><meta name="viewport" content="width=device-width">
    <body style="font:16px system-ui;max-width:360px;margin:15vh auto">
    <h2>Sign in to Notes (demo)</h2>
    <form method="post"><input name="name" placeholder="Your name" required autofocus style="font:inherit;padding:8px">
    <input type="hidden" name="returnTo" value="${returnTo.replace(/"/g, '&quot;')}">
    <button style="font:inherit;padding:8px 14px">Sign in</button></form></body>`);
});

app.post('/login', (req, res) => {
  const sid = crypto.randomBytes(24).toString('base64url');
  sessions.set(sid, String(req.body.name).slice(0, 40));
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  const returnTo = String(req.body.returnTo || '/');
  res.redirect(303, returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/');
});

// ---- MCP + OAuth: this is all the kit needs --------------------------------------------------
const auth = createMcpAuth({
  issuerUrl: BASE_URL,
  store: new MemoryStore(), // swap for a database store in production (docs/storage.md)
  secret: SECRET,
  serviceName: 'Notes',
  scopes: ['notes'],
  tokenPrefix: 'notes',
  getUser: (req) => {
    const name = sessionUser(req);
    return name ? { id: name, name } : null;
  },
  loginUrl: '/login',
});

const { mcpUrl } = auth.mount(app, {
  createServer: ({ userId }) => {
    const server = new McpServer({ name: 'notes', version: '1.0.0' }, { instructions: 'Personal notes of the signed-in user.' });
    const mine = () => notes.get(userId) ?? notes.set(userId, []).get(userId)!;

    server.registerTool('add_note', { title: 'Add note', description: 'Save a note', inputSchema: { text: z.string().min(1).max(2000) } }, async ({ text }) => {
      mine().push(text);
      return ok({ saved: true, count: mine().length });
    });
    server.registerTool('list_notes', { title: 'List notes', description: 'All notes of the user', inputSchema: {}, annotations: { readOnlyHint: true } }, async () =>
      ok({ user: userId, notes: mine() })
    );
    server.registerTool(
      'delete_note',
      { title: 'Delete note', description: 'Delete a note by its index', inputSchema: { index: z.number().int().min(0) }, annotations: { destructiveHint: true } },
      async ({ index }) => (index < mine().length ? ok({ deleted: mine().splice(index, 1)[0] }) : fail(`There is no note #${index}.`))
    );
    return server;
  },
});

// A settings page would list connected apps like this:
app.get('/connections', async (req, res) => {
  const user = sessionUser(req);
  if (!user) return void res.redirect('/login?returnTo=/connections');
  res.json(await auth.listTokens(user));
});

app.get('/', (_req, res) => res.type('text').send(`Notes MCP server. Connect your AI app to ${mcpUrl.href}`));

app.listen(PORT, () => {
  console.log(`MCP endpoint:   ${mcpUrl.href}`);
  console.log(`Try it:         npx @modelcontextprotocol/inspector  (transport: Streamable HTTP, URL above)`);
});
