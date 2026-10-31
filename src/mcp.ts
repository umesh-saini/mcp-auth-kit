import express, { type Express, type NextFunction, type Request, type RequestHandler, type Response, type Router } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { createAuthCore, type McpAuthCore, type McpAuthExtra, type McpAuthOptions } from './auth.js';
import { createConsentRouter, type ConsentPageData } from './consent.js';

/** Anything with connect/close: an `McpServer` or a low-level `Server`. */
export interface ConnectableServer {
  connect(transport: Transport): Promise<void>;
  close(): Promise<void>;
}

/** Who is calling, passed to `createServer` for every request. */
export interface McpRequestContext extends McpAuthExtra {
  clientId: string;
  scopes: string[];
  authInfo: AuthInfo;
  req: Request;
}

export interface MountOptions {
  /** Path of the MCP endpoint. Default '/mcp'. */
  path?: string;
  /**
   * Builds the MCP server for one request. The kit is stateless (a fresh server and transport per
   * request), so any instance behind a load balancer can answer any call. Tools can close over `ctx.userId`.
   */
  createServer: (ctx: McpRequestContext) => ConnectableServer | Promise<ConnectableServer>;
  /** Scopes every call must carry. */
  requiredScopes?: string[];
  /** Extra middleware before auth, e.g. `rateLimit({ windowMs: 60_000, limit: 120 })` from express-rate-limit. */
  middleware?: RequestHandler[];
  /** JSON body limit for MCP requests. Default '4mb'. */
  bodyLimit?: string;
  /** Called when a request throws. Default: console.error. */
  onError?: (err: unknown, req: Request) => void;
}

export interface CreateMcpAuthOptions extends McpAuthOptions {
  /** Replace the built-in consent page markup. */
  renderConsentPage?: (data: ConsentPageData) => string;
}

export interface McpAuth extends McpAuthCore {
  /**
   * The OAuth endpoints (/authorize, /token, /register, /revoke, /.well-known/*) and the built-in
   * consent page. Mount at the site root. `mount()` does this for you.
   */
  router(resourceUrl?: URL): Router;
  /** Bearer-token middleware for any route you want to protect with the same tokens. */
  protect(resourceUrl: URL, requiredScopes?: string[]): RequestHandler;
  /** One call: OAuth endpoints + consent page + a protected, stateless Streamable HTTP MCP endpoint. */
  mount(app: Express, options: MountOptions): { mcpUrl: URL };
}

/** Lets browser-based MCP clients (MCP Inspector, web agents) call the endpoint and read the auth headers. */
const openCors: RequestHandler = (req, res, next) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id, WWW-Authenticate',
    'Access-Control-Max-Age': '86400',
  });
  if (req.method === 'OPTIONS') return void res.sendStatus(204);
  next();
};

const rpcError = (res: Response, status: number, code: number, message: string) =>
  res.status(status).json({ jsonrpc: '2.0', error: { code, message }, id: null });

/**
 * Creates the OAuth 2.1 authorization server for your MCP endpoint.
 *
 * ```ts
 * const auth = createMcpAuth({ issuerUrl, store: new MemoryStore(), secret, getUser: (req) => req.user });
 * auth.mount(app, { createServer: ({ userId }) => buildServer(userId) });
 * ```
 */
export function createMcpAuth(options: CreateMcpAuthOptions): McpAuth {
  const core = createAuthCore(options);
  const { scopes, serviceName } = core.options;

  const router = (resourceUrl?: URL) => {
    const r = express.Router();
    r.use(
      mcpAuthRouter({
        provider: core.provider,
        issuerUrl: core.issuer,
        resourceServerUrl: resourceUrl,
        scopesSupported: scopes,
        resourceName: serviceName,
      })
    );
    if (!options.consentUrl) r.use(createConsentRouter(core, options.renderConsentPage));
    return r;
  };

  const protect = (resourceUrl: URL, requiredScopes?: string[]) =>
    requireBearerAuth({ verifier: core.provider, requiredScopes, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl) });

  function mount(app: Express, m: MountOptions) {
    const path = m.path ?? '/mcp';
    const mcpUrl = new URL(path, core.issuer);
    const onError = m.onError ?? ((err) => console.error('[mcp-oauth-starter] MCP request failed', err));
    app.use(router(mcpUrl));

    // A no-op when the app already parsed the body with its own express.json().
    const body = express.json({ limit: m.bodyLimit ?? '4mb' });

    app.options(path, openCors);
    app.post(path, openCors, ...(m.middleware ?? []), protect(mcpUrl, m.requiredScopes), body, async (req: Request, res: Response, _next: NextFunction) => {
      const authInfo = (req as Request & { auth?: AuthInfo }).auth!;
      const extra = authInfo.extra as unknown as McpAuthExtra;
      let server: ConnectableServer | undefined;
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => {
        transport.close().catch(() => undefined);
        server?.close().catch(() => undefined);
      });
      try {
        server = await m.createServer({ ...extra, clientId: authInfo.clientId, scopes: authInfo.scopes, authInfo, req });
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
      } catch (err) {
        onError(err, req);
        if (!res.headersSent) rpcError(res, 500, -32603, 'Internal error');
      }
    });
    // Stateless server: no SSE stream to resume and no session to delete.
    const notAllowed: RequestHandler = (_req, res) => void rpcError(res.set('Allow', 'POST'), 405, -32000, 'Method not allowed');
    app.get(path, openCors, notAllowed);
    app.delete(path, openCors, notAllowed);
    return { mcpUrl };
  }

  return { ...core, router, protect, mount };
}
