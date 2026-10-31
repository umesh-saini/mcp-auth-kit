import express, { Router, type Request, type Response } from 'express';
import type { ConsentRequestInfo, McpAuthCore } from './auth.js';
import { hmac, safeEqual } from './crypto.js';
import type { AuthUser } from './types.js';

export const CONSENT_PATH = '/oauth/consent';

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** Ties the form to both the request and the signed-in user, so another site cannot submit it. */
const csrfFor = (secret: string, requestId: string, userId: string) => hmac(secret, `consent:${requestId}:${userId}`);

export interface ConsentPageData {
  request: ConsentRequestInfo;
  user: AuthUser;
  serviceName: string;
  csrf: string;
  action: string;
}

/** The default consent screen. Pass `renderConsentPage` to `createMcpAuth` to replace it. */
export function defaultConsentPage({ request, user, serviceName, csrf, action }: ConsentPageData): string {
  const e = escapeHtml;
  const scopes = request.scopes.map((s) => `<li><code>${e(s)}</code></li>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect ${e(request.clientName)} to ${e(serviceName)}</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--text:#14161a;--muted:#5d6470;--line:#e3e6ea;--accent:#2f6fec}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--text:#eef0f3;--muted:#9aa3ae;--line:#2a2f37;--accent:#5b8ff9}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
main{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
h1{font-size:20px;line-height:1.3;margin:0 0 6px}p{margin:0 0 14px;color:var(--muted)}strong{color:var(--text)}
ul{margin:0 0 18px;padding-left:20px}code{font-size:13px}
.host{padding:10px 12px;border:1px solid var(--line);border-radius:10px;margin-bottom:20px;font-size:14px}
.row{display:flex;gap:10px}button{flex:1;padding:11px 14px;border-radius:10px;font:600 15px system-ui;cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--text)}
button[value=approve]{background:var(--accent);border-color:var(--accent);color:#fff}
</style></head><body><main>
<h1>${e(request.clientName)} wants to use your ${e(serviceName)} account</h1>
<p>Signed in as <strong>${e(user.name || user.id)}</strong>. It will be able to act as you through these permissions:</p>
<ul>${scopes}</ul>
<div class="host">After you answer you will be sent to <strong>${e(request.redirectHost)}</strong>. Only continue if that is the app you are connecting.</div>
<form method="post" action="${e(action)}">
<input type="hidden" name="request" value="${e(request.requestId)}"><input type="hidden" name="csrf" value="${e(csrf)}">
<div class="row"><button name="decision" value="deny">Deny</button><button name="decision" value="approve">Allow</button></div>
</form></main></body></html>`;
}

function messagePage(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:420px;margin:15vh auto;padding:0 24px}</style></head>
<body><h1 style="font-size:20px">${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></body></html>`;
}

function secureHeaders(res: Response) {
  res.set({
    // No framing (clickjacking), no third-party anything, nothing cached.
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  });
}

export function createConsentRouter(core: McpAuthCore, render: (data: ConsentPageData) => string = defaultConsentPage): Router {
  const { getUser, loginUrl, secret, serviceName } = core.options;
  if (!getUser) throw new Error('mcp-oauth-starter: pass `getUser` to use the built-in consent page, or set `consentUrl` to your own.');
  const router = Router();
  const action = new URL(CONSENT_PATH, core.issuer).pathname;

  async function signedIn(req: Request, res: Response): Promise<AuthUser | null> {
    const user = await getUser!(req);
    if (user?.id) return user;
    if (loginUrl && req.method === 'GET') {
      const target = new URL(loginUrl, core.issuer);
      target.searchParams.set('returnTo', req.originalUrl);
      res.redirect(302, target.pathname + target.search);
    } else {
      res.status(401).type('html').send(messagePage('Please sign in', `Sign in to ${serviceName}, then start the connection again from your AI app.`));
    }
    return null;
  }

  router.get(CONSENT_PATH, async (req, res, next) => {
    try {
      secureHeaders(res);
      const user = await signedIn(req, res);
      if (!user) return;
      const request = await core.getConsentRequest(String(req.query.request ?? ''));
      if (!request) {
        res.status(404).type('html').send(messagePage('Request expired', 'This connection request expired or was already answered. Start the connection again from your AI app.'));
        return;
      }
      res.type('html').send(render({ request, user, serviceName, action, csrf: csrfFor(secret, request.requestId, user.id) }));
    } catch (err) {
      next(err);
    }
  });

  router.post(CONSENT_PATH, express.urlencoded({ extended: false, limit: '8kb' }), async (req, res, next) => {
    try {
      secureHeaders(res);
      const user = await signedIn(req, res);
      if (!user) return;
      const { request = '', csrf = '', decision = '' } = (req.body ?? {}) as Record<string, string>;
      if (!safeEqual(String(csrf), csrfFor(secret, String(request), user.id))) {
        res.status(403).type('html').send(messagePage('Could not verify this form', 'Reload the page and try again.'));
        return;
      }
      if (!(await core.getConsentRequest(String(request)))) {
        res.status(404).type('html').send(messagePage('Request expired', 'Start the connection again from your AI app.'));
        return;
      }
      const target = decision === 'approve' ? await core.approveConsent(request, user.id) : await core.denyConsent(request);
      res.redirect(303, target);
    } catch (err) {
      next(err);
    }
  });

  return router;
}
