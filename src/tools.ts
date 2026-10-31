/** Small helpers for writing tools that act as the signed-in user. */
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { McpAuthExtra } from './auth.js';

export type ToolExtra = { authInfo?: AuthInfo };
export type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean; [key: string]: unknown };

/** JSON tool result. */
export const ok = (data: unknown): ToolResult => ({ content: [{ type: 'text', text: typeof data === 'string' ? data : JSON.stringify(data, null, 2) }] });

/** A tool error the model can read and recover from (instead of a protocol error). */
export const fail = (message: string): ToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

/** The verified caller of a tool call (from the `extra` argument the SDK passes to handlers). */
export function authOf(extra: ToolExtra): McpAuthExtra & { clientId: string; scopes: string[] } {
  const e = extra.authInfo?.extra as Partial<McpAuthExtra> | undefined;
  if (!extra.authInfo || typeof e?.userId !== 'string') throw new Error('Not signed in. Reconnect this server in your AI app.');
  return { userId: e.userId, tokenId: String(e.tokenId), kind: e.kind ?? 'oauth', clientId: extra.authInfo.clientId, scopes: extra.authInfo.scopes };
}

/**
 * Wraps a tool handler: resolves the caller and turns thrown errors into readable tool errors.
 *
 * ```ts
 * server.registerTool('list_notes', { inputSchema: {} }, withAuth(async (_args, { userId }) => ok(await notes.list(userId))));
 * ```
 */
export function withAuth<A>(fn: (args: A, caller: ReturnType<typeof authOf>) => Promise<ToolResult> | ToolResult) {
  return async (args: A, extra: ToolExtra): Promise<ToolResult> => {
    try {
      return await fn(args, authOf(extra));
    } catch (err) {
      return fail((err as Error)?.message || String(err));
    }
  };
}
