/**
 * Leak oracle: a mock LLM upstream that records everything it receives, plus a
 * set of synthetic sentinel values. A test sends the sentinels through some
 * Vela surface and asserts that none of them reached the upstream (or a log,
 * or an audit sink). Every fail-open fix starts with a test built on this.
 */
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/** Synthetic values every built-in detector finds. Never use real personal data. */
export const SENTINELS = {
  name: 'Rahul Sharma',
  pan: 'ABCDE1234F',
  aadhaar: '2345 6789 0124',
  email: 'rahul.sentinel@company.com',
  card: '4111 1111 1111 1111',
} as const;

export const SENTINEL_TEXT = `${SENTINELS.name}, PAN ${SENTINELS.pan}, Aadhaar ${SENTINELS.aadhaar}, email ${SENTINELS.email}, card ${SENTINELS.card}`;

/** Forms a sentinel can leak in: as written, without separators, JSON-escaped. */
function forms(v: string): string[] {
  return [...new Set([v, v.replace(/[\s-]/g, ''), v.toLowerCase()])];
}

/** Every sentinel found in `haystack` (empty when nothing leaked). */
export function findSentinels(haystack: string): string[] {
  const lower = haystack.toLowerCase();
  return Object.values(SENTINELS).filter((v) => forms(v).some((f) => lower.includes(f.toLowerCase())));
}

export function assertNoSentinel(haystack: string, where = 'upstream'): void {
  const leaked = findSentinels(haystack);
  assert.deepEqual(leaked, [], `sentinel values reached the ${where}: ${leaked.join(', ')}`);
}

export interface SeenRequest {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface MockUpstream {
  server: Server;
  url: string;
  seen: SeenRequest[];
  /** Everything received, as one string (method, url, headers and bodies). */
  dump(): string;
  close(): Promise<void>;
}

type Responder = (req: SeenRequest, res: ServerResponse) => void;

const defaultResponder: Responder = (_req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end('{}');
};

/** Start a recording upstream on a random loopback port. */
export async function startUpstream(respond: Responder = defaultResponder): Promise<MockUpstream> {
  const seen: SeenRequest[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const r: SeenRequest = {
      method: req.method ?? '',
      url: req.url ?? '',
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8'),
    };
    seen.push(r);
    respond(r, res);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    url: `http://127.0.0.1:${port}`,
    seen,
    dump: () => seen.map((s) => `${s.method} ${s.url} ${JSON.stringify(s.headers)} ${s.body}`).join('\n'),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

/** Wait for a server started with listen(0) and return its base URL. */
export async function baseUrlOf(server: Server): Promise<string> {
  if (!server.listening) await new Promise((r) => server.once('listening', r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}
