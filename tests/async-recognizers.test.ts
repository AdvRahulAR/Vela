/**
 * Async recognizers (NER services) and the Presidio adapter, against a mock
 * Presidio Analyzer. The mock "knows" names the built-in heuristics miss, and
 * reports offsets in Unicode code points like the real (Python) service.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  Vela,
  presidioRecognizer,
  codePointToUtf16Index,
  maskOpenAiRequestAsync,
  maskAnthropicRequestAsync,
  wrapOpenAiClient,
  wrapAnthropicClient,
  createFetchInterceptor,
  runProxy,
  VelaNotPreparedError,
  VelaRecognizerError,
  type AsyncEntityRecognizer,
} from '../src/index.js';

const KEY = new Uint8Array(32).fill(7);
/** Names only the "NER service" can find. */
const NER_NAMES = ['Thiruvenkatam', 'Oluwaseun Adeyemi', 'ராகுல்'];

type Mode = 'ok' | 'error' | 'hang';
let mode: Mode = 'ok';
let presidioCalls = 0;

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

async function readBody(req: AsyncIterable<unknown>): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

/** Mock Presidio /analyze: code-point offsets for every NER_NAMES occurrence. */
const presidio = createServer(async (req, res) => {
  presidioCalls++;
  const body = JSON.parse(await readBody(req)) as { text: string };
  if (mode === 'hang') return; // never respond
  if (mode === 'error') {
    res.writeHead(500).end('boom');
    return;
  }
  const cps = [...body.text];
  const results: unknown[] = [];
  for (const name of NER_NAMES) {
    const n = [...name];
    for (let i = 0; i + n.length <= cps.length; i++) {
      if (n.every((ch, j) => cps[i + j] === ch)) results.push({ entity_type: 'PERSON', start: i, end: i + n.length, score: 0.85 });
    }
  }
  res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(results));
});

/** Mock LLM upstream: records what it receives and echoes the last user text. */
const seen: string[] = [];
const upstream = createServer(async (req, res) => {
  const body = await readBody(req);
  seen.push(body);
  const parsed = JSON.parse(body) as { messages?: Array<{ content: unknown }> };
  const last = parsed.messages?.at(-1)?.content;
  const text = typeof last === 'string' ? last : JSON.stringify(last);
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ choices: [{ index: 0, message: { role: 'assistant', content: `echo: ${text}` }, finish_reason: 'stop' }] }));
});

let presidioUrl = '';
let upstreamUrl = '';
const makeVela = (extra: Partial<ConstructorParameters<typeof Vela>[0]> = {}) =>
  new Vela({ fpeKey: KEY, asyncRecognizers: [presidioRecognizer({ url: presidioUrl })], ...extra });

before(async () => {
  presidioUrl = `http://127.0.0.1:${await listen(presidio)}`;
  upstreamUrl = `http://127.0.0.1:${await listen(upstream)}`;
});
after(() => {
  presidio.closeAllConnections();
  presidio.close();
  upstream.close();
});

describe('Async recognizers', () => {
  it('maskAsync masks names only the NER service finds, and restores them', async () => {
    mode = 'ok';
    const vela = makeVela();
    const r = await vela.maskAsync('Thiruvenkatam met Oluwaseun Adeyemi at test@domain.com');
    // Multi-word names are registered first, so numbering need not follow text order.
    const m = /^\[(PERSON_\d)\] met \[(PERSON_\d)\] at \[EMAIL_1\]$/.exec(r.text);
    assert.ok(m && m[1] !== m[2], r.text);
    assert.equal(vela.unmask(r.text, r).text, 'Thiruvenkatam met Oluwaseun Adeyemi at test@domain.com');
  });

  it('converts Presidio code-point offsets to JavaScript offsets (emoji, Tamil)', async () => {
    mode = 'ok';
    const vela = makeVela();
    const r = await vela.maskAsync('🙂🙂 hi Thiruvenkatam and ராகுல் 👍');
    assert.equal(r.text, '🙂🙂 hi [PERSON_1] and [PERSON_2] 👍');
    assert.deepEqual(codePointToUtf16Index('a🙂b'), [0, 1, 3, 4]);
  });

  it('synchronous mask() refuses unprepared text when async recognizers are configured', () => {
    assert.throws(() => makeVela().mask('Thiruvenkatam'), VelaNotPreparedError);
  });

  it('masks inside JSON tool arguments and Anthropic tool results without missing a field', async () => {
    mode = 'ok';
    const vela = makeVela();
    const oai = await maskOpenAiRequestAsync(vela, {
      model: 'm',
      messages: [
        { role: 'user', content: 'look up the client' },
        { role: 'assistant', tool_calls: [{ id: 't1', type: 'function', function: { name: 'f', arguments: '{"customer_name":"Thiruvenkatam"}' } }] },
      ],
    });
    assert.doesNotMatch(JSON.stringify(oai.payload), /Thiruvenkatam/);
    const anth = await maskAnthropicRequestAsync(vela, {
      model: 'm',
      messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: [{ type: 'text', text: 'Owner: Oluwaseun Adeyemi' }] }] }],
    });
    assert.doesNotMatch(JSON.stringify(anth.payload), /Oluwaseun/);
  });

  it('client wrappers and the fetch interceptor run the recognizers', async () => {
    mode = 'ok';
    const vela = makeVela();
    let sentOpenAi = '';
    const openai = wrapOpenAiClient(
      {
        chat: {
          completions: {
            create: async (p: { model: string; messages: Array<{ role: string; content: string }> }) => {
              sentOpenAi = JSON.stringify(p);
              return { choices: [{ message: { role: 'assistant', content: `hi ${p.messages[0]?.content}` } }] };
            },
          },
        },
      },
      vela,
    );
    const out = await openai.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: 'Thiruvenkatam' }] });
    assert.doesNotMatch(sentOpenAi, /Thiruvenkatam/);
    assert.equal((out as { choices: Array<{ message: { content: string } }> }).choices[0]?.message.content, 'hi Thiruvenkatam');

    let sentAnthropic = '';
    const anthropic = wrapAnthropicClient(
      {
        messages: {
          create: async (p: unknown) => {
            sentAnthropic = JSON.stringify(p);
            return { content: [{ type: 'text', text: 'ok' }] };
          },
        },
      },
      vela,
    );
    await anthropic.messages.create({ model: 'm', max_tokens: 10, messages: [{ role: 'user', content: 'Oluwaseun Adeyemi' }] });
    assert.doesNotMatch(sentAnthropic, /Oluwaseun/);

    const before = seen.length;
    const velaFetch = createFetchInterceptor(vela, { targetUrls: ['/v1/chat/completions'] });
    const res = await velaFetch(`${upstreamUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'call Thiruvenkatam' }] }),
    });
    const json = (await res.json()) as { choices: Array<{ message: { content: string } }> };
    assert.doesNotMatch(seen[before] ?? '', /Thiruvenkatam/);
    assert.equal(json.choices[0]?.message.content, 'echo: call Thiruvenkatam');
  });

  it('keeps offsets right when a JSON key is used as context prefix', async () => {
    mode = 'ok';
    const vela = makeVela();
    const s = vela.createSession();
    const value = { customer_name: 'Thiruvenkatam', note: 'ref Oluwaseun Adeyemi today' };
    await s.prepareValue(value);
    assert.deepEqual(s.maskValue(value), { customer_name: '[PERSON_1]', note: 'ref [PERSON_2] today' });
  });

  it('a batched recognizer is called once per request, not once per string', async () => {
    let calls = 0;
    const counting: AsyncEntityRecognizer = async (texts) => {
      calls++;
      return texts.map(() => []);
    };
    const vela = new Vela({ fpeKey: KEY, asyncRecognizers: [counting] });
    await maskOpenAiRequestAsync(vela, {
      model: 'm',
      messages: [
        { role: 'system', content: 'be brief' },
        { role: 'user', content: 'first message' },
        { role: 'user', content: 'second message' },
      ],
    });
    assert.equal(calls, 1);
  });
});

describe('Recognizer failure handling', () => {
  async function proxyRequest(vela: Vela): Promise<{ status: number; upstreamHits: number }> {
    const before = seen.length;
    const proxy = runProxy(vela, { port: 0, upstream: upstreamUrl });
    await new Promise((r) => proxy.once('listening', r));
    try {
      const r = await fetch(`http://127.0.0.1:${(proxy.address() as AddressInfo).port}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'Thiruvenkatam, email test@domain.com' }] }),
      });
      await r.text();
      return { status: r.status, upstreamHits: seen.length - before };
    } finally {
      proxy.close();
    }
  }

  it('blocks by default when Presidio errors: proxy returns 503 and contacts no upstream', async () => {
    mode = 'error';
    assert.deepEqual(await proxyRequest(makeVela()), { status: 503, upstreamHits: 0 });
    await assert.rejects(makeVela().maskAsync('Thiruvenkatam'), VelaRecognizerError);
  });

  it('blocks on timeout', async () => {
    mode = 'hang';
    const t0 = Date.now();
    assert.deepEqual(await proxyRequest(makeVela({ recognizerTimeoutMs: 200 })), { status: 503, upstreamHits: 0 });
    assert.ok(Date.now() - t0 < 3000);
  });

  it("'continue' falls back to built-in detection and still masks what it can", async () => {
    mode = 'error';
    const before = seen.length;
    const r = await proxyRequest(makeVela({ recognizerFailure: 'continue' }));
    assert.deepEqual(r, { status: 200, upstreamHits: 1 });
    assert.doesNotMatch(seen[before] ?? '', /test@domain\.com/);
  });

  it('without async recognizers nothing changes (no NER calls, sync mask works)', async () => {
    const calls = presidioCalls;
    const vela = new Vela({ fpeKey: KEY });
    assert.equal(vela.mask('test@domain.com').text, '[EMAIL_1]');
    assert.equal((await vela.maskAsync('test@domain.com')).text, '[EMAIL_1]');
    assert.equal(presidioCalls, calls);
  });
});
