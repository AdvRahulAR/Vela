/**
 * Regression tests for the issues found in the 0.2.3 audit.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createDecipheriv } from 'node:crypto';
import {
  Vela,
  FpeMasker,
  QuantumKeyManager,
  detectPii,
  validateVerhoeff,
  generateVerhoeffChecksum,
  validateLuhn,
  luhnCheckDigit,
  validateGstin,
  validateIban,
  maskOpenAiRequest,
  maskOpenAiResponsesRequest,
  unmaskOpenAiResponse,
  unmaskOpenAiStream,
  maskAnthropicRequest,
  unmaskAnthropicResponse,
  createSseTransformer,
  createFetchInterceptor,
  createExpressMiddleware,
  wrapOpenAiClient,
  wrapAnthropicClient,
  runProxy,
  VelaInputTooLargeError,
} from '../src/index.js';

const KEY = new Uint8Array(32).fill(7);
const vela = new Vela({ fpeKey: KEY });
const rand = (n: number) => Math.floor(Math.random() * n);

function randomAadhaar(): string {
  let b = String(2 + rand(8));
  for (let i = 0; i < 10; i++) b += rand(10);
  return b + generateVerhoeffChecksum(b);
}

describe('FPE keeps values structurally valid', () => {
  const s = vela.createSession();
  it('Aadhaar ciphertext passes Verhoeff and starts 2-9', () => {
    for (let i = 0; i < 200; i++) {
      const c = s.mask(`Aadhaar ${randomAadhaar()}`).slice(8);
      assert.ok(validateVerhoeff(c) && /^[2-9]/.test(c), c);
    }
  });
  it('PAN ciphertext is PAN-shaped and keeps the holder-type letter', () => {
    const L = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (let i = 0; i < 200; i++) {
      const pan = `${L[rand(26)]}${L[rand(26)]}${L[rand(26)]}P${L[rand(26)]}${1000 + rand(9000)}${L[rand(26)]}`;
      assert.match(s.mask(`PAN ${pan}`).slice(4), /^[A-Z]{3}P[A-Z]\d{4}[A-Z]$/);
    }
  });
  it('card ciphertext passes Luhn and keeps the brand digit', () => {
    for (let i = 0; i < 200; i++) {
      let cc = '5' + Array.from({ length: 14 }, () => rand(10)).join('');
      cc += luhnCheckDigit(cc);
      const c = s.mask(`card ${cc}`).slice(5);
      assert.ok(validateLuhn(c) && c[0] === '5', c);
    }
  });
  it('GSTIN gets a valid check char and embeds the same masked PAN', () => {
    const out = s.mask('GSTIN 27AAPFU0939F1ZV belongs to PAN AAPFU0939F');
    const [, g, p] = /GSTIN (\S+) belongs to PAN (\S+)/.exec(out) ?? [];
    assert.ok(g && p);
    assert.ok(validateGstin(g));
    assert.equal(g.slice(2, 12), p);
    assert.equal(g.slice(0, 2), '27');
  });
  it('IBAN keeps country + spacing and recomputes check digits', () => {
    const c = s.mask('IBAN GB82 WEST 1234 5698 7654 32').slice(5);
    assert.match(c, /^GB\d{2} [A-Z]{4} \d{4} \d{4} \d{4} \d{2}$/);
    assert.ok(validateIban(c));
  });
  it('IPv4 stays a valid address; phone keeps +91 and a mobile prefix', () => {
    const ip = s.mask('ip 192.168.1.20').slice(3);
    assert.ok(ip.split('.').every((o) => Number(o) <= 255 && String(Number(o)) === o), ip);
    const ph = s.mask('call +91 98765 43210').slice(5);
    assert.match(ph, /^\+91 [6-9]\d{4} \d{5}$/);
  });
  it('is a bijection (decryptEntity inverts encryptEntity)', () => {
    const f = new FpeMasker(KEY);
    for (const [t, v] of [
      ['AADHAAR', '2345 6789 0124'],
      ['CREDIT_CARD', '4111 1111 1111 1111'],
      ['PAN', 'ABCDE1234F'],
      ['IBAN', 'DE89370400440532013000'],
      ['IP_ADDRESS', '10.0.0.1'],
      ['SSN', '123-45-6789'],
      ['GSTIN', '27AAPFU0939F1ZV'],
    ] as const) {
      const c = f.encryptEntity(t, v, 'seed');
      assert.ok(c && c !== v);
      assert.equal(f.decryptEntity(t, c, 'seed'), v);
    }
  });
});

describe('Fail closed', () => {
  it('values too small to encrypt safely become tokens instead of leaking', () => {
    const f = new FpeMasker(KEY);
    assert.equal(f.encrypt('12345'), null); // below NIST 10^6 domain
    const r = vela.mask('IPv6 2001:db8::1 and PIN code 560001');
    assert.doesNotMatch(r.text, /2001:db8::1|560001/);
    assert.match(r.text, /\[IP_ADDRESS_1\]/);
    assert.match(r.text, /\[PIN_CODE_1\]/);
  });
});

describe('Sessions', () => {
  it('gives every value a unique placeholder across messages (stream and non-stream agree)', async () => {
    const { payload, session } = maskOpenAiRequest(vela, {
      messages: [
        { role: 'user', content: 'My email is alice@a.com' },
        { role: 'user', content: 'Colleague is bob@b.com' },
      ],
    });
    assert.equal(payload.messages[0]?.content, 'My email is [EMAIL_1]');
    assert.equal(payload.messages[1]?.content, 'Colleague is [EMAIL_2]');
    const resp = unmaskOpenAiResponse(vela, { choices: [{ message: { role: 'assistant', content: 'Email [EMAIL_2]' } }] }, session);
    assert.equal(resp.choices?.[0]?.message?.content, 'Email bob@b.com');
    async function* src() {
      yield { choices: [{ index: 0, delta: { content: 'Email [EMA' } }] };
      yield { choices: [{ index: 0, delta: { content: 'IL_2]' }, finish_reason: 'stop' }] };
    }
    let text = '';
    for await (const c of unmaskOpenAiStream(src(), session)) text += c.choices?.[0]?.delta?.content ?? '';
    assert.equal(text, 'Email bob@b.com');
  });
  it('no sessionId → unlinkable across sessions; same sessionId → stable', () => {
    const t = 'PAN ABCDE1234F';
    assert.notEqual(vela.mask(t).text, vela.mask(t).text);
    const a = vela.mask(t, vela.createSession({ sessionId: 'conv-1' })).text;
    const b = vela.mask(t, vela.createSession({ sessionId: 'conv-1' })).text;
    const c = vela.mask(t, vela.createSession({ sessionId: 'conv-2' })).text;
    assert.equal(a, b);
    assert.notEqual(a, c);
  });
  it('names introduced in a later message are masked in earlier ones too', () => {
    const { payload } = maskOpenAiRequest(vela, {
      messages: [
        { role: 'user', content: 'Sharma called yesterday.' },
        { role: 'user', content: 'My name is Rahul Sharma.' },
      ],
    });
    assert.doesNotMatch(JSON.stringify(payload), /Sharma|Rahul/);
  });
});

describe('Detection coverage', () => {
  const types = (t: string) => detectPii(t).map((e) => `${e.type}:${e.value}`);
  it('names, addresses, DOB, passport, bank, IFSC, UPI, PIN', () => {
    const got = types(
      'Rahul Sharma lives at 12 MG Road, Bengaluru 560001, DOB 14/03/1990, passport K1234567. A/c 50100123456789 IFSC HDFC0001234 UPI rahul@okhdfc',
    );
    for (const want of [
      'PERSON:Rahul Sharma',
      'ADDRESS:12 MG Road, Bengaluru 560001',
      'DATE_OF_BIRTH:14/03/1990',
      'PASSPORT:K1234567',
      'BANK_ACCOUNT:50100123456789',
      'IFSC:HDFC0001234',
      'UPI_ID:rahul@okhdfc',
    ]) {
      assert.ok(got.includes(want), `${want} missing from ${got.join(', ')}`);
    }
  });
  it('international phones, spaced IBAN, IPv6, lowercase PAN', () => {
    const got = types('+1 415-555-2671, +44 20 7946 0958, GB82 WEST 1234 5698 7654 32, 2001:db8::1, pan abcde1234f');
    assert.equal(got.filter((g) => g.startsWith('PHONE')).length, 2);
    assert.ok(got.includes('IBAN:GB82 WEST 1234 5698 7654 32'));
    assert.ok(got.includes('IP_ADDRESS:2001:db8::1'));
    assert.ok(got.includes('PAN:abcde1234f'));
  });
  it('signatures, honorifics and re-mentions', () => {
    const got = types('Dear Mr. Sharma, please meet Priya.\nRegards,\nAnita Desai. Later DESAI replied.');
    for (const n of ['PERSON:Sharma', 'PERSON:Priya', 'PERSON:Anita Desai', 'PERSON:DESAI']) assert.ok(got.includes(n), n);
  });
  it('avoids common false positives', () => {
    assert.deepEqual(types('Order ID 7012345678 shipped; invoice 8000000000.'), []);
    assert.deepEqual(types('Will you check? I am Happy to help. Sunny day in May. The Supreme Court ruled.'), []);
  });
  it('pluggable recognizers (NER) are honoured', () => {
    const v = new Vela({ recognizers: [(t) => [{ type: 'LOCATION', start: t.indexOf('Pune'), end: t.indexOf('Pune') + 4 }]], tokenTypes: ['LOCATION'] });
    assert.equal(v.mask('Flying to Pune').text, 'Flying to [LOCATION_1]');
  });
});

describe('Tolerant restoration', () => {
  it('restores values the LLM reformatted', () => {
    const r = vela.mask('Aadhaar 2345 6789 0124, PAN ABCDE1234F, email a@b.co');
    const [aad] = /\d{4} \d{4} \d{4}/.exec(r.text) ?? [''];
    const [pan] = /[A-Z]{5}\d{4}[A-Z]/.exec(r.text) ?? [''];
    const llm = `ID ${aad.replace(/ /g, '')}, pan ${pan.toLowerCase()}, mail EMAIL_1 / [ email_1 ]`;
    assert.equal(vela.unmask(llm, r).text, 'ID 2345 6789 0124, pan ABCDE1234F, mail a@b.co / a@b.co');
  });
});

describe('JSON safety', () => {
  it('tool-call arguments stay valid JSON both ways, with quotes escaped on restore', () => {
    const { payload, session } = maskOpenAiRequest(vela, {
      messages: [
        { role: 'user', content: 'Ping "Bob" O\'Neil' },
        {
          role: 'assistant',
          tool_calls: [{ id: '1', type: 'function', function: { name: 'send', arguments: '{"customer_name":"Rahul Sharma","email":"r@d.ai"}' } }],
        },
      ],
    });
    const args = payload.messages[1]?.tool_calls?.[0]?.function?.arguments as string;
    const parsed = JSON.parse(args);
    assert.match(parsed.customer_name, /^\[PERSON_\d+\]$/);
    assert.match(parsed.email, /^\[EMAIL_\d+\]$/);
    // A restored value containing quotes must not break JSON-string arguments
    const s2 = vela.createSession();
    const masked = s2.mask('Name: Ann "Ace" Lee');
    const tok = /\[PERSON_\d+\]/.exec(masked)?.[0] ?? '';
    const back = s2.unmaskValue({ arguments: `{"who":"${tok}"}` });
    assert.doesNotThrow(() => JSON.parse(back.arguments));
    assert.ok(session.replacements.length >= 2);
  });
});

describe('Streaming', () => {
  it('OpenAI chat: separate lanes per choice and per tool call, flushed on finish_reason', async () => {
    const s = vela.createSession();
    const m = s.mask('a@x.io and b@y.io');
    assert.equal(m, '[EMAIL_1] and [EMAIL_2]');
    async function* src() {
      yield { choices: [{ index: 0, delta: { content: 'to [EMA' } }, { index: 1, delta: { content: 'cc [EMAIL' } }] };
      yield { choices: [{ index: 1, delta: { content: '_2]' } }, { index: 0, delta: { content: 'IL_1]' } }] };
      yield { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"to":"[EMAIL' } }] } }] };
      yield { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '_1]"}' } }] } }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }, { index: 1, delta: {}, finish_reason: 'stop' }] };
    }
    const content: Record<number, string> = { 0: '', 1: '' };
    let args = '';
    for await (const c of unmaskOpenAiStream(src(), s)) {
      for (const ch of c.choices ?? []) {
        content[ch.index] += ch.delta?.content ?? '';
        args += ch.delta?.tool_calls?.map((t: { function?: { arguments?: string } }) => t.function?.arguments ?? '').join('') ?? '';
      }
    }
    assert.equal(content[0], 'to a@x.io');
    assert.equal(content[1], 'cc b@y.io');
    assert.deepEqual(JSON.parse(args), { to: 'a@x.io' });
  });

  it('Anthropic SSE: text and input_json deltas restored, held text flushed before content_block_stop', () => {
    const s = vela.createSession();
    s.mask('PAN ABCDE1234F, mail z@z.io');
    const pan = s.replacements.find((r) => r.type === 'PAN')!.masked;
    const t = createSseTransformer('anthropic-messages', s);
    const ev = (o: object) => `event: ${(o as { type: string }).type}\ndata: ${JSON.stringify(o)}\n\n`;
    let out = t.push(ev({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: `PAN ${pan.slice(0, 4)}` } }));
    out += t.push(ev({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: `${pan.slice(4)} ok [EMAIL_` } }));
    out += t.push(ev({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '1]' } }));
    out += t.push(ev({ type: 'content_block_stop', index: 0 }));
    out += t.push(ev({ type: 'message_stop' }));
    out += t.end();
    const texts = [...out.matchAll(/^data: (.*)$/gm)]
      .map((m) => JSON.parse(m[1] as string))
      .filter((e) => e.type === 'content_block_delta')
      .map((e) => e.delta.text)
      .join('');
    assert.equal(texts, 'PAN ABCDE1234F ok z@z.io');
    assert.ok(out.indexOf('content_block_stop') > out.lastIndexOf('text_delta'));
  });

  it('Responses SSE: output_text deltas and done events restored', () => {
    const s = vela.createSession();
    s.mask('mail q@q.io');
    const t = createSseTransformer('openai-responses', s);
    const ev = (o: object) => `event: ${(o as { type: string }).type}\ndata: ${JSON.stringify(o)}\n\n`;
    let out = t.push(ev({ type: 'response.output_text.delta', item_id: 'm1', output_index: 0, content_index: 0, delta: 'hi [EMAIL' }));
    out += t.push(ev({ type: 'response.output_text.done', item_id: 'm1', output_index: 0, content_index: 0, text: 'hi [EMAIL_1]' }));
    out += t.end();
    assert.doesNotMatch(out, /EMAIL_1/);
    assert.match(out, /q@q\.io/);
  });
});

describe('Anthropic + Responses request coverage', () => {
  it('masks system prompt, text blocks, tool_use input and tool_result; restores response blocks', () => {
    const { payload, session } = maskAnthropicRequest(vela, {
      model: 'claude',
      system: 'User is Rahul Sharma, PAN ABCDE1234F, email r@d.ai',
      messages: [
        { role: 'user', content: [{ type: 'text', text: 'Card 4111 1111 1111 1111' }] },
        { role: 'assistant', content: [{ type: 'tool_use', id: 't', name: 'lookup', input: { email: 'r@d.ai' } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: 'Phone +91 98765 43210' }] },
      ],
    });
    const wire = JSON.stringify(payload);
    for (const leak of ['Rahul', 'ABCDE1234F', 'r@d.ai', '4111 1111 1111 1111', '98765 43210']) assert.ok(!wire.includes(leak), leak);
    const resp = unmaskAnthropicResponse({ content: [{ type: 'text', text: (payload as { system: string }).system }] }, session);
    assert.equal(resp.content[0]?.text, 'User is Rahul Sharma, PAN ABCDE1234F, email r@d.ai');
  });
  it('masks Responses API requests instead of crashing', () => {
    const { payload } = maskOpenAiResponsesRequest(vela, {
      model: 'gpt',
      instructions: 'Customer email a@b.io',
      input: [{ role: 'user', content: [{ type: 'input_text', text: 'PAN ABCDE1234F' }] }, { type: 'function_call_output', call_id: 'c', output: '{"phone":"+91 98765 43210"}' }],
    });
    const wire = JSON.stringify(payload);
    assert.ok(!wire.includes('a@b.io') && !wire.includes('ABCDE1234F') && !wire.includes('98765'));
  });
});

describe('Client wrappers', () => {
  it('wrapOpenAiClient covers chat and responses; wrapAnthropicClient covers messages', async () => {
    let seen = '';
    const echo = async (p: unknown) => {
      seen = JSON.stringify(p);
      return { choices: [{ message: { content: seen } }], output: [{ content: [{ text: seen }] }], content: [{ type: 'text', text: seen }] };
    };
    const oai = wrapOpenAiClient({ chat: { completions: { create: echo } }, responses: { create: echo } }, vela);
    const r1 = await oai.chat.completions.create({ messages: [{ role: 'user', content: 'mail a@b.io' }] });
    assert.ok(!seen.includes('a@b.io') && r1.choices[0]!.message.content.includes('a@b.io'));
    const r2 = await oai.responses!.create({ input: 'mail a@b.io' });
    assert.ok(!seen.includes('a@b.io') && r2.output[0]!.content[0]!.text.includes('a@b.io'));
    const ant = wrapAnthropicClient({ messages: { create: echo } }, vela);
    const r3 = await ant.messages.create({ system: 'mail a@b.io', messages: [] });
    assert.ok(!seen.includes('a@b.io') && r3.content[0]!.text.includes('a@b.io'));
  });
});

// ── HTTP-level tests with a mock upstream ────────────────────────────────────

function listen(server: Server, host = '127.0.0.1'): Promise<number> {
  return new Promise((resolve) => server.listen(0, host, () => resolve((server.address() as AddressInfo).port)));
}

function mockUpstream(): { server: Server; seen: Array<{ url: string; headers: Record<string, unknown>; body: any }> } {
  const seen: Array<{ url: string; headers: Record<string, unknown>; body: any }> = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    seen.push({ url: req.url ?? '', headers: req.headers, body });
    const echo = JSON.stringify(body);
    if (body.stream) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      // Echo the masked prompt back 3 characters at a time
      const text = body.messages?.[0]?.content ?? '';
      for (let i = 0; i < text.length; i += 3) {
        res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: text.slice(i, i + 3) } }] })}\n\n`);
      }
      res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })}\n\n`);
      res.end('data: [DONE]\n\n');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    if (req.url?.endsWith('/messages')) res.end(JSON.stringify({ content: [{ type: 'text', text: echo }] }));
    else res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: echo } }] }));
  });
  return { server, seen };
}

describe('Proxy / fetch / Express', () => {
  it('proxy binds to 127.0.0.1 by default and logs assigned port on port 0', async () => {
    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => { logs.push(args.join(' ')); };
    try {
      const p = runProxy(vela, { port: 0 });
      await new Promise((r) => p.once('listening', r));
      const addr = p.address() as AddressInfo;
      assert.equal(addr.address, '127.0.0.1');
      assert.ok(addr.port > 0);
      assert.ok(logs.some((l) => l.includes(`127.0.0.1:${addr.port}`)), `Expected banner to show actual port, got: ${logs.join('; ')}`);
      p.close();
    } finally {
      console.log = origLog;
    }
  });

  it('proxy: JSON + SSE round trip, UTF-8 safe, session header stripped, Anthropic key header', async () => {
    const up = mockUpstream();
    const upPort = await listen(up.server);
    const proxy = runProxy(vela, { port: 0, upstream: `http://127.0.0.1:${upPort}`, apiKey: 'sk-test' });
    await new Promise((r) => proxy.once('listening', r));
    const base = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    try {
      const prompt = 'नमस्ते — PAN ABCDE1234F, email ä@example.com, 名前 Rahul Sharma';
      const r1 = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-vela-session': 'conv-9' },
        body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: prompt }] }),
      });
      const j = (await r1.json()) as { choices: Array<{ message: { content: string } }> };
      const wire = JSON.stringify(up.seen[0]?.body);
      assert.ok(!wire.includes('ABCDE1234F') && !wire.includes('ä@example.com') && !wire.includes('Rahul'));
      assert.ok(wire.includes('नमस्ते') && wire.includes('名前'));
      assert.equal(up.seen[0]?.headers['x-vela-session'], undefined);
      assert.equal(up.seen[0]?.headers['authorization'], 'Bearer sk-test');
      assert.equal(JSON.parse(j.choices[0]!.message.content).messages[0].content, prompt);

      const r2 = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'm', stream: true, messages: [{ role: 'user', content: prompt }] }),
      });
      const sse = await r2.text();
      const streamed = [...sse.matchAll(/^data: (\{.*\})$/gm)].map((m) => JSON.parse(m[1] as string).choices[0].delta.content ?? '').join('');
      assert.equal(streamed, prompt);
      assert.match(sse, /data: \[DONE\]/);

      await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'c', system: 'PAN ABCDE1234F', messages: [{ role: 'user', content: 'hi' }] }),
      });
      const ant = up.seen[2]!;
      assert.equal(ant.headers['x-api-key'], 'sk-test');
      assert.equal(ant.headers['authorization'], undefined);
      assert.ok(!JSON.stringify(ant.body).includes('ABCDE1234F'));
    } finally {
      proxy.close();
      up.server.close();
    }
  });

  it('fetch interceptor handles Anthropic and Request objects', async () => {
    const up = mockUpstream();
    const port = await listen(up.server);
    const f = createFetchInterceptor(vela);
    try {
      const res = await f(
        new Request(`http://127.0.0.1:${port}/v1/messages`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-api-key': 'k' },
          body: JSON.stringify({ system: 'Card 4111 1111 1111 1111', messages: [{ role: 'user', content: 'mail a@b.io' }] }),
        }),
      );
      const j = (await res.json()) as { content: Array<{ text: string }> };
      assert.ok(!JSON.stringify(up.seen[0]?.body).includes('a@b.io'));
      assert.ok(!JSON.stringify(up.seen[0]?.body).includes('4111 1111 1111 1111'));
      assert.equal(up.seen[0]?.headers['x-api-key'], 'k');
      const echoed = JSON.parse(j.content[0]!.text);
      assert.equal(echoed.system, 'Card 4111 1111 1111 1111');
    } finally {
      up.server.close();
    }
  });

  it('Express middleware proxies with query string and restores', async () => {
    const up = mockUpstream();
    const port = await listen(up.server);
    const mw = createExpressMiddleware(vela, { upstream: `http://127.0.0.1:${port}` });
    let status = 0;
    let body = '';
    const res = {
      status: (c: number) => ((status = c), res),
      json: (b: unknown) => (body = JSON.stringify(b)),
      setHeader: () => undefined,
      writeHead: (c: number) => (status = c),
      write: (c: unknown) => ((body += Buffer.from(c as Uint8Array).toString()), true),
      end: () => undefined,
    };
    try {
      await mw(
        { path: '/v1/chat/completions', url: '/v1/chat/completions?x=1', method: 'POST', headers: {}, body: { messages: [{ role: 'user', content: 'mail a@b.io' }] } },
        res,
        () => assert.fail('next() should not be called'),
      );
      assert.equal(status, 200);
      assert.equal(up.seen[0]?.url, '/v1/chat/completions?x=1');
      assert.match(body, /a@b\.io/);
      assert.ok(!JSON.stringify(up.seen[0]?.body).includes('a@b.io'));
    } finally {
      up.server.close();
    }
  });
});

describe('Key sealing', () => {
  it('seals with an HKDF-derived key, not the raw shared secret, and supports AAD', () => {
    const kp = QuantumKeyManager.generateKeyPair();
    const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
    const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);
    const aad = Buffer.from('tenant-42');
    const sealed = QuantumKeyManager.sealFpeKey(fpeKey, sharedSecret, aad);
    assert.deepEqual(QuantumKeyManager.unsealFpeKey(sealed, sharedSecret, aad), fpeKey);
    assert.throws(() => QuantumKeyManager.unsealFpeKey(sealed, sharedSecret, Buffer.from('other')));
    const raw = createDecipheriv('aes-256-gcm', sharedSecret, sealed.iv);
    raw.setAuthTag(sealed.tag);
    raw.setAAD(aad);
    assert.throws(() => Buffer.concat([raw.update(sealed.data), raw.final()]));
  });
});

describe('0.3.1 gap fixes', () => {
  it('masks xapp- Slack app tokens', () => {
    const tok = 'xapp-1-A0123456789-1234567890123-' + 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
    const r = vela.mask(`token ${tok} end`);
    assert.ok(!r.text.includes('a1b2c3d4'), r.text);
  });

  it('masks PII in tool descriptions and schemas (Anthropic + OpenAI)', () => {
    const anth = maskAnthropicRequest(vela, {
      model: 'm',
      messages: [{ role: 'user', content: 'hi' }],
      tools: [{ name: 't', description: 'Look up PAN ABCDE1234F', input_schema: { type: 'object', properties: { p: { type: 'string', default: 'ABCDE1234F' } } } }],
    });
    assert.ok(!JSON.stringify(anth.payload).includes('ABCDE1234F'));
    const oai = maskOpenAiRequest(vela, {
      model: 'm',
      messages: [{ role: 'user', content: 'hi' }],
      tools: [{ type: 'function', function: { name: 't', description: 'Look up PAN ABCDE1234F', parameters: { type: 'object', properties: {} } } }],
    } as never);
    assert.ok(!JSON.stringify(oai.payload).includes('ABCDE1234F'));
  });

  it('literal placeholder-shaped text in one message cannot collide with a real token', () => {
    const s = vela.createSession();
    const a = s.mask('Literal tag [EMAIL_1] here');
    const b = s.mask('Mail bob@example.com');
    assert.equal(a, 'Literal tag [EMAIL_1] here');
    assert.ok(!b.includes('[EMAIL_1]'), b);
    assert.equal(s.unmask(b).text, 'Mail bob@example.com');
  });

  it('detects voter ID (context-gated) and driving licence', () => {
    assert.ok(detectPii('Voter ID: ABC1234567').some((e) => e.type === 'VOTER_ID'));
    assert.ok(!detectPii('Code ABC1234567 shipped').some((e) => e.type === 'VOTER_ID'));
    assert.ok(detectPii('DL KL07 20110012345 issued').some((e) => e.type === 'DRIVING_LICENCE'));
    assert.ok(detectPii('licence MH-12-2011-0012345').some((e) => e.type === 'DRIVING_LICENCE'));
    const r = vela.mask('Voter ID: ABC1234567');
    assert.ok(!r.text.includes('ABC1234567'));
  });

  it('proxy forwards non-chat routes and masks embeddings input; --no-passthrough 404s', async () => {
    const seen: Array<{ method: string; url: string; body: string }> = [];
    const up = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      seen.push({ method: req.method ?? '', url: req.url ?? '', body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ data: [] }));
    });
    const upPort = await listen(up);
    const proxy = runProxy(vela, { port: 0, upstream: `http://127.0.0.1:${upPort}` });
    const strict = runProxy(vela, { port: 0, upstream: `http://127.0.0.1:${upPort}`, passthrough: false });
    await Promise.all([proxy, strict].map((p) => new Promise((r) => p.once('listening', r))));
    const base = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    const strictBase = `http://127.0.0.1:${(strict.address() as AddressInfo).port}`;
    try {
      const m = await fetch(`${base}/v1/models?limit=2`);
      assert.equal(m.status, 200);
      assert.equal(seen[0]?.method, 'GET');
      assert.equal(seen[0]?.url, '/v1/models?limit=2');

      const e = await fetch(`${base}/v1/embeddings`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'm', input: ['PAN ABCDE1234F', 'plain'] }),
      });
      assert.equal(e.status, 200);
      assert.ok(!seen[1]?.body.includes('ABCDE1234F'), seen[1]?.body);
      assert.ok(seen[1]?.body.includes('plain'));

      assert.equal((await fetch(`${strictBase}/v1/models`)).status, 404);
    } finally {
      proxy.close();
      strict.close();
      up.close();
    }
  });
});

describe('0.3.2 gap fixes', () => {
  const types = (t: string) => detectPii(t).map((e) => `${e.type}:${e.value}`);
  const persons = (t: string) => detectPii(t).filter((e) => e.type === 'PERSON').map((e) => e.value);

  it('custom entity types are always masked (never passed through)', () => {
    const v = new Vela({
      fpeKey: KEY,
      customDetectors: [{ name: 'emp', type: 'EMP_ID', regex: /EMP-\d{5}/g }],
      recognizers: [(t) => (t.includes('REF-9') ? [{ type: 'ACCOUNT_REF', start: t.indexOf('REF-9'), end: t.indexOf('REF-9') + 5 }] : [])],
    });
    const s = v.createSession();
    const masked = s.mask('Employee EMP-12345 with REF-9 pending');
    assert.equal(masked, 'Employee [EMP_ID_1] with [ACCOUNT_REF_1] pending');
    assert.equal(s.unmask(masked).text, 'Employee EMP-12345 with REF-9 pending');
    // Built-in types keep their opt-out semantics.
    const off = new Vela({ fpeKey: KEY, tokenTypes: [] });
    assert.equal(off.mask('mail bob@example.com').text, 'mail bob@example.com');
  });

  it('detects all-lowercase names without masking ordinary prose', () => {
    assert.deepEqual(persons('rahul sharma called. arjun told deepa to pay.'), ['rahul sharma', 'arjun', 'deepa']);
    assert.deepEqual(persons('the harsh winter was long; christian values; a brown bag'), []);
    assert.deepEqual(persons('const john = 1; emma.ts'), []);
    assert.deepEqual(persons('rahul said hello'), ['rahul']);
    assert.deepEqual(persons('amit paid'), ['amit']);
    assert.deepEqual(persons('ram paid'), []);
    assert.deepEqual(persons('my name is ram'), ['ram']);
    assert.deepEqual(persons('Rahul Sharma signed. later sharma paid.'), ['Rahul Sharma', 'sharma']);
    assert.deepEqual(persons('Christian Brown left. christian values in a brown bag.'), ['Christian Brown']);
    assert.deepEqual(persons('Deepak called. Kiran left.'), ['Deepak', 'Kiran']);
  });

  it('links partial mentions of a person to the full name placeholder', () => {
    const rt = (s: string) => {
      const r = vela.mask(s);
      return [r.text, vela.unmask(r.text, r).text];
    };
    assert.deepEqual(rt('Joseph Mathew signed. Joseph paid.'), ['[PERSON_1] signed. [PERSON_1] paid.', 'Joseph Mathew signed. Joseph Mathew paid.']);
    assert.deepEqual(rt('Joseph paid. Joseph Mathew signed.'), ['[PERSON_1] paid. [PERSON_1] signed.', 'Joseph Mathew paid. Joseph Mathew signed.']);
    assert.equal(rt('Rahul Sharma and Rahul Verma met. Rahul left.')[0], '[PERSON_1] and [PERSON_2] met. [PERSON_3] left.');
    assert.equal(rt('Mr. Sharma, Rahul Sharma')[0], 'Mr. [PERSON_1], [PERSON_1]');
    assert.equal(rt('SHARMA and Sharma and sharma: Rahul Sharma')[0], '[PERSON_1] and [PERSON_1] and [PERSON_1]: [PERSON_1]');
    assert.equal(vela.createSession({ linkPartialNames: false }).mask('Joseph Mathew signed. Joseph paid.'), '[PERSON_1] signed. [PERSON_2] paid.');

    // Full name in a later message links the earlier short mention via the learn() pass.
    const { payload, session } = maskOpenAiRequest(vela, {
      model: 'm',
      messages: [
        { role: 'user', content: 'Joseph paid' },
        { role: 'user', content: 'Joseph Mathew signed' },
      ],
    });
    const texts = payload.messages.map((m) => m.content as string);
    assert.deepEqual(texts, ['[PERSON_1] paid', '[PERSON_1] signed']);
    assert.equal(session.unmask(texts[0] as string).text, 'Joseph Mathew paid');
  });

  it('detects emails with combining marks (Devanagari)', () => {
    const got = types('राहुल@उदाहरण.भारत 用户@例子.广告 josé@exämple.com');
    assert.deepEqual(got, ['EMAIL:राहुल@उदाहरण.भारत', 'EMAIL:用户@例子.广告', 'EMAIL:josé@exämple.com']);
  });

  it('does not treat version strings as IP addresses', () => {
    for (const t of ['version 1.2.3.4', 'v1.2.3.4', 'upgraded to 2.0.1.3', 'release: 3.1.4.1']) assert.deepEqual(types(t), [], t);
    for (const t of ['host 10.0.0.1', 'ip: 8.8.8.8', 'server at 192.168.1.1']) assert.equal(types(t).length, 1, t);
  });

  it('leaves party names in reported court citations alone', () => {
    assert.deepEqual(types('State of Kerala v. Rahul Sharma (2019) 3 SCC 123'), []);
    assert.deepEqual(persons('Rahul Sharma v. Priya Menon'), ['Rahul Sharma', 'Priya Menon']);
    assert.deepEqual(types('In Rahul Sharma v. Union of India (supra)'), []);
    assert.deepEqual(persons('Client Rahul Sharma; see Rahul Sharma v. State AIR 2020 Ker 55. Sharma paid.'), ['Rahul Sharma', 'Sharma']);
    assert.deepEqual(types('Rahul Sharma v. Anr, 2021 SCC OnLine Ker 99; call 9876543210'), ['PHONE:9876543210']);
    const r = new Vela({ fpeKey: KEY, maskCitationParties: true }).mask('State of Kerala v. Rahul Sharma (2019) 3 SCC 123');
    assert.equal(r.text, 'State of Kerala v. [PERSON_1] (2019) 3 SCC 123');
  });

  it('detects key=value credentials, AWS secret keys and MAC addresses', () => {
    assert.deepEqual(types('password=hunter2'), ['SECRET_KEY:hunter2']);
    assert.deepEqual(types('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), ['SECRET_KEY:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY']);
    assert.deepEqual(types('00:1A:2B:3C:4D:5E and 001a.2b3c.4d5e'), ['MAC_ADDRESS:00:1A:2B:3C:4D:5E', 'MAC_ADDRESS:001a.2b3c.4d5e']);
    assert.deepEqual(types('the token expired'), []);
    assert.equal(vela.createSession().maskJsonString('{"password":"hunter2","user":"bob"}'), '{"password":"[SECRET_KEY_1]","user":"bob"}');
    const r = vela.mask('MAC 00:1A:2B:3C:4D:5E');
    assert.equal(r.text, 'MAC [MAC_ADDRESS_1]');
    assert.equal(vela.unmask(r.text, r).text, 'MAC 00:1A:2B:3C:4D:5E');
  });
});

describe('0.3.3 fixes', () => {
  it('a literal placeholder in a later JSON field cannot collide with a token issued earlier', () => {
    const s = vela.createSession();
    const value = [{ name: 'a@x.com, b@y.com, c@z.com' }, { note: 'literal [EMAIL_3] here' }];
    const masked = s.maskValue(value);
    assert.equal((masked[1] as { note: string }).note, 'literal [EMAIL_3] here');
    assert.ok(!JSON.stringify(masked[0]).includes('[EMAIL_3]'), JSON.stringify(masked));
    assert.deepEqual(s.unmaskValue(masked), value);
  });

  it('detects lowercase names before sentence punctuation but not in code or paths', () => {
    const names = (t: string) => detectPii(t).filter((e) => e.type === 'PERSON').map((e) => e.value);
    assert.deepEqual(names('I met deepa. later arjun came'), ['deepa', 'arjun']);
    assert.deepEqual(names("const john = 1; import emma from './emma.ts';"), []);
    assert.deepEqual(names('see ./rahul.txt and rahul_sharma.log'), []);
  });

  it('keeps abbreviations like "No." inside labelled addresses', () => {
    const got = detectPii('r/o House No. 14, Sector 21, Gurugram 122001').map((e) => `${e.type}:${e.value}`);
    assert.deepEqual(got, ['ADDRESS:House No. 14, Sector 21, Gurugram 122001']);
  });

  it('rejects oversized input with a typed error; the proxy answers 413 without forwarding', async () => {
    const small = new Vela({ fpeKey: KEY, maxInputChars: 100 });
    assert.throws(() => small.mask('x'.repeat(101)), (e: unknown) => e instanceof VelaInputTooLargeError && e.status === 413);
    let upstreamHits = 0;
    const up = createServer((_req, res) => {
      upstreamHits++;
      res.end('{}');
    });
    const upPort = await listen(up);
    const proxy = runProxy(small, { port: 0, upstream: `http://127.0.0.1:${upPort}` });
    await new Promise((r) => proxy.once('listening', r));
    try {
      const r = await fetch(`http://127.0.0.1:${(proxy.address() as AddressInfo).port}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'y'.repeat(500) }] }),
      });
      assert.equal(r.status, 413);
      assert.equal(upstreamHits, 0);
    } finally {
      proxy.close();
      up.close();
    }
  });
});
