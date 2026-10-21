import { randomBytes } from 'node:crypto';
import { Vela } from '../src/core/vela.js';
import type { VelaConfig } from '../src/types.js';
import { QuantumKeyManager } from '../src/core/quantum.js';
import { runProxy } from '../src/integrations/proxy.js';
import { presidioRecognizer } from '../src/integrations/presidio.js';
import { PACKAGE_VERSION } from '../src/config/constants.js';
import { readFileSync } from 'node:fs';
import { consoleSink, jsonlFileSink, verifyAuditChain, type AuditSink } from '../src/core/audit.js';
import { policyHash } from '../src/core/policy.js';
import { POLICY_PRESETS, resolvePolicy } from '../src/policies/presets.js';
import { DETECTOR_PACKS } from '../src/packs/index.js';

const SHORT: Record<string, string> = { p: 'port', u: 'upstream', k: 'key', g: 'glossary', H: 'host', a: 'api-key', h: 'help', v: 'version' };
const BOOLEAN = new Set(['help', 'version', 'kem', 'json', 'no-passthrough', 'presidio-optional', 'insecure', 'audit-stdout']);

export function parseArgs(args: string[]): { flags: Record<string, string | boolean>; positionals: string[] } {
  const flags: Record<string, string | boolean> = {};
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--') {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (arg.startsWith('-') && arg.length > 1 && !/^-\d/.test(arg)) {
      let key = arg.replace(/^--?/, '');
      let value: string | undefined;
      const eq = key.indexOf('=');
      if (eq >= 0) {
        value = key.slice(eq + 1);
        key = key.slice(0, eq);
      }
      if (!arg.startsWith('--')) key = SHORT[key] ?? key;
      if (value === undefined && !BOOLEAN.has(key)) {
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          value = next;
          i++;
        }
      }
      flags[key] = value ?? true;
    } else {
      positionals.push(arg);
    }
  }
  return { flags, positionals };
}

function printHelp(): void {
  console.log(`
Vela — LLM Privacy Gateway CLI (v${PACKAGE_VERSION})

USAGE:
  vela <command> [options]

COMMANDS:
  proxy               Start the local privacy proxy (OpenAI Chat/Responses + Anthropic Messages)
  mask <text>         Mask PII in the given text and show detected entities
  keygen              Generate a random 32-byte FPE key (add --kem for an ML-KEM-768 keypair)
  policy <name|file>  Validate a policy (preset or .json/.yaml file) and print it with its hash
  policies            List policy presets
  packs               List detector packs and their entity types
  audit verify <file> Check a hash-chained audit log (exit code 1 if it was altered). Add
                      --head <hash> (the last hash you recorded elsewhere) to also detect truncation
  help                Show this help

PROXY OPTIONS:
  --port, -p <num>      Port (default: 8787)
  --host, -H <addr>     Interface to bind (default: 127.0.0.1 — loopback only)
  --upstream, -u <url>  Upstream base URL (default: OpenAI; Anthropic paths auto-route to api.anthropic.com)
  --api-key, -a <key>   Upstream API key to inject (or env VELA_UPSTREAM_API_KEY; otherwise the client's own key is
                        forwarded). With --upstream it goes there; without, only to OpenAI
  --anthropic-api-key <k>, --gemini-api-key <k>
                        Keys for auto-routed Anthropic / Gemini requests (or VELA_ANTHROPIC_API_KEY,
                        VELA_GEMINI_API_KEY). A provider without a key gets none
  --passthrough <mode>  Routes Vela can't mask. safe (default): body-free requests (GET /v1/models…) are
                        forwarded, anything else (batches, files, unknown endpoints) gets 403.
                        none: 404 for everything except maskable routes. all: forward unknown routes
                        UNMASKED (opt-in only). Chat, Responses, Messages, count_tokens, embeddings,
                        moderations and legacy completions are always masked.
  --no-passthrough      Same as --passthrough none
  --key, -k <hex>       32-byte FPE key as 64 hex chars (or env VELA_FPE_KEY; default: random per process)
  --glossary, -g <s>    Comma-separated confidential terms to always mask
  --presidio-url <url>  Presidio Analyzer URL for NER-based name/location detection. If it is down,
                        requests are rejected with 503 (add --presidio-optional to fall back instead)

  --policy <name|file>  Masking policy: a preset (dpdp-baseline, india-bfsi, pci, hipaa-safe-harbor,
                        gdpr-pseudonymise) or a .json/.yaml file
  --packs <list>        Detector packs, comma-separated (pci, india-bfsi, health-in, us, eu-uk, intl)
  --audit-log <file>    Append hash-chained, value-free audit events (JSON lines) to this file
  --audit-stdout        Write audit events to stdout
  --auth-token-file <f> Client tokens, one "<tenant> <token>" per line; clients send x-vela-key: <token>.
                        Required with a non-loopback --host (or pass --insecure)
  --insecure            Allow a non-loopback --host without tokens (only behind an authenticating proxy)
  --rate-limit <n>      Requests per minute per tenant / client IP (429 beyond it)
  --tls-cert <file>     Serve HTTPS with this certificate (PEM), together with --tls-key <file>

  Send header "x-vela-session: <conversation-id>" to keep masking stable across turns.

MASK OPTIONS:
  --glossary, -g <s>    Comma-separated confidential terms
  --presidio-url <url>  Presidio Analyzer URL for NER-based detection
  --policy <name|file>  Masking policy (as for proxy)
  --packs <list>        Detector packs (as for proxy)
  --json                Print machine-readable JSON

EXAMPLES:
  $ npx vela-privacy proxy --port 8787
  $ npx vela-privacy mask "My email is alice@company.com and Aadhaar 2345 6789 0124"
  $ npx vela-privacy keygen
`);
}

function readKey(flags: Record<string, string | boolean>): Uint8Array | undefined {
  const k = flags['key'] ?? process.env['VELA_FPE_KEY'];
  if (typeof k !== 'string') return undefined;
  const key = new Uint8Array(Buffer.from(k, 'hex'));
  if (key.length !== 32 || !/^[0-9a-fA-F]{64}$/.test(k)) {
    console.error('Error: key must be exactly 32 bytes (64 hex characters).');
    process.exit(1);
  }
  return key;
}

function nerConfig(flags: Record<string, string | boolean>): Pick<VelaConfig, 'asyncRecognizers' | 'recognizerFailure'> {
  const url = flags['presidio-url'] ?? process.env['VELA_PRESIDIO_URL'];
  if (typeof url !== 'string' || !url) return {};
  return {
    asyncRecognizers: [presidioRecognizer({ url })],
    recognizerFailure: flags['presidio-optional'] === true ? 'continue' : 'block',
  };
}

const glossaryOf = (flags: Record<string, string | boolean>): string[] | undefined =>
  typeof flags['glossary'] === 'string' ? flags['glossary'].split(',').map((s) => s.trim()).filter(Boolean) : undefined;

function passthroughOf(flags: Record<string, string | boolean>): { passthrough?: 'safe' | 'all' | 'none' } {
  if (flags['no-passthrough'] === true) return { passthrough: 'none' };
  const p = flags['passthrough'];
  if (p === undefined) return {};
  if (p === 'safe' || p === 'all' || p === 'none') return { passthrough: p };
  console.error('Error: --passthrough must be safe, none or all');
  process.exit(1);
}

function fail(msg: string): never {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

/** Policy, packs and audit settings shared by `mask` and `proxy`. */
function complianceConfig(flags: Record<string, string | boolean>): Pick<VelaConfig, 'policy' | 'packs' | 'audit'> {
  const out: Pick<VelaConfig, 'policy' | 'packs' | 'audit'> = {};
  try {
    if (typeof flags['policy'] === 'string') out.policy = resolvePolicy(flags['policy']);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  if (typeof flags['packs'] === 'string') out.packs = flags['packs'].split(',').map((s) => s.trim()).filter(Boolean);
  const sinks: AuditSink[] = [];
  if (typeof flags['audit-log'] === 'string') sinks.push(jsonlFileSink(flags['audit-log']));
  if (flags['audit-stdout'] === true) sinks.push(consoleSink());
  if (sinks.length) out.audit = async (e) => {
    for (const s of sinks) await s(e);
  };
  return out;
}

/** Per-provider upstream keys for auto-routing (no --upstream): flags or VELA_<PROVIDER>_API_KEY. */
function providerKeys(flags: Record<string, string | boolean>): { apiKeys?: Partial<Record<'openai' | 'anthropic' | 'gemini', string>> } {
  const keys: Partial<Record<'openai' | 'anthropic' | 'gemini', string>> = {};
  for (const p of ['anthropic', 'gemini'] as const) {
    const v = flags[`${p}-api-key`] ?? process.env[`VELA_${p.toUpperCase()}_API_KEY`];
    if (typeof v === 'string' && v) keys[p] = v;
  }
  return Object.keys(keys).length ? { apiKeys: keys } : {};
}

function authTokensOf(flags: Record<string, string | boolean>): Record<string, string> | undefined {
  const file = flags['auth-token-file'];
  if (typeof file !== 'string') return undefined;
  const tokens: Record<string, string> = {};
  for (const [i, line] of readFileSync(file, 'utf8').split('\n').entries()) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const [tenant, token, extra] = t.split(/\s+/);
    if (!tenant || !token || extra !== undefined || token.length < 16) fail(`${file}:${i + 1}: expected "<tenant> <token>" with a token of 16+ characters`);
    tokens[token] = tenant;
  }
  if (!Object.keys(tokens).length) fail(`${file} has no tokens`);
  return tokens;
}

async function main(): Promise<void> {
  const { flags, positionals } = parseArgs(process.argv.slice(2));
  const command = positionals[0] ?? 'help';

  if (flags['version']) {
    console.log(PACKAGE_VERSION);
    return;
  }
  if (command === 'help' || flags['help']) {
    printHelp();
    return;
  }

  if (command === 'keygen') {
    if (flags['kem']) {
      const kp = QuantumKeyManager.generateKeyPair();
      console.log(JSON.stringify({
        algorithm: 'ML-KEM-768 (FIPS 203)',
        publicKey: Buffer.from(kp.publicKey).toString('hex'),
        secretKey: Buffer.from(kp.secretKey).toString('hex'),
      }, null, 2));
      console.error('Keep secretKey private. Peers encapsulate to publicKey; derive the FPE key with QuantumKeyManager.deriveFpeKey().');
      return;
    }
    console.log(randomBytes(32).toString('hex'));
    console.error('Use with --key <hex> or VELA_FPE_KEY=<hex>. Store it like any other secret.');
    return;
  }

  if (command === 'policies') {
    for (const [name, p] of Object.entries(POLICY_PRESETS)) console.log(`${name.padEnd(20)} ${p.description ?? ''}`);
    return;
  }

  if (command === 'policy') {
    const target = positionals[1];
    if (!target) fail('usage: vela policy <preset|file>');
    let policy;
    try {
      policy = resolvePolicy(target);
    } catch (err) {
      fail(err instanceof Error ? err.message : String(err));
    }
    console.log(JSON.stringify({ ...policy, hash: policyHash(policy) }, null, 2));
    return;
  }

  if (command === 'packs') {
    for (const [name, patterns] of Object.entries(DETECTOR_PACKS)) {
      console.log(`${name.padEnd(12)} ${[...new Set(patterns.map((p) => String(p.type)))].join(', ')}`);
    }
    return;
  }

  if (command === 'audit') {
    const file = positionals[2];
    if (positionals[1] !== 'verify' || !file) fail('usage: vela audit verify <file>');
    const head = typeof flags['head'] === 'string' ? flags['head'] : undefined;
    const r = verifyAuditChain(readFileSync(file, 'utf8'), head ? { expectHead: head } : {});
    if (r.ok) {
      console.log(`OK: ${r.events} events, chain intact. Head: ${r.head}`);
      if (!head) console.log('Record the head hash outside this file; pass it as --head next time to detect truncation.');
      return;
    }
    console.error(`ALTERED: line ${r.line} does not verify (edited, inserted, reordered or deleted lines${head ? ', or truncated before the expected head' : ''})`);
    process.exit(1);
  }

  if (command === 'mask') {
    const text = positionals.slice(1).join(' ');
    if (!text) {
      console.error('Error: please provide text to mask.');
      process.exit(1);
    }
    const key = readKey(flags);
    const glossary = glossaryOf(flags);
    const vela = new Vela({ ...(key ? { fpeKey: key } : {}), ...(glossary ? { glossary } : {}), ...nerConfig(flags), ...complianceConfig(flags) });
    const masked = await vela.maskAsync(text);
    if (flags['json']) {
      console.log(JSON.stringify({ text: masked.text, replacements: masked.replacements }, null, 2));
      return;
    }
    console.log('\n--- Masked Output ---');
    console.log(masked.text);
    console.log('\n--- Replacements ---');
    for (const r of masked.replacements ?? []) console.log(`  ${r.type.padEnd(14)} ${r.method.padEnd(5)} ${r.original}  →  ${r.masked}`);
    console.log('');
    return;
  }

  if (command === 'proxy') {
    const port = typeof flags['port'] === 'string' ? parseInt(flags['port'], 10) : undefined;
    if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      console.error('Error: --port must be 1-65535');
      process.exit(1);
    }
    const key = readKey(flags);
    if (!key) console.log('[vela] No --key provided — using a random key for this process.');
    const glossary = glossaryOf(flags);
    const ner = nerConfig(flags);
    if (ner.asyncRecognizers) console.log(`[vela] NER via Presidio (${ner.recognizerFailure === 'block' ? 'requests blocked if it is unavailable' : 'falls back to built-in detection'})`);
    const compliance = complianceConfig(flags);
    if (compliance.policy) console.log(`[vela] Policy ${compliance.policy.id} (${policyHash(compliance.policy)})`);
    const vela = new Vela({ ...(key ? { fpeKey: key } : {}), ...(glossary ? { glossary } : {}), ...ner, ...compliance, enableLogging: true });
    const authTokens = authTokensOf(flags);
    const rate = typeof flags['rate-limit'] === 'string' ? Number(flags['rate-limit']) : undefined;
    if (rate !== undefined && !(Number.isInteger(rate) && rate > 0)) fail('--rate-limit must be a positive integer');
    const certFile = flags['tls-cert'];
    const keyFile = flags['tls-key'];
    if ((typeof certFile === 'string') !== (typeof keyFile === 'string')) fail('--tls-cert and --tls-key go together');
    runProxy(vela, {
      ...(authTokens ? { authTokens } : {}),
      ...(flags['insecure'] === true ? { insecure: true } : {}),
      ...(rate ? { rateLimitPerMinute: rate } : {}),
      ...(typeof certFile === 'string' && typeof keyFile === 'string' ? { tls: { cert: readFileSync(certFile), key: readFileSync(keyFile) } } : {}),
      ...(port !== undefined ? { port } : {}),
      ...(typeof flags['host'] === 'string' ? { host: flags['host'] } : {}),
      ...(typeof flags['upstream'] === 'string' ? { upstream: flags['upstream'] } : {}),
      ...(typeof (flags['api-key'] ?? process.env['VELA_UPSTREAM_API_KEY']) === 'string' ? { apiKey: (flags['api-key'] ?? process.env['VELA_UPSTREAM_API_KEY']) as string } : {}),
      ...providerKeys(flags),
      ...passthroughOf(flags),
    });
    return;
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

main().catch((err: unknown) => {
  console.error('Fatal CLI Error:', err instanceof Error ? err.message : err);
  process.exit(1);
});
