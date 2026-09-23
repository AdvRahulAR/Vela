import { Vela } from '../src/core/vela.js';
import { QuantumKeyManager } from '../src/core/quantum.js';
import { runProxy } from '../src/integrations/proxy.js';

function parseArgs(args: string[]): Record<string, string | boolean> {
  const result: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        result[key] = next;
        i++;
      } else {
        result[key] = true;
      }
    } else if (arg.startsWith('-')) {
      const key = arg.slice(1);
      const next = args[i + 1];
      if (next && !next.startsWith('-')) {
        result[key] = next;
        i++;
      } else {
        result[key] = true;
      }
    }
  }
  return result;
}

function printHelp(): void {
  console.log(`
Vela — Universal LLM Privacy Gateway CLI

USAGE:
  vela [command] [options]

COMMANDS:
  proxy               Start standalone privacy proxy
  keygen              Generate ML-KEM-768 post-quantum keypair & FPE key
  mask <text>         Mask PII in input text from CLI
  help, --help, -h    Show this help message

OPTIONS FOR 'proxy':
  --port, -p <num>    Proxy port (default: 8787)
  --upstream, -u <u>  Upstream URL (default: https://api.openai.com)
  --key, -k <hex>     Hex-encoded 32-byte FPE key (default: auto-generates ephemeral key)
  --glossary, -g <s>  Comma-separated list of confidential terms

EXAMPLES:
  $ npx vela-privacy proxy --port 8787
  $ npx vela-privacy keygen
  $ npx vela-privacy mask "My email is alice@company.com and Aadhaar 2345 6789 0123"
`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const flags = parseArgs(argv);
  const command = argv.find((a) => !a.startsWith('-')) ?? 'help';

  if (command === 'help' || flags['help'] || flags['h']) {
    printHelp();
    process.exit(0);
  }

  if (command === 'keygen') {
    const keyPair = QuantumKeyManager.generateKeyPair();
    const { sharedSecret } = QuantumKeyManager.encapsulate(keyPair.publicKey);
    const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);

    console.log('\n--- Vela Quantum Key Generation ---');
    console.log('Algorithm: ML-KEM-768 (NIST FIPS 203) + HKDF-SHA256');
    console.log(`FPE Key (32 bytes Hex): ${Buffer.from(fpeKey).toString('hex')}`);
    console.log(`Public Key (Hex):       ${Buffer.from(keyPair.publicKey).toString('hex').slice(0, 48)}... (truncated)`);
    console.log(`Secret Key (Hex):       ${Buffer.from(keyPair.secretKey).toString('hex').slice(0, 48)}... (truncated)`);
    console.log('\nUse this key by setting VELA_FPE_KEY=<hex> or passing --key <hex>\n');
    return;
  }

  if (command === 'mask') {
    const textToMask = argv.slice(1).filter((a) => !a.startsWith('-')).join(' ');
    if (!textToMask) {
      console.error('Error: Please provide text to mask.');
      process.exit(1);
    }

    const kp = QuantumKeyManager.generateKeyPair();
    const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
    const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);

    const vela = new Vela({ fpeKey });
    const masked = vela.mask(textToMask);

    console.log('\n--- Masked Output ---');
    console.log(masked.text);
    console.log('\n--- Detected Entities ---');
    console.dir(masked.entities, { depth: null });
    return;
  }

  if (command === 'proxy') {
    const port = typeof flags['port'] === 'string' ? parseInt(flags['port'], 10) : 8787;
    const upstream = typeof flags['upstream'] === 'string' ? flags['upstream'] : undefined;
    const glossary = typeof flags['glossary'] === 'string' ? flags['glossary'].split(',').map((s) => s.trim()) : undefined;

    let fpeKey: Uint8Array;
    const keyFlag = flags['key'] ?? flags['k'] ?? process.env.VELA_FPE_KEY;

    if (typeof keyFlag === 'string') {
      fpeKey = new Uint8Array(Buffer.from(keyFlag, 'hex'));
      if (fpeKey.length !== 32) {
        console.error('Error: Provided key must be exactly 32 bytes (64 hex characters).');
        process.exit(1);
      }
    } else {
      console.log('[vela] No key provided — generating ephemeral ML-KEM-768 session key');
      const kp = QuantumKeyManager.generateKeyPair();
      const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
      fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);
    }

    const vela = new Vela({
      fpeKey,
      glossary,
      enableLogging: true,
    });

    runProxy(vela, { port, upstream });
    return;
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

main().catch((err: unknown) => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
