#!/usr/bin/env node
// Packed-install smoke test: builds, packs and installs the tarball into a clean
// temp project, then exercises require(), import and the CLI with the *current*
// Node binary. This is the check that would have caught the 0.3.1 require() crash.
import { execSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve('.');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const work = mkdtempSync(join(tmpdir(), 'vela-smoke-'));
const sh = (cmd, cwd = root) => execSync(cmd, { cwd, stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8' });

let failed = false;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? `  (${detail})` : ''}`);
  if (!ok) failed = true;
};

try {
  console.log(`node ${process.version} | ${pkg.name}@${pkg.version} | ${work}`);
  if (!process.argv.includes('--no-build')) sh('npm run build');
  sh(`npm pack --silent --pack-destination "${work}"`);
  const tgz = readdirSync(work).find((f) => f.endsWith('.tgz'));
  if (!tgz) throw new Error('npm pack produced no tarball');

  const app = join(work, 'app');
  sh(`node -e "require('fs').mkdirSync('app')"`, work);
  writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'smoke', private: true }));
  sh(`npm install --silent --no-audit --no-fund "${join(work, tgz)}"`, app);

  const body = (mod) => `
const { Vela, QuantumKeyManager: Q } = ${mod};
const v = new Vela({ fpeKey: new Uint8Array(32).fill(7), customDetectors: [{ name: 'emp', type: 'EMP_ID', regex: /EMP-\\d{5}/g }] });
const r = v.mask('Rahul Sharma, PAN ABCDE1234F, id EMP-12345');
const kp = Q.generateKeyPair(), enc = Q.encapsulate(kp.publicKey);
const kem = Buffer.from(Q.decapsulate(enc.cipherText, kp.secretKey)).equals(Buffer.from(enc.sharedSecret));
const back = v.unmask(r.text, r).text;
console.log(JSON.stringify({ text: r.text, back, kem }));`;
  writeFileSync(join(app, 't.cjs'), body("require('vela-privacy')"));
  writeFileSync(join(app, 't.mjs'), `import * as m from 'vela-privacy';\n${body('m')}`);

  for (const f of ['t.cjs', 't.mjs']) {
    const r = spawnSync(process.execPath, [f], { cwd: app, encoding: 'utf8' });
    if (r.status !== 0) {
      check(`${f} loads`, false, (r.stderr || '').split('\n').find((l) => /Error/.test(l)) ?? `exit ${r.status}`);
      continue;
    }
    const out = JSON.parse(r.stdout.trim().split('\n').pop());
    const m = /^\[PERSON_1\], PAN ([A-Z]{5}\d{4}[A-Z]), id \[EMP_ID_1\]$/.exec(out.text);
    check(`${f} masks`, !!m && m[1] !== 'ABCDE1234F', out.text);
    check(`${f} restores`, out.back === 'Rahul Sharma, PAN ABCDE1234F, id EMP-12345');
    check(`${f} ML-KEM round-trip`, out.kem === true);
  }

  const cli = join(app, 'node_modules', 'vela-privacy', 'dist', 'bin', 'vela-cli.js');
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd: app, encoding: 'utf8' });
  const ver = run('--version');
  check('cli --version', ver.status === 0 && ver.stdout.trim() === pkg.version, ver.stdout.trim() || ver.stderr.trim());
  const mk = run('mask', 'email test@domain.com');
  check('cli mask', mk.status === 0 && mk.stdout.includes('email [EMAIL_1]'), mk.status === 0 ? '' : mk.stderr.trim());
  const kg = run('keygen', '--kem');
  check('cli keygen --kem', kg.status === 0 && kg.stdout.includes('"publicKey"'));
} catch (e) {
  check('smoke run', false, e instanceof Error ? e.message : String(e));
} finally {
  try {
    rmSync(work, { recursive: true, force: true });
  } catch {
    /* temp dir cleanup is best-effort */
  }
}

process.exit(failed ? 1 : 0);
