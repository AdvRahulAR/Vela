import { Vela } from '../src/core/vela.js';
import { QuantumKeyManager } from '../src/core/quantum.js';
import { generateVerhoeffChecksum } from '../src/core/algorithms/verhoeff.js';

const kp = QuantumKeyManager.generateKeyPair();
const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);

const vela = new Vela({
  fpeKey,
  glossary: ['ConfidentialProject'],
});

const base = '23456789012';
const chk = generateVerhoeffChecksum(base);
const validAadhaar = `${base.slice(0, 4)} ${base.slice(4, 8)} ${base.slice(8, 11)}${chk}`;

const sampleText = `Employee Alice Smith (PAN: ABCDE1234F, Aadhaar: ${validAadhaar}, Card: 4532-0151-1283-0366, Phone: +91 9876543210, Email: alice.smith@enterprise.org) is assigned to ConfidentialProject under CASE NO. 1234 OF 2023.`;

const ITERATIONS = 1000;

console.log(`\n=== Vela Privacy Benchmark (${ITERATIONS} iterations) ===\n`);

// 1. Benchmark Mask
const startMask = performance.now();
let lastMaskResult = vela.mask(sampleText);
for (let i = 0; i < ITERATIONS; i++) {
  lastMaskResult = vela.mask(sampleText);
}
const elapsedMask = performance.now() - startMask;
const avgMaskMs = elapsedMask / ITERATIONS;
const maskThroughput = Math.round((ITERATIONS / elapsedMask) * 1000);

console.log(`Masking:`);
console.log(`  Total time:       ${elapsedMask.toFixed(2)} ms`);
console.log(`  Average latency:  ${avgMaskMs.toFixed(3)} ms / op`);
console.log(`  Throughput:       ${maskThroughput.toLocaleString()} ops / sec`);

// 2. Benchmark Unmask
const maskedText = lastMaskResult.text;
const startUnmask = performance.now();
for (let i = 0; i < ITERATIONS; i++) {
  vela.unmask(maskedText, lastMaskResult);
}
const elapsedUnmask = performance.now() - startUnmask;
const avgUnmaskMs = elapsedUnmask / ITERATIONS;
const unmaskThroughput = Math.round((ITERATIONS / elapsedUnmask) * 1000);

console.log(`\nUnmasking:`);
console.log(`  Total time:       ${elapsedUnmask.toFixed(2)} ms`);
console.log(`  Average latency:  ${avgUnmaskMs.toFixed(3)} ms / op`);
console.log(`  Throughput:       ${unmaskThroughput.toLocaleString()} ops / sec`);

// 3. Post-Quantum KEM Keygen & Encapsulation Benchmark
const KEM_ITERS = 100;
const startKem = performance.now();
for (let i = 0; i < KEM_ITERS; i++) {
  const k = QuantumKeyManager.generateKeyPair();
  QuantumKeyManager.encapsulate(k.publicKey);
}
const elapsedKem = performance.now() - startKem;
console.log(`\nML-KEM-768 Key Agreement (Keygen + Encapsulate):`);
console.log(`  Average latency:  ${(elapsedKem / KEM_ITERS).toFixed(3)} ms / handshake`);
console.log(`\n=======================================================\n`);
