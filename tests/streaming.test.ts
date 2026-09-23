import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { TokenStreamDeMasker, createSseDeMasker } from '../src/core/streaming.js';
import type { MaskResult } from '../src/types.js';

describe('Streaming De-masker', () => {
  const mockResult: MaskResult = {
    text: '',
    mapping: {
      '<PII type="EMAIL" id="0"/>': 'alice@company.com',
    },
    fpeMap: {
      'ABCDE1234F': 'ZXCVB9876Y',
    },
    entities: [],
  };

  it('should unmask tokens when split across chunks', () => {
    const deMasker = new TokenStreamDeMasker(mockResult);

    // Split token "<PII type=\"EMAIL\" id=\"0\"/>" across 3 chunks
    const chunk1 = 'Contact information: <PII typ';
    const chunk2 = 'e="EMAIL" id';
    const chunk3 = '="0"/> for follow-up.';

    const out1 = deMasker.feed(chunk1);
    const out2 = deMasker.feed(chunk2);
    const out3 = deMasker.feed(chunk3);
    const outFlush = deMasker.flush();

    const fullOutput = out1 + out2 + out3 + outFlush;
    assert.equal(fullOutput, 'Contact information: alice@company.com for follow-up.');
  });

  it('should unmask FPE ciphertexts split across chunks', () => {
    const deMasker = new TokenStreamDeMasker(mockResult);

    // Target is ZXCVB9876Y -> ABCDE1234F
    const c1 = 'Tax ID: ZXCV';
    const c2 = 'B987';
    const c3 = '6Y confirmed.';

    const out1 = deMasker.feed(c1);
    const out2 = deMasker.feed(c2);
    const out3 = deMasker.feed(c3);
    const outFlush = deMasker.flush();

    const fullOutput = out1 + out2 + out3 + outFlush;
    assert.equal(fullOutput, 'Tax ID: ABCDE1234F confirmed.');
  });

  it('should process SSE formatted event streams', () => {
    const sseDeMasker = createSseDeMasker(mockResult);

    const sseEvent1 = `data: {"choices":[{"delta":{"content":"User email is <PII ty"}}]}\n\n`;
    const sseEvent2 = `data: {"choices":[{"delta":{"content":"pe=\\"EMAIL\\" id=\\"0\\"/> and tax "}}]}\n\n`;
    const sseDone = `data: [DONE]\n\n`;

    const res1 = sseDeMasker(sseEvent1);
    const res2 = sseDeMasker(sseEvent2);
    const resDone = sseDeMasker(sseDone);

    const fullSse = res1 + res2 + resDone;
    assert.match(fullSse, /alice@company\.com/);
  });
});
