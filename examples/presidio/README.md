# NER-based detection with Microsoft Presidio

Vela's built-in name and address detection is heuristic. It misses names written in Indian scripts, rare names and free-form addresses. For production, run a Named Entity Recognition (NER) service next to Vela and plug it in as an async recognizer. This folder sets up [Microsoft Presidio](https://microsoft.github.io/presidio/) Analyzer for that.

## 1. Start Presidio

```bash
docker compose -f examples/presidio/docker-compose.yml up -d
```

The analyzer listens on `http://localhost:5002`, bound to loopback only. It receives raw, unmasked text, so keep it on the same host or private network as Vela and never expose it publicly.

## 2. Use it

**Proxy:**

```bash
npx vela-privacy proxy --presidio-url http://localhost:5002
```

**Library:**

```ts
import { Vela, presidioRecognizer } from 'vela-privacy';

const vela = new Vela({
  asyncRecognizers: [presidioRecognizer({ url: 'http://localhost:5002' })],
  // recognizerFailure: 'block' is the default: if Presidio is down, requests are
  // rejected (HTTP 503 in the proxy) instead of going out with weaker masking.
});

const r = await vela.maskAsync('Thiruvenkatam called from Chennai');
```

The proxy, fetch interceptor, Express middleware and the OpenAI / Anthropic client wrappers run the recognizer automatically. If you call the request helpers yourself, use the `*Async` versions (`maskOpenAiRequestAsync`, `maskAnthropicRequestAsync`, `maskOpenAiResponsesRequestAsync`). Synchronous `vela.mask()` throws `VelaNotPreparedError` while async recognizers are configured, so text can't skip NER by accident.

## Options

| Option | Default | Notes |
|---|---|---|
| `url` | required | Analyzer base URL |
| `language` | `en` | Must be a language your Presidio deployment has a model for |
| `entities` | `PERSON`, `LOCATION`, `ORGANIZATION`, `NRP` | Presidio entity types to request |
| `scoreThreshold` | `0.5` | Lower finds more, with more false positives |
| `typeMap` | `PERSON→PERSON`, `LOCATION→LOCATION`, `ORGANIZATION→ORG` | Unmapped types are masked as `[<TYPE>_n]` |
| `concurrency` | `8` | Parallel `/analyze` calls per request |
| `headers` | none | For an analyzer behind authentication |

`VelaConfig` controls failure behaviour:

| Option | Default | Notes |
|---|---|---|
| `recognizerFailure` | `block` | `continue` falls back to built-in detection and logs a warning |
| `recognizerTimeoutMs` | `5000` | Per request |

## Notes

- Vela converts Presidio's offsets (Unicode code points) to JavaScript string offsets, so emoji or other astral characters before a name don't shift the masked span.
- Presidio's default image ships English models. For Hindi, Tamil or other languages, build an analyzer image with the matching spaCy or transformers model and pass `language`.
- Structured identifiers (Aadhaar, PAN, cards…) are still found by Vela's own validated detectors. There's no need to request Presidio's equivalents.
