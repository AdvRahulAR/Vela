# Security policy

## Supported versions

Security fixes go into the latest minor release line. While the package is 0.x, upgrade to the newest version to receive fixes.

| Version | Supported |
|---|---|
| 0.5.x | Yes |
| < 0.5 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through **GitHub private vulnerability reporting** on [AdvRahulAR/Vela](https://github.com/AdvRahulAR/Vela/security/advisories/new). Do not open a public issue.

Useful things to include:

- the version, and whether you use the library, the proxy or the CLI
- a minimal input that reproduces the problem, using synthetic data only (never real personal data)
- what you expected and what happened, such as a value reaching the upstream request in clear text

## What counts as a vulnerability

- A **detected** value reaching the upstream LLM request in clear text.
- Restoration writing an original value somewhere it was not masked from, or mixing up two values.
- A crash, hang or memory blow-up triggered by request content (denial of service through the proxy).
- Weaknesses in the FF1 implementation, tweak derivation, or key sealing.
- The proxy leaking headers, API keys or values into logs or responses.

A value the detectors **don't recognise** (for example, an unusual name with no NER service configured) is a detection gap, not a vulnerability. Please report it as a normal issue, ideally with a corpus case (see [CONTRIBUTING.md](CONTRIBUTING.md)). [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists what Vela does and doesn't guarantee.

## Our commitments

- Acknowledge your report within **3 business days**.
- Give an initial assessment within **10 business days**.
- Release a fix for high-severity issues within **30 days** where possible, and publish a GitHub security advisory.
- Credit you in the advisory and the changelog, unless you prefer to stay anonymous.

## Independent review

Vela has **not yet been independently security-reviewed**. The reviewer packet is [docs/REVIEW_GUIDE.md](docs/REVIEW_GUIDE.md). This file will link the review summary once it is complete.
