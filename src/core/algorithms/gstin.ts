const CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/** Compute the GSTIN check character (mod-36 weighted checksum) for the first 14 chars. */
export function gstinCheckChar(first14: string): string {
  let sum = 0;
  for (let i = 0; i < 14; i++) {
    const v = CHARSET.indexOf(first14[i] ?? '');
    if (v < 0) return '0';
    const prod = v * (i % 2 === 0 ? 1 : 2);
    sum += Math.floor(prod / 36) + (prod % 36);
  }
  return CHARSET[(36 - (sum % 36)) % 36] as string;
}

/** Validate a 15-character GSTIN: state code + structure + check character. */
export function validateGstin(gstin: string, checkDigit = true): boolean {
  const g = gstin.toUpperCase();
  if (!/^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(g)) return false;
  const state = Number(g.slice(0, 2));
  if (!((state >= 1 && state <= 38) || state === 97 || state === 99)) return false;
  return !checkDigit || gstinCheckChar(g.slice(0, 14)) === g[14];
}
