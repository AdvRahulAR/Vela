/**
 * Verhoeff checksum algorithm (used by Indian Aadhaar UIDAI)
 * Validates 12-digit Aadhaar numbers, rejecting random 12-digit sequences.
 */

const D_TABLE: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const P_TABLE: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const INV_TABLE: readonly number[] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/**
 * Validate an Aadhaar number using the Verhoeff checksum.
 * UIDAI specification:
 * - 12 digits
 * - Does not start with 0 or 1
 * - Verhoeff check returns 0
 */
export function validateVerhoeff(str: string): boolean {
  const digits = str.replace(/\s+/g, '');
  if (!/^\d{12}$/.test(digits)) return false;
  if (digits[0] === '0' || digits[0] === '1') return false;

  let c = 0;
  const len = digits.length;
  for (let i = 0; i < len; i++) {
    const digitChar = digits[len - 1 - i];
    if (digitChar === undefined) return false;
    const digit = parseInt(digitChar, 10);
    const pRow = P_TABLE[i % 8];
    if (!pRow) return false;
    const pVal = pRow[digit];
    if (pVal === undefined) return false;
    const dRow = D_TABLE[c];
    if (!dRow) return false;
    const dVal = dRow[pVal];
    if (dVal === undefined) return false;
    c = dVal;
  }

  return c === 0;
}

/**
 * Calculate the Verhoeff checksum digit for an 11-digit string.
 */
export function generateVerhoeffChecksum(str: string): number {
  let c = 0;
  const len = str.length;
  for (let i = 0; i < len; i++) {
    const digitChar = str[len - 1 - i];
    if (digitChar === undefined) return 0;
    const digit = parseInt(digitChar, 10);
    const pRow = P_TABLE[(i + 1) % 8];
    if (!pRow) return 0;
    const pVal = pRow[digit];
    if (pVal === undefined) return 0;
    const dRow = D_TABLE[c];
    if (!dRow) return 0;
    const dVal = dRow[pVal];
    if (dVal === undefined) return 0;
    c = dVal;
  }
  return INV_TABLE[c] ?? 0;
}
