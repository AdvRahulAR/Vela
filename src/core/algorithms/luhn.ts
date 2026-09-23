/**
 * Luhn algorithm (Mod 10) validator
 * Used for Credit Cards (Visa, Mastercard, Amex, RuPay, Discover, etc.)
 */

export function validateLuhn(input: string): boolean {
  const digits = input.replace(/[\s-]+/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;

  let sum = 0;
  let alternate = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    const char = digits[i];
    if (char === undefined) return false;
    let n = parseInt(char, 10);
    if (alternate) {
      n *= 2;
      if (n > 9) {
        n -= 9;
      }
    }
    sum += n;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}
