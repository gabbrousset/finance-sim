const SYMBOL_RE = /^[A-Z][A-Z0-9.\-]{0,9}$/;

export function normalizeSymbol(input: string): string {
  return input.trim().toUpperCase();
}

export function isValidSymbol(input: string): boolean {
  return SYMBOL_RE.test(input);
}
