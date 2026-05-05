import { describe, it, expect } from 'vitest';
import { normalizeSymbol, isValidSymbol } from './symbols';

describe('symbols', () => {
  it('uppercases and trims', () => {
    expect(normalizeSymbol(' aapl ')).toBe('AAPL');
    expect(normalizeSymbol('brk.b')).toBe('BRK.B');
  });
  it('validates plausible tickers', () => {
    expect(isValidSymbol('AAPL')).toBe(true);
    expect(isValidSymbol('BRK.B')).toBe(true);
    expect(isValidSymbol('A')).toBe(true);
  });
  it('rejects junk', () => {
    expect(isValidSymbol('')).toBe(false);
    expect(isValidSymbol('AAPL ')).toBe(false);
    expect(isValidSymbol('aa pl')).toBe(false);
    expect(isValidSymbol('THISWAYTOOLONG')).toBe(false);
    expect(isValidSymbol('aapl')).toBe(false);
    expect(isValidSymbol('1AAPL')).toBe(false);
  });
});
