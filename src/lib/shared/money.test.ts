import { describe, it, expect } from 'vitest';
import { centsToDollars, dollarsToCents, formatUsd } from './money';

describe('money', () => {
  it('round-trips dollars <-> cents without precision loss', () => {
    expect(dollarsToCents(123.45)).toBe(12345);
    expect(centsToDollars(12345)).toBe(123.45);
  });
  it('formats cents as USD', () => {
    expect(formatUsd(12345)).toBe('$123.45');
    expect(formatUsd(0)).toBe('$0.00');
    expect(formatUsd(-100)).toBe('-$1.00');
    expect(formatUsd(123456789)).toBe('$1,234,567.89');
  });
  it('rejects fractional cents on input', () => {
    expect(() => dollarsToCents(0.001)).toThrow();
  });
});
