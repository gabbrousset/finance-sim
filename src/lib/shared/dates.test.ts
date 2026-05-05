import { describe, it, expect } from 'vitest';
import { toIsoDate, parseIsoDate, daysBetween } from './dates';

describe('dates', () => {
  it('formats unix seconds as YYYY-MM-DD UTC', () => {
    // 2024-06-15T12:00:00Z
    expect(toIsoDate(1718452800)).toBe('2024-06-15');
  });
  it('parses YYYY-MM-DD as UTC midnight unix seconds', () => {
    expect(parseIsoDate('2024-06-15')).toBe(1718409600);
  });
  it('counts whole days between two iso dates inclusive', () => {
    expect(daysBetween('2024-06-15', '2024-06-15')).toBe(1);
    expect(daysBetween('2024-06-15', '2024-06-17')).toBe(3);
  });
});
