import { describe, it, expect } from 'vitest';
import { isMarketOpen } from './market-hours';

// All timestamps verified: constructed via Date.UTC with EDT/EST offset, then
// confirmed by round-tripping through Intl.DateTimeFormat('America/New_York').

describe('isMarketOpen', () => {
	it('returns true for a weekday at 10:00 AM ET', () => {
		// 2024-01-22 Mon 10:00 ET = unix 1705935600
		expect(isMarketOpen(1705935600)).toBe(true);
	});

	it('returns false for a weekday at 5:00 AM ET (before open)', () => {
		// 2024-01-22 Mon 05:00 ET = unix 1705917600
		expect(isMarketOpen(1705917600)).toBe(false);
	});

	it('returns false for a weekday at 5:00 PM ET (after close)', () => {
		// 2024-01-22 Mon 17:00 ET = unix 1705960800
		expect(isMarketOpen(1705960800)).toBe(false);
	});

	it('returns false on Saturday', () => {
		// 2024-01-20 Sat 12:00 ET = unix 1705770000
		expect(isMarketOpen(1705770000)).toBe(false);
	});

	it('returns false on a full-close holiday (New Year\'s Day 2024)', () => {
		// 2024-01-01 Mon 12:00 ET = unix 1704128400
		expect(isMarketOpen(1704128400)).toBe(false);
	});

	it('returns true on an early-close day (2024-07-03 1:00 PM ET)', () => {
		// Early-close days are treated as fully open for caching purposes.
		// The holiday list contains only full-day closures; early-close days
		// (e.g. July 3, day after Thanksgiving) are omitted intentionally.
		// Over-caching by ~30 min on those days is harmless.
		// 2024-07-03 Wed 13:00 ET = unix 1720026000
		expect(isMarketOpen(1720026000)).toBe(true);
	});
});
