// NYSE market hours: 9:30 AM – 4:00 PM ET, Monday–Friday, excluding holidays.
//
// Early-close days (e.g. July 3 in some years, the day after Thanksgiving) are
// intentionally NOT included in the holiday list. The only consumer of this
// module is the cache TTL layer, and over-caching by ~30 minutes on early-close
// days is harmless. Treating early closes as fully open keeps the logic simple
// and avoids a separate early-close calendar that would need annual maintenance.

import holidays from './nyse-holidays.json';

const HOLIDAY_DATES = new Set(holidays.map((h) => h.date));

function toEt(unixSec: number): {
	dateIso: string;
	hour: number;
	minute: number;
	weekday: number;
} {
	const fmt = new Intl.DateTimeFormat('en-CA', {
		timeZone: 'America/New_York',
		year: 'numeric',
		month: '2-digit',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit',
		hour12: false,
		weekday: 'short'
	});
	const parts = Object.fromEntries(
		fmt.formatToParts(new Date(unixSec * 1000)).map((p) => [p.type, p.value])
	);
	const weekdayMap: Record<string, number> = {
		Sun: 0,
		Mon: 1,
		Tue: 2,
		Wed: 3,
		Thu: 4,
		Fri: 5,
		Sat: 6
	};
	return {
		dateIso: `${parts['year']}-${parts['month']}-${parts['day']}`,
		hour: Number(parts['hour']),
		minute: Number(parts['minute']),
		weekday: weekdayMap[parts['weekday']!]!
	};
}

export function isMarketOpen(unixSec: number): boolean {
	const t = toEt(unixSec);
	if (t.weekday === 0 || t.weekday === 6) return false;
	if (HOLIDAY_DATES.has(t.dateIso)) return false;
	const minutes = t.hour * 60 + t.minute;
	return minutes >= 9 * 60 + 30 && minutes < 16 * 60;
}

export function nextOpenAfter(unixSec: number): number {
	let cursor = unixSec;
	for (let i = 0; i < 14; i++) {
		cursor += 86_400;
		if (isMarketOpen(cursor)) return cursor;
	}
	return cursor;
}
