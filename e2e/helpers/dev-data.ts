export function uniqueUsername(prefix: string): string {
	// Username max 24 chars: use last 6 digits of epoch + 3 random digits.
	const suffix = `${Date.now()}`.slice(-6) + Math.floor(Math.random() * 1000).toString().padStart(3, '0');
	return `${prefix}${suffix}`.slice(0, 24);
}
