import { test, expect } from '@playwright/test';
import { enableVirtualAuthenticator } from './helpers/webauthn';
import { uniqueUsername } from './helpers/dev-data';

// Historical competition: AAPL seeded at 18500 cents ($185.00) on 2024-01-02.
// 10 shares × $185 = $1,850 → cash = $10,000 - $1,850 = $8,150.
// End price: AAPL 2024-12-31 = 24000 cents ($240.00).
// Return: (10 × $240 + $8,150 - $10,000) / $10,000 = $550 / $10,000 = 5.50%

test('historical competition: create → trade at start price → resolve → leaderboard shows return', async ({
	page,
	context
}) => {
	const username = uniqueUsername('hist');

	// Sign up.
	await page.goto('/signup');
	await enableVirtualAuthenticator(context, page);
	await page.fill('input[name="username"]', username);
	await page.locator('form[action="?/begin"] button[type="submit"]').click();
	await expect(page.getByText('save your recovery codes')).toBeVisible({ timeout: 15_000 });
	await page.check('input[type="checkbox"]');
	await page.getByRole('button', { name: 'continue to portfolio' }).click();
	await expect(page).toHaveURL(/\/portfolio$/, { timeout: 10_000 });

	// Create historical competition spanning all of 2024.
	await page.goto('/competitions/new');
	await page.locator('label:has(input[value="historical"])').click();
	await page.fill('input[name="name"]', 'History 2024');
	await page.fill('input[name="startDate"]', '2024-01-02');
	await page.fill('input[name="endDate"]', '2024-12-31');
	await page.fill('input[name="startingCash"]', '10000');
	await page.locator('main button[type="submit"]').click();

	await expect(page).toHaveURL(/\/competitions\/[a-z0-9]+$/, { timeout: 10_000 });

	// Competition should be open.
	await expect(page.getByText('open')).toBeVisible({ timeout: 5_000 });

	// Trade section is visible for open historical competitions.
	const tradeSection = page.locator('section').filter({ hasText: /^trade/ });
	await expect(tradeSection).toBeVisible({ timeout: 5_000 });

	// Buy 10 AAPL — historical mode uses the start-date close (2024-01-02 = $185.00).
	await tradeSection.locator('input[name="symbol"]').fill('AAPL');
	await tradeSection.locator('input[name="shares"]').fill('10');
	await tradeSection.locator('button[type="submit"]').click();

	// The competition trade action calls invalidateAll() after success, clearing form state.
	// Assert on the cash update instead: $10,000 - 10 * $185 = $8,150.
	await expect(page.getByText('$8,150.00')).toBeVisible({ timeout: 10_000 });

	// Resolve (host-only button in host controls section).
	const hostSection = page.locator('section').filter({ hasText: 'host controls' });
	await hostSection.getByRole('button', { name: 'resolve now' }).click();

	// After resolve, status changes to "finished".
	await expect(page.getByText('finished')).toBeVisible({ timeout: 10_000 });

	// Leaderboard shows ~5.50% return.
	await expect(page.getByText(/5\.5/)).toBeVisible({ timeout: 5_000 });
});
