import { test, expect } from '@playwright/test';
import { enableVirtualAuthenticator } from './helpers/webauthn';
import { uniqueUsername } from './helpers/dev-data';

// Tests the join flow for a live competition.
// Skips the "force into running" step — covered by unit tests.
// This spec verifies: create → join → both members visible on leaderboard.

async function signupUser(
	page: import('@playwright/test').Page,
	context: import('@playwright/test').BrowserContext,
	username: string
) {
	// Defensive: clear any leaked cookies from prior tests so /signup
	// doesn't redirect to /portfolio for a stale session.
	await context.clearCookies();
	await page.goto('/signup');
	await enableVirtualAuthenticator(context, page);
	await page.fill('input[name="username"]', username);
	await page.locator('form[action="?/begin"] button[type="submit"]').click();
	await expect(page.getByText('save your recovery codes')).toBeVisible({ timeout: 15_000 });
	await page.check('input[type="checkbox"]');
	await page.getByRole('button', { name: 'continue to portfolio' }).click();
	await expect(page).toHaveURL(/\/portfolio$/, { timeout: 10_000 });
}

test('live competition: create → second user joins → both appear on leaderboard', async ({
	page,
	context,
	browser
}) => {
	const host = uniqueUsername('host');

	// Sign up host.
	await signupUser(page, context, host);

	// Create a live competition with start date far in the future (keeps status = open).
	await page.goto('/competitions/new');
	await page.locator('label:has(input[value="live"])').click();
	await page.fill('input[name="name"]', 'Live Test Comp');
	await page.fill('input[name="startDate"]', '2099-01-01');
	await page.fill('input[name="endDate"]', '2099-12-31');
	await page.fill('input[name="startingCash"]', '10000');
	await page.locator('main button[type="submit"]').click();

	// Redirects to competition detail page.
	await expect(page).toHaveURL(/\/competitions\/[a-z0-9]+$/, { timeout: 10_000 });

	// Extract invite code — rendered in the SectionHead's `.meta` span as
	// e.g. "live · code ABCD2345". Match the first .meta containing "code".
	const metaEl = page.locator('.meta').filter({ hasText: /code/ }).first();
	await expect(metaEl).toBeVisible({ timeout: 5_000 });
	const metaText = (await metaEl.textContent())?.trim() ?? '';
	const inviteCode = metaText.match(/code\s+(\S+)/)?.[1] ?? '';
	expect(inviteCode.length).toBeGreaterThan(0);

	// Sign up second user in a fresh browser context.
	const ctx2 = await browser.newContext();
	const page2 = await ctx2.newPage();
	const member = uniqueUsername('member');
	await signupUser(page2, ctx2, member);

	// Join via invite code.
	await page2.goto(`/competitions/join/${inviteCode}`);
	// Join page shows a SectionHead titled "Join: <comp name>".
	await expect(page2.getByText('Live Test Comp')).toBeVisible({ timeout: 5_000 });
	await page2.locator('main button[type="submit"]').click();

	// Should redirect to the competition detail page.
	await expect(page2).toHaveURL(/\/competitions\/[a-z0-9]+$/, { timeout: 10_000 });

	// Both users should appear in the leaderboard table.
	await expect(page2.getByRole('cell', { name: host })).toBeVisible({ timeout: 5_000 });
	await expect(page2.getByRole('cell', { name: member })).toBeVisible({ timeout: 5_000 });

	await ctx2.close();
});
