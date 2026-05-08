import { test, expect } from '@playwright/test';
import { enableVirtualAuthenticator } from './helpers/webauthn';
import { uniqueUsername } from './helpers/dev-data';

// DB is reset once in global-setup before the server boots.
// Each test uses a unique username so reruns on the same DB don't conflict.

test('signup → trade → portfolio → sell', async ({ page, context }) => {
	const username = uniqueUsername('alice');

	// Enable virtual authenticator on this page before any WebAuthn call.
	await page.goto('/signup');
	await enableVirtualAuthenticator(context, page);

	// 1. Fill signup form and submit.
	await page.fill('input[name="username"]', username);
	await page.locator('form[action="?/begin"] button[type="submit"]').click();

	// Virtual authenticator auto-confirms the biometric prompt.
	await expect(page.getByText('save your recovery codes')).toBeVisible({ timeout: 15_000 });

	// Confirm saved and navigate to portfolio.
	await page.check('input[type="checkbox"]');
	await page.getByRole('button', { name: 'continue to portfolio' }).click();

	await expect(page).toHaveURL(/\/portfolio$/, { timeout: 10_000 });
	await expect(page.getByText('$10,000.00').first()).toBeVisible();

	// 2. Trade — buy 5 AAPL (seeded live price: 19000 cents = $190.00).
	await page.goto('/trade');

	await page.fill('input[name="symbol"]', 'AAPL');
	await page.fill('input[name="shares"]', '5');
	// main scopes away from the sidebar's signout form buttons.
	// The trade form's submit button is the only type="submit" inside <main>.
	await page.locator('main button[type="submit"]').click();

	// Success message from trade action: "bought 5 AAPL @ $190.00"
	await expect(page.getByText(/bought 5 AAPL/i)).toBeVisible({ timeout: 10_000 });

	// 3. Navigate to portfolio and verify cash and holdings.
	await page.goto('/portfolio');
	// Cash: $10,000 - 5 * $190 = $9,050
	await expect(page.getByText('$9,050.00')).toBeVisible({ timeout: 10_000 });
	await expect(page.getByRole('cell', { name: 'AAPL' })).toBeVisible();

	// 4. Sell all 5 AAPL.
	await page.goto('/trade');
	// Switch to sell mode — the toggle buttons have type="button".
	await page.locator('main button[type="button"]:has-text("sell")').click();
	await page.fill('input[name="symbol"]', 'AAPL');
	await page.fill('input[name="shares"]', '5');
	// Now the submit button should show "sell".
	await page.locator('main button[type="submit"]').click();

	await expect(page.getByText(/sold 5 AAPL/i)).toBeVisible({ timeout: 10_000 });

	// 5. Portfolio should now show no holdings and cash back to $10,000.
	await page.goto('/portfolio');
	await expect(page.getByText(/no holdings yet/i)).toBeVisible({ timeout: 10_000 });
	await expect(page.getByText('$10,000.00').first()).toBeVisible();
});
