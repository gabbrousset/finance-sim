import { test, expect } from '@playwright/test';
import { enableVirtualAuthenticator } from './helpers/webauthn';
import { uniqueUsername } from './helpers/dev-data';

test('recovery flow: signup → capture code → sign out → recover → passkey setup page', async ({
	page,
	context
}) => {
	const username = uniqueUsername('bob');

	// Sign up.
	await context.clearCookies();
	await page.goto('/signup');
	await enableVirtualAuthenticator(context, page);

	await page.fill('input[name="username"]', username);
	await page.locator('form[action="?/begin"] button[type="submit"]').click();

	await expect(page.getByText('save your recovery codes')).toBeVisible({ timeout: 15_000 });

	// Capture a recovery code from the rendered <pre> block.
	const pre = page.locator('pre');
	await expect(pre).toBeVisible();
	const codesText = await pre.textContent();
	const codes = (codesText ?? '').trim().split('\n').filter(Boolean);
	expect(codes.length).toBeGreaterThan(0);
	const recoveryCode = codes[0].trim();

	// Confirm saved and continue.
	await page.check('input[type="checkbox"]');
	await page.getByRole('button', { name: 'continue to portfolio' }).click();
	await expect(page).toHaveURL(/\/portfolio$/, { timeout: 10_000 });

	// Sign out. The desktop sidebar has a sign out button inside <aside>.
	// It's in a form[action="/signout"] — click the visible one.
	await page.locator('aside form[action="/signout"] button').click();
	await page.waitForURL((url) => !url.pathname.startsWith('/portfolio'), { timeout: 5_000 });

	// Navigate to recovery page.
	await page.goto('/recover');
	await page.fill('input[name="username"]', username);
	await page.fill('input[name="code"]', recoveryCode);
	// The recover form is the only form on this page.
	await page.locator('form button[type="submit"]').click();

	// After recovery, server redirects to /settings/passkeys?force=1.
	await expect(page).toHaveURL(/\/settings\/passkeys/, { timeout: 10_000 });

	// The forced-setup alert should be visible.
	await expect(
		page.getByText('you signed in with a recovery code')
	).toBeVisible({ timeout: 5_000 });
});
