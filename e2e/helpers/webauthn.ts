import type { BrowserContext, CDPSession, Page } from '@playwright/test';

export async function enableVirtualAuthenticator(
	context: BrowserContext,
	page: Page
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
	const cdp = await context.newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			transport: 'internal',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true
		}
	});
	return { cdp, authenticatorId };
}

export async function clearCredentials(
	cdp: CDPSession,
	authenticatorId: string
): Promise<void> {
	await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
}

export async function removeAuthenticator(
	cdp: CDPSession,
	authenticatorId: string
): Promise<void> {
	await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
}
