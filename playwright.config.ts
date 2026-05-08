import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
	testDir: './e2e',
	testMatch: /.*\.spec\.ts$/,
	fullyParallel: false,
	retries: process.env.CI ? 2 : 0,
	workers: 1,
	reporter: process.env.CI ? 'github' : 'list',
	globalSetup: './e2e/global-setup.ts',
	use: {
		baseURL: 'http://localhost:5174',
		trace: 'on-first-retry',
		screenshot: 'only-on-failure'
	},
	projects: [
		{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }
	],
	webServer: {
		command: 'pnpm build && DATABASE_URL=./e2e/test.db MARKET_DATA=mock MARKET_SEED_PATH=./e2e/fixtures/market-seed.json RP_ID=localhost ORIGIN=http://localhost:5174 NODE_ENV=test PORT=5174 node build',
		url: 'http://localhost:5174',
		reuseExistingServer: false,
		timeout: 120_000,
		stdout: 'pipe',
		stderr: 'pipe',
		env: {
			DATABASE_URL: './e2e/test.db',
			MARKET_DATA: 'mock',
			MARKET_SEED_PATH: './e2e/fixtures/market-seed.json',
			RP_ID: 'localhost',
			ORIGIN: 'http://localhost:5174',
			NODE_ENV: 'test',
			PORT: '5174'
		}
	}
});
