import { existsSync, unlinkSync } from 'node:fs';

export default function globalSetup() {
	for (const suffix of ['', '-wal', '-shm']) {
		const path = `./e2e/test.db${suffix}`;
		if (existsSync(path)) unlinkSync(path);
	}
}
