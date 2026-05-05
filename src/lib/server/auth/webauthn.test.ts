import { describe, it, expect } from 'vitest';
import { rpConfig, generateRegistrationChallenge, generateAuthenticationChallenge } from './webauthn';

describe('webauthn config and challenges', () => {
  it('reads RP ID and origin from environment-shaped config', () => {
    const cfg = rpConfig({ rpId: 'localhost', origin: 'http://localhost:5173' });
    expect(cfg.rpId).toBe('localhost');
    expect(cfg.expectedOrigin).toBe('http://localhost:5173');
  });

  it('generates registration options containing the username and a challenge', async () => {
    const opts = await generateRegistrationChallenge({
      rp: { rpId: 'localhost', expectedOrigin: 'http://localhost:5173', rpName: 'test' },
      userId: 'u1',
      username: 'alice',
      displayName: 'Alice',
      excludeCredentialIds: []
    });
    expect(opts.user.name).toBe('alice');
    expect(opts.user.displayName).toBe('Alice');
    expect(opts.challenge).toBeDefined();
  });

  it('generates authentication options that allow resident credentials', async () => {
    const opts = await generateAuthenticationChallenge({
      rp: { rpId: 'localhost', expectedOrigin: 'http://localhost:5173', rpName: 'test' }
    });
    expect(opts.challenge).toBeDefined();
    expect(opts.allowCredentials).toEqual([]);
  });
});
