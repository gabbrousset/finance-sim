import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse
} from '@simplewebauthn/server';

export interface RpConfig {
  rpId: string;
  rpName: string;
  expectedOrigin: string;
}

export function rpConfig(input: { rpId: string; origin: string; rpName?: string }): RpConfig {
  return {
    rpId: input.rpId,
    rpName: input.rpName ?? 'Curb & Co.',
    expectedOrigin: input.origin
  };
}

export async function generateRegistrationChallenge(args: {
  rp: RpConfig;
  userId: string;
  username: string;
  displayName: string;
  excludeCredentialIds: string[];
}) {
  return generateRegistrationOptions({
    rpName: args.rp.rpName,
    rpID: args.rp.rpId,
    userID: new TextEncoder().encode(args.userId),
    userName: args.username,
    userDisplayName: args.displayName,
    attestationType: 'none',
    excludeCredentials: args.excludeCredentialIds.map((id) => ({ id })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred'
    }
  });
}

export async function verifyRegistration(args: {
  rp: RpConfig;
  expectedChallenge: string;
  response: Parameters<typeof verifyRegistrationResponse>[0]['response'];
}): Promise<VerifiedRegistrationResponse> {
  return verifyRegistrationResponse({
    response: args.response,
    expectedChallenge: args.expectedChallenge,
    expectedOrigin: args.rp.expectedOrigin,
    expectedRPID: args.rp.rpId,
    requireUserVerification: false
  });
}

export async function generateAuthenticationChallenge(args: { rp: RpConfig }) {
  return generateAuthenticationOptions({
    rpID: args.rp.rpId,
    userVerification: 'preferred',
    allowCredentials: []
  });
}

export async function verifyAuthentication(args: {
  rp: RpConfig;
  expectedChallenge: string;
  storedCredential: { id: string; publicKey: Uint8Array; counter: number; transports?: string[] };
  response: Parameters<typeof verifyAuthenticationResponse>[0]['response'];
}): Promise<VerifiedAuthenticationResponse> {
  return verifyAuthenticationResponse({
    response: args.response,
    expectedChallenge: args.expectedChallenge,
    expectedOrigin: args.rp.expectedOrigin,
    expectedRPID: args.rp.rpId,
    credential: {
      id: args.storedCredential.id,
      publicKey: args.storedCredential.publicKey as Uint8Array<ArrayBuffer>,
      counter: args.storedCredential.counter,
      transports: args.storedCredential.transports as never
    },
    requireUserVerification: false
  });
}
