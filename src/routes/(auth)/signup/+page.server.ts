import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getDb } from '$lib/server/db/client';
import * as auth from '$lib/server/auth/service';
import { env } from '$env/dynamic/private';

const rp = {
  rpId: env.RP_ID ?? 'localhost',
  expectedOrigin: env.ORIGIN ?? 'http://localhost:5173',
  rpName: 'finance-sim'
};

export const load: PageServerLoad = async ({ locals }) => {
  if (locals.user) throw redirect(302, '/portfolio');
  return {};
};

export const actions: Actions = {
  begin: async ({ request, cookies }) => {
    const form = await request.formData();
    const username = String(form.get('username') ?? '').trim();
    const displayName = String(form.get('displayName') ?? '').trim() || username;
    if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) {
      return fail(400, { error: 'username must be 3-24 chars, letters/digits/_/-' });
    }
    const db = getDb();
    try {
      const { options, challengeCookieValue } = await auth.beginSignup(
        db,
        rp,
        username,
        displayName,
        request.headers.get('user-agent') ?? ''
      );
      cookies.set('signup_challenge', challengeCookieValue, {
        path: '/',
        httpOnly: true,
        secure: env.ORIGIN?.startsWith('https') ?? false,
        sameSite: 'strict',
        maxAge: 300
      });
      return { stage: 'options' as const, options };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'signup failed';
      return fail(400, { error: msg });
    }
  },

  complete: async ({ request, cookies }) => {
    const challengeCookie = cookies.get('signup_challenge');
    if (!challengeCookie) return fail(400, { error: 'missing or expired challenge' });
    const form = await request.formData();
    const attestationStr = String(form.get('attestation') ?? '');
    if (!attestationStr) return fail(400, { error: 'missing attestation' });
    let attestation;
    try {
      attestation = JSON.parse(attestationStr);
    } catch {
      return fail(400, { error: 'malformed attestation' });
    }
    const db = getDb();
    try {
      const result = await auth.completeSignup(db, rp, challengeCookie, attestation);
      cookies.delete('signup_challenge', { path: '/' });
      cookies.set('session', result.sessionCookieValue, {
        path: '/',
        httpOnly: true,
        secure: env.ORIGIN?.startsWith('https') ?? false,
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 30
      });
      return { stage: 'success' as const, recoveryCodes: result.recoveryCodes };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'signup failed';
      return fail(400, { error: msg });
    }
  }
};
