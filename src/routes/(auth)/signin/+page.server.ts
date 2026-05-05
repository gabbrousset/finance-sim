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
  begin: async ({ cookies }) => {
    const db = getDb();
    try {
      const { options, challengeCookieValue } = await auth.beginSignin(db, rp);
      cookies.set('signin_challenge', challengeCookieValue, {
        path: '/',
        httpOnly: true,
        secure: env.ORIGIN?.startsWith('https') ?? false,
        sameSite: 'strict',
        maxAge: 300
      });
      return { stage: 'options' as const, options };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'sign-in failed';
      return fail(400, { error: msg });
    }
  },

  complete: async ({ request, cookies }) => {
    const cookie = cookies.get('signin_challenge');
    if (!cookie) return fail(400, { error: 'missing or expired challenge' });
    const body = await request.json();
    const db = getDb();
    try {
      const result = await auth.completeSignin(
        db,
        rp,
        cookie,
        body.assertion,
        request.headers.get('user-agent') ?? ''
      );
      cookies.delete('signin_challenge', { path: '/' });
      if (!result) return fail(400, { error: 'sign-in failed' });
      cookies.set('session', result.sessionCookieValue, {
        path: '/',
        httpOnly: true,
        secure: env.ORIGIN?.startsWith('https') ?? false,
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 30
      });
      return { stage: 'success' as const };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'sign-in failed';
      return fail(400, { error: msg });
    }
  }
};
