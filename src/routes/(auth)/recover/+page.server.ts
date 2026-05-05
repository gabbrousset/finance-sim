import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getDb } from '$lib/server/db/client';
import * as auth from '$lib/server/auth/service';
import { env } from '$env/dynamic/private';

export const load: PageServerLoad = async ({ locals }) => {
  if (locals.user) throw redirect(302, '/portfolio');
  return {};
};

export const actions: Actions = {
  default: async ({ request, cookies }) => {
    const form = await request.formData();
    const username = String(form.get('username') ?? '').trim();
    const code = String(form.get('code') ?? '').trim();
    if (!username || !code) return fail(400, { error: 'username and code required' });
    const db = getDb();
    const result = await auth.signinWithRecoveryCode(
      db,
      username,
      code,
      request.headers.get('user-agent') ?? ''
    );
    if (!result) return fail(400, { error: 'invalid username or recovery code' });
    cookies.set('session', result.sessionCookieValue, {
      path: '/',
      httpOnly: true,
      secure: env.ORIGIN?.startsWith('https') ?? false,
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 30
    });
    cookies.set('force_passkey_setup', '1', {
      path: '/',
      httpOnly: true,
      secure: env.ORIGIN?.startsWith('https') ?? false,
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 30
    });
    throw redirect(303, '/settings/passkeys?force=1');
  }
};
