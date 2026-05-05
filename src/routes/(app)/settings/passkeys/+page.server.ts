import { fail, redirect } from '@sveltejs/kit';
import { and, eq } from 'drizzle-orm';
import type { Actions, PageServerLoad } from './$types';
import { getDb, schema } from '$lib/server/db/client';
import * as authService from '$lib/server/auth/service';
import { regenerateRecoveryCodes } from '$lib/server/auth/recovery';
import { suggestDeviceName } from '$lib/server/auth/aaguid';
import { env } from '$env/dynamic/private';

const rp = {
  rpId: env.RP_ID ?? 'localhost',
  expectedOrigin: env.ORIGIN ?? 'http://localhost:5173',
  rpName: 'finance-sim'
};

export const load: PageServerLoad = async ({ locals, url, cookies }) => {
  if (!locals.user) throw redirect(302, '/signin');
  const db = getDb();
  const rows = db
    .select()
    .from(schema.passkeys)
    .where(eq(schema.passkeys.userId, locals.user.id))
    .all();
  return {
    user: locals.user,
    passkeys: rows.map((r) => ({
      id: r.id,
      deviceName: r.deviceName,
      suggestion: suggestDeviceName(r.aaguid),
      lastUsedAt: r.lastUsedAt,
      backupState: r.backupState
    })),
    forceSetup:
      url.searchParams.get('force') === '1' && cookies.get('force_passkey_setup') === '1'
  };
};

export const actions: Actions = {
  beginAdd: async ({ locals, cookies }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const db = getDb();
    const { options, challengeCookieValue } = await authService.beginAddPasskey(
      db,
      rp,
      locals.user.id
    );
    cookies.set('add_passkey_challenge', challengeCookieValue, {
      path: '/',
      httpOnly: true,
      secure: env.ORIGIN?.startsWith('https') ?? false,
      sameSite: 'strict',
      maxAge: 300
    });
    return { stage: 'options' as const, options };
  },

  completeAdd: async ({ request, locals, cookies }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const cookie = cookies.get('add_passkey_challenge');
    if (!cookie) return fail(400, { error: 'missing or expired challenge' });
    const body = await request.json();
    const db = getDb();
    try {
      const { passkeyId } = await authService.completeAddPasskey(
        db,
        rp,
        locals.user.id,
        cookie,
        body.attestation
      );
      cookies.delete('add_passkey_challenge', { path: '/' });
      cookies.delete('force_passkey_setup', { path: '/' });
      return { stage: 'added' as const, passkeyId };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'failed';
      return fail(400, { error: msg });
    }
  },

  rename: async ({ request, locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const form = await request.formData();
    const passkeyId = String(form.get('passkeyId') ?? '');
    const deviceName = String(form.get('deviceName') ?? '').trim();
    if (deviceName.length < 1 || deviceName.length > 40) {
      return fail(400, { error: 'device name must be 1-40 chars' });
    }
    const db = getDb();
    // Guard: only update if the passkey belongs to the current user
    db.update(schema.passkeys)
      .set({ deviceName })
      .where(and(eq(schema.passkeys.id, passkeyId), eq(schema.passkeys.userId, locals.user.id)))
      .run();
    return { ok: true };
  },

  revoke: async ({ request, locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const form = await request.formData();
    const passkeyId = String(form.get('passkeyId') ?? '');
    const db = getDb();
    // Ownership precheck: the service deletes by id without checking userId,
    // so we verify ownership here before handing off.
    const owns = db
      .select()
      .from(schema.passkeys)
      .where(and(eq(schema.passkeys.id, passkeyId), eq(schema.passkeys.userId, locals.user.id)))
      .get();
    if (!owns) return fail(404, { error: 'passkey not found' });
    try {
      await authService.revokePasskey(db, locals.user.id, passkeyId);
      return { ok: true };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'failed';
      return fail(400, { error: msg });
    }
  },

  regenerateCodes: async ({ locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const db = getDb();
    const codes = await regenerateRecoveryCodes(db, locals.user.id);
    return { recoveryCodes: codes };
  }
};
