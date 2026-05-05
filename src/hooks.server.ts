import type { Handle } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { resolveSession } from '$lib/server/auth/sessions';
import { getDb, schema } from '$lib/server/db/client';

export const handle: Handle = async ({ event, resolve }) => {
  event.locals.session = null;
  event.locals.user = null;

  const cookie = event.cookies.get('session');
  if (cookie) {
    const db = getDb();
    const session = await resolveSession(db, cookie);
    if (session) {
      const user = db
        .select({
          id: schema.users.id,
          username: schema.users.username,
          displayName: schema.users.displayName
        })
        .from(schema.users)
        .where(eq(schema.users.id, session.userId))
        .get();
      if (user) {
        event.locals.session = session;
        event.locals.user = user;
      }
    }
  }

  return resolve(event);
};
