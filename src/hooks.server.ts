import type { Handle } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { resolveSession } from '$lib/server/auth/sessions';
import { getDb, schema } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { CompetitionService } from '$lib/server/competitions/service';

let lastTickAt = 0;
const TICK_INTERVAL_SEC = 30;

function maybeTick() {
  const now = Math.floor(Date.now() / 1000);
  if (now - lastTickAt < TICK_INTERVAL_SEC) return;
  lastTickAt = now;
  try {
    const db = getDb();
    const market = getMarketData();
    const svc = new CompetitionService(db, market);
    svc.tickStatuses();
  } catch (e) {
    // Don't let a tick error break requests; reset so we'll retry next time.
    lastTickAt = 0;
    console.error('[hook] tickStatuses failed:', e);
  }
}

export const handle: Handle = async ({ event, resolve }) => {
  maybeTick();
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
