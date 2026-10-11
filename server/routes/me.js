import { Router } from 'express';
import { COOKIE_NAME, findSession, readCookie, requireAuth } from '../sessions.js';
import { buildMe } from '../me.js';

export function meRouter({ db }) {
  const router = Router();

  router.get('/session', (req, res) => {
    const auth = findSession(db, readCookie(req, COOKIE_NAME));
    res.json(auth ? { authenticated: true, me: buildMe(db, auth.user, auth.sessionId) } : { authenticated: false });
  });

  router.get('/me', requireAuth(db), (req, res) => {
    res.json(buildMe(db, req.auth.user, req.auth.sessionId));
  });

  return router;
}
