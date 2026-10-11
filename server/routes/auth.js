import { Router } from 'express';
import { DUMMY_HASH, rateLimit, verifySecret } from '../security.js';
import {
  audit, clearSessionCookie, createSession, endAllSessions, endSession,
  findSession, readCookie, requireAuth, setSessionCookie, COOKIE_NAME
} from '../sessions.js';
import { buildMe } from '../me.js';

const ROLES = ['head', 'hq', 'commander', 'admin'];
const MAX_FAILED_LOGINS = 5;
const LOCK_MS = 15 * 60 * 1000;

const GENERIC_PASSWORD_ERROR = 'Неверные учётные данные или учётная запись временно заблокирована.';
const GENERIC_KEP_ERROR = 'Носитель не опознан или PIN-код неверен.';
const TOKEN_LOCKED_ERROR = 'Носитель заблокирован. Обратитесь в службу ИБ.';

const isText = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max;

function context(req) {
  return { ip: req.ip, userAgent: (req.get('user-agent') || '').slice(0, 300) };
}


async function loginWithPassword(db, { role, identifier, secret }, ctx) {
  if (!isText(identifier, 100) || !ROLES.includes(role)) {
    return { status: 400, error: 'Заполните все поля.' };
  }

  const login = identifier.trim().toLowerCase();
  const digits = identifier.replace(/\D/g, '');
  const user = db.prepare(
    `SELECT * FROM users WHERE is_active = 1 AND (login = ? OR snils_digits = ?)`
  ).get(login, digits.length === 11 ? digits : null);

  const now = Date.now();
  const locked = Boolean(user && user.locked_until && user.locked_until > now);
  // Хэш проверяется всегда — время ответа не зависит от того, существует ли учётная запись.
  const passwordOk = await verifySecret(secret, user?.password_hash ?? DUMMY_HASH);

  if (!user || locked || !passwordOk) {
    if (user && !locked) registerFailure(db, user, ctx);
    audit(db, { userId: user?.id ?? null, event: 'login_fail', method: 'password', identifier, ctx,
                details: locked ? 'account_locked' : null });
    return { status: 401, error: GENERIC_PASSWORD_ERROR };
  }

  if (user.role !== role) {
    audit(db, { userId: user.id, event: 'login_denied', method: 'password', identifier, ctx, details: `role_mismatch:${role}` });
    return { status: 403, error: 'Выбранный профиль доступа не назначен этой учётной записи.' };
  }

  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
  return { user };
}

function registerFailure(db, user, ctx) {
  const attempts = user.failed_attempts + 1;
  if (attempts >= MAX_FAILED_LOGINS) {
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?').run(Date.now() + LOCK_MS, user.id);
    audit(db, { userId: user.id, event: 'lockout', method: 'password', ctx });
  } else {
    db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(attempts, user.id);
  }
}


async function loginWithKep(db, { tokenSerial, secret }, ctx) {
  if (!isText(tokenSerial, 50)) return { status: 400, error: 'Не выбран ключевой носитель.' };

  const token = db.prepare('SELECT * FROM tokens WHERE serial = ?').get(tokenSerial);

  if (token?.locked) {
    audit(db, { userId: token.user_id, event: 'login_fail', method: 'kep', identifier: tokenSerial, ctx, details: 'token_locked' });
    return { status: 423, error: TOKEN_LOCKED_ERROR, attemptsLeft: 0, locked: true };
  }

  const pinOk = await verifySecret(secret, token?.pin_hash ?? DUMMY_HASH);
  if (!token || !pinOk) {
    if (!token) {
      audit(db, { event: 'login_fail', method: 'kep', identifier: tokenSerial, ctx, details: 'unknown_token' });
      return { status: 401, error: GENERIC_KEP_ERROR };
    }
    const attemptsLeft = token.pin_attempts_left - 1;
    db.prepare('UPDATE tokens SET pin_attempts_left = ?, locked = ? WHERE id = ?')
      .run(attemptsLeft, attemptsLeft <= 0 ? 1 : 0, token.id);
    audit(db, { userId: token.user_id, event: attemptsLeft <= 0 ? 'token_locked' : 'login_fail', method: 'kep', identifier: tokenSerial, ctx });
    return attemptsLeft <= 0
      ? { status: 423, error: TOKEN_LOCKED_ERROR, attemptsLeft: 0, locked: true }
      : { status: 401, error: `Неверный PIN-код. Осталось попыток: ${attemptsLeft}`, attemptsLeft };
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(token.user_id);
  const cert = db.prepare('SELECT * FROM certificates WHERE token_id = ? ORDER BY valid_to DESC LIMIT 1').get(token.id);
  if (!user || !cert || cert.status !== 'valid' || cert.valid_to <= Date.now()) {
    audit(db, { userId: token.user_id, event: 'login_denied', method: 'kep', identifier: tokenSerial, ctx, details: 'certificate_invalid' });
    return { status: 403, error: 'Сертификат недействителен: срок действия истёк или он отозван.' };
  }

  db.prepare('UPDATE tokens SET pin_attempts_left = 3 WHERE id = ?').run(token.id);
  return { user };
}


export function authRouter({ db, config }) {
  const router = Router();

  router.post('/login', rateLimit(config.loginRateLimit), async (req, res, next) => {
    try {
      const body = req.body ?? {};
      const { method } = body;
      if ((method !== 'password' && method !== 'kep') || !isText(body.secret, 200)) {
        return res.status(400).json({ error: 'Заполните все поля.' });
      }

      const ctx = context(req);
      const result = method === 'kep'
        ? await loginWithKep(db, body, ctx)
        : await loginWithPassword(db, body, ctx);

      if (!result.user) {
        const { status, ...payload } = result;
        return res.status(status).json(payload);
      }

      const session = createSession(db, config, { userId: result.user.id, method, ctx });
      audit(db, { userId: result.user.id, event: 'login_ok', method, ctx });
      setSessionCookie(res, session.token, config);
      res.json(buildMe(db, result.user, session.id));
    } catch (error) {
      next(error);
    }
  });

  router.post('/logout', (req, res) => {
    const auth = findSession(db, readCookie(req, COOKIE_NAME));
    if (auth) {
      endSession(db, auth.sessionId, 'logout');
      audit(db, { userId: auth.user.id, event: 'logout', method: auth.method, ctx: context(req) });
    }
    clearSessionCookie(res, config);
    res.status(204).end();
  });

  router.post('/logout-all', requireAuth(db), (req, res) => {
    const closed = endAllSessions(db, req.auth.user.id, 'forced');
    audit(db, { userId: req.auth.user.id, event: 'logout_all', method: req.auth.method, ctx: context(req), details: `closed:${closed}` });
    clearSessionCookie(res, config);
    res.status(204).end();
  });

  return router;
}
