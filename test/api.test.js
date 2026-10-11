import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../server/config.js';
import { openDb } from '../server/db.js';
import { createApp } from '../server/app.js';
import { seedDemo } from '../server/seed.js';

let server, base, db;

before(async () => {
  db = openDb(':memory:');
  await seedDemo(db);
  const config = { ...loadConfig({}), loginRateLimit: { windowMs: 60_000, max: 1000 } };
  server = createApp({ db, config }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => { server.close(); db.close(); });

function client() {
  let cookie = '';
  return {
    async call(method, path, body, headers = {}) {
      const response = await fetch(base + path, {
        method,
        headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers },
        body: body ? JSON.stringify(body) : undefined
      });
      const set = response.headers.get('set-cookie');
      if (set) cookie = set.split(';')[0].endsWith('=') ? '' : set.split(';')[0];
      const text = await response.text();
      return { status: response.status, headers: response.headers, set, json: text ? JSON.parse(text) : null };
    },
    get cookie() { return cookie; }
  };
}

const login = (c, over = {}) => c.call('POST', '/api/auth/login',
  { method: 'password', role: 'head', identifier: 'voronov', secret: 'Voronov#2026', ...over });

test('без сеанса: /api/me → 401, /api/session → authenticated:false', async () => {
  const c = client();
  assert.equal((await c.call('GET', '/api/me')).status, 401);
  assert.deepEqual((await c.call('GET', '/api/session')).json, { authenticated: false });
});

test('успешный вход выдаёт httpOnly-cookie и данные пользователя без секретов', async () => {
  const c = client();
  const res = await login(c);
  assert.equal(res.status, 200);
  assert.match(res.set, /sid=/);
  assert.match(res.set, /HttpOnly/i);
  assert.match(res.set, /SameSite=Lax/i);
  assert.equal(res.json.user.fullName, 'Воронов Сергей Михайлович');
  assert.equal(res.json.user.initials, 'ВС');
  const text = JSON.stringify(res.json);
  assert.ok(!/password_hash|pin_hash|scrypt/i.test(text), 'в ответе не должно быть хэшей');
  assert.equal((await c.call('GET', '/api/me')).status, 200);
  assert.equal((await c.call('GET', '/api/session')).json.authenticated, true);
});

test('токен сеанса в базе хранится только в виде хэша', async () => {
  const c = client();
  await login(c);
  const token = c.cookie.split('=')[1];
  assert.equal(db.prepare('SELECT COUNT(*) n FROM sessions WHERE id = ?').get(token).n, 0);
});

test('вход по СНИЛС в разных форматах', async () => {
  for (const identifier of ['148-293-810 94', '14829381094']) {
    assert.equal((await login(client(), { identifier })).status, 200, identifier);
  }
});

test('неверный пароль и неизвестный логин дают одинаковый ответ', async () => {
  const a = await login(client(), { secret: 'wrong' });
  const b = await login(client(), { identifier: 'nobody', secret: 'wrong' });
  assert.equal(a.status, 401);
  assert.deepEqual(a.json, b.json);
});

test('верный пароль, но чужой профиль доступа → 403', async () => {
  const res = await login(client(), { role: 'commander' });
  assert.equal(res.status, 403);
  assert.equal(res.set, null);
});

test('SQL-инъекция в идентификаторе не проходит и не ломает сервер', async () => {
  const res = await login(client(), { identifier: "' OR '1'='1' --", secret: 'x' });
  assert.equal(res.status, 401);
});

test('некорректные тела запросов → 400', async () => {
  const c = client();
  for (const body of [{}, { method: 'password' }, { method: 'x', secret: 'a' },
                      { method: 'password', role: 'root', identifier: 'a', secret: 'b' },
                      { method: 'password', role: 'head', identifier: 123, secret: 'b' }]) {
    assert.equal((await c.call('POST', '/api/auth/login', body)).status, 400, JSON.stringify(body));
  }
  const raw = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{bad' });
  assert.equal(raw.status, 400);
  const big = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ a: 'x'.repeat(20000) }) });
  assert.equal(big.status, 413);
});

test('после 5 неудачных попыток учётная запись блокируется даже при верном пароле', async () => {
  for (let i = 0; i < 5; i++) assert.equal((await login(client(), { identifier: 'kuznetsov', role: 'hq', secret: 'bad' })).status, 401);
  const res = await login(client(), { identifier: 'kuznetsov', role: 'hq', secret: 'Kuznetsov#2026' });
  assert.equal(res.status, 401);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event = 'lockout'").get().n, 1);
  db.prepare("UPDATE users SET locked_until = NULL WHERE login = 'kuznetsov'").run(); // разблокировка для других тестов
});

test('КЭП: неверный PIN уменьшает счётчик, на третьей ошибке носитель блокируется навсегда', async () => {
  const kep = secret => client().call('POST', '/api/auth/login', { method: 'kep', tokenSerial: '38291048-A', secret });
  assert.equal((await kep('0000')).json.attemptsLeft, 2);
  assert.equal((await kep('0000')).json.attemptsLeft, 1);
  const third = await kep('0000');
  assert.equal(third.status, 423);
  assert.equal(third.json.locked, true);
  assert.equal((await kep('12345678')).status, 423, 'верный PIN не снимает блокировку');
  db.prepare("UPDATE tokens SET locked = 0, pin_attempts_left = 3").run();
});

test('КЭП: верный PIN → вход под владельцем носителя, счётчик сбрасывается', async () => {
  const c = client();
  await c.call('POST', '/api/auth/login', { method: 'kep', tokenSerial: '38291048-A', secret: 'bad' });
  const res = await c.call('POST', '/api/auth/login', { method: 'kep', tokenSerial: '38291048-A', secret: '12345678' });
  assert.equal(res.status, 200);
  assert.equal(res.json.user.login, 'voronov');
  assert.equal(res.json.token.attemptsLeft, 3);
  assert.equal(res.json.certificate.daysLeft, 180);
  assert.equal(res.json.audit.sessions[0].method, 'kep');
});

test('КЭП: просроченный или отозванный сертификат не допускается', async () => {
  db.prepare("UPDATE certificates SET valid_to = ?").run(Date.now() - 1000);
  const res = await client().call('POST', '/api/auth/login', { method: 'kep', tokenSerial: '38291048-A', secret: '12345678' });
  assert.equal(res.status, 403);
  db.prepare("UPDATE certificates SET valid_to = ?").run(Date.now() + 180 * 86400000);
});

test('КЭП: неизвестный носитель → общая ошибка', async () => {
  const res = await client().call('POST', '/api/auth/login', { method: 'kep', tokenSerial: 'nope', secret: '12345678' });
  assert.equal(res.status, 401);
});

test('выход завершает сеанс на сервере: старая cookie больше не работает', async () => {
  const c = client();
  await login(c);
  const stolen = c.cookie;
  assert.equal((await c.call('POST', '/api/auth/logout')).status, 204);
  const replay = await fetch(base + '/api/me', { headers: { cookie: stolen } });
  assert.equal(replay.status, 401);
});

test('«Завершить все сеансы» закрывает сеансы на всех устройствах', async () => {
  const a = client(), b = client();
  await login(a); await login(b);
  assert.equal((await a.call('POST', '/api/auth/logout-all')).status, 204);
  assert.equal((await b.call('GET', '/api/me')).status, 401);
});

test('сеанс истекает по таймауту и это фиксируется в журнале', async () => {
  const c = client();
  await login(c);
  db.prepare('UPDATE sessions SET expires_at = ? WHERE ended_at IS NULL AND user_id = (SELECT id FROM users WHERE login = ?)')
    .run(Date.now() - 1, 'voronov');
  assert.equal((await c.call('GET', '/api/me')).status, 401);
  assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event = 'session_expired'").get().n >= 1);
});

test('журнал аудита и список сеансов в профиле', async () => {
  const c = client();
  const res = await login(c, { identifier: 'ilyin', role: 'commander', secret: 'Ilyin#2026' });
  assert.equal(res.status, 200);
  const me = (await c.call('GET', '/api/me')).json;
  assert.equal(me.audit.sessions[0].current, true);
  assert.equal(me.audit.sessions[0].status, 'active');
  assert.ok(me.audit.total >= 1);
  assert.equal(me.certificate, null);
});

test('чужой Origin и cross-site запросы на изменение отклоняются', async () => {
  const c = client();
  const evil = await login(c, {}).then(() => c.call('POST', '/api/auth/logout', {}, { Origin: 'https://evil.example' }));
  assert.equal(evil.status, 403);
  const cross = await client().call('POST', '/api/auth/login', { method: 'password' }, { 'Sec-Fetch-Site': 'cross-site' });
  assert.equal(cross.status, 403);
});

test('заголовки безопасности и отсутствие кэширования API', async () => {
  const res = await client().call('GET', '/api/session');
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('файл базы данных и исходники сервера не отдаются как статика', async () => {
  for (const path of ['/data/gochs.db', '/server/seed.js', '/package.json', '/../server/db.js', '/.env']) {
    const res = await fetch(base + path);
    assert.notEqual(res.status, 200, path);
  }
});

test('ограничитель частоты входа возвращает 429', async () => {
  const config = { ...loadConfig({}), loginRateLimit: { windowMs: 60_000, max: 3 } };
  const limited = createApp({ db, config }).listen(0, '127.0.0.1');
  await new Promise(resolve => limited.once('listening', resolve));
  const url = `http://127.0.0.1:${limited.address().port}/api/auth/login`;
  const codes = [];
  for (let i = 0; i < 5; i++) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"method":"password"}' });
    codes.push(r.status);
  }
  limited.close();
  assert.deepEqual(codes, [400, 400, 400, 429, 429]);
});


const loginAdmin = c => login(c, { role: 'admin', identifier: 'komissarov', secret: 'Komissarov#2026' });

test('admin: вход, роль и подпись в профиле', async () => {
  const c = client();
  const res = await loginAdmin(c);
  assert.equal(res.status, 200);
  assert.equal(res.json.user.role, 'admin');
  assert.equal(res.json.user.initials, 'КВ');
  assert.match(res.json.user.roleLabel, /Администратор/);
});

test('admin: чужая роль в форме не даёт прав администратора', async () => {
  const res = await login(client(), { role: 'admin', identifier: 'voronov', secret: 'Voronov#2026' });
  assert.equal(res.status, 403);
});

test('админские API: без входа — 401, под другими ролями — 403', async () => {
  for (const path of ['/api/admin/users', '/api/admin/audit']) {
    assert.equal((await client().call('GET', path)).status, 401, path);
    for (const [role, identifier, secret] of [['head', 'voronov', 'Voronov#2026'], ['hq', 'kuznetsov', 'Kuznetsov#2026'], ['commander', 'ilyin', 'Ilyin#2026']]) {
      const c = client();
      await login(c, { role, identifier, secret });
      assert.equal((await c.call('GET', path)).status, 403, `${role} ${path}`);
    }
  }
  const c = client();
  await login(c, { role: 'commander', identifier: 'ilyin', secret: 'Ilyin#2026' });
  const target = db.prepare("SELECT id FROM users WHERE login = 'voronov'").get().id;
  assert.equal((await c.call('POST', `/api/admin/users/${target}/reset-sessions`)).status, 403);
});

test('admin: реестр пользователей без секретов', async () => {
  const c = client();
  await loginAdmin(c);
  const res = await c.call('GET', '/api/admin/users');
  assert.equal(res.status, 200);
  assert.equal(res.json.total, 4);
  assert.equal(res.json.roles, 4);
  const voronov = res.json.users.find(u => u.login === 'voronov');
  assert.equal(voronov.tokenModel, 'Рутокен ЭЦП 3.0 NFC');
  assert.ok(voronov.certificate.serialNumber);
  const text = JSON.stringify(res.json);
  assert.ok(!/hash|scrypt|snils|pin/i.test(text), 'в ответе не должно быть секретов и СНИЛС');
});

test('admin: журнал аудита — события, сводка, поиск, критические', async () => {
  const c = client();
  await loginAdmin(c);
  const all = (await c.call('GET', '/api/admin/audit?limit=5')).json;
  assert.equal(all.items.length, 5);
  assert.ok(all.total >= all.last24h && all.last24h > 0);
  assert.ok(all.items.every(item => item.level && item.eid && item.title));
  assert.ok(all.items[0].at >= all.items[4].at, 'новые события сверху');

  const found = (await c.call('GET', '/api/admin/audit?q=komissarov')).json;
  assert.ok(found.matching > 0 && found.items.every(i => /komissarov/i.test(JSON.stringify(i))));

  const nothing = (await c.call('GET', '/api/admin/audit?q=' + encodeURIComponent("%' OR 1=1 --"))).json;
  assert.equal(nothing.matching, 0, 'спецсимволы поиска не работают как шаблон или SQL');

  const critical = (await c.call('GET', '/api/admin/audit?critical=1&limit=200')).json;
  assert.ok(critical.items.length > 0 && critical.items.every(i => i.level === 'ALERT'));
  assert.ok(critical.critical24h > 0 && critical.lastCriticalAt);

  assert.equal((await c.call('GET', '/api/admin/audit?limit=999999&offset=-5')).status, 200);
});

test('admin: сброс сеансов пользователя завершает его сеансы и попадает в журнал', async () => {
  const victim = client();
  await login(victim, { role: 'commander', identifier: 'ilyin', secret: 'Ilyin#2026' });
  assert.equal((await victim.call('GET', '/api/me')).status, 200);

  const admin = client();
  await loginAdmin(admin);
  const id = db.prepare("SELECT id FROM users WHERE login = 'ilyin'").get().id;
  const res = await admin.call('POST', `/api/admin/users/${id}/reset-sessions`);
  assert.equal(res.status, 200);
  assert.ok(res.json.closed >= 1);
  assert.equal((await victim.call('GET', '/api/me')).status, 401);

  const entry = (await admin.call('GET', '/api/admin/audit?q=admin_session_reset')).json.items[0];
  assert.equal(entry.level, 'WARNING');
  assert.equal(entry.user.login, 'komissarov');
  assert.match(entry.details, /target:ilyin/);

  assert.equal((await admin.call('POST', '/api/admin/users/99999/reset-sessions')).status, 404);
  assert.equal((await admin.call('POST', '/api/admin/users/abc/reset-sessions')).status, 404);
  assert.equal((await admin.call('POST', `/api/admin/users/${id}/reset-sessions`, {}, { Origin: 'https://evil.example' })).status, 403);
});

test('миграция: база без роли admin обновляется с сохранением данных', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const file = `/tmp/legacy-${process.pid}.db`;
  for (const suffix of ['', '-wal', '-shm']) (await import('node:fs')).rmSync(file + suffix, { force: true });
  const legacy = new DatabaseSync(file);
  legacy.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, snils_digits TEXT UNIQUE, password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL, short_name TEXT NOT NULL, position TEXT NOT NULL, short_position TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('head', 'hq', 'commander')), employee_code TEXT, personnel_number TEXT, phone TEXT, email TEXT,
    department TEXT, appointment_order TEXT, clearance TEXT, workstation TEXT, failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER, is_active INTEGER NOT NULL DEFAULT 1)`);
  legacy.exec("INSERT INTO users (login, password_hash, full_name, short_name, position, short_position, role) VALUES ('old', 'x', 'А Б', 'А. Б.', 'п', 'п', 'head')");
  legacy.close();
  const migrated = openDb(file);
  assert.equal(migrated.prepare("SELECT login FROM users").get().login, 'old');
  migrated.prepare("INSERT INTO users (login, password_hash, full_name, short_name, position, short_position, role) VALUES ('new', 'x', 'В Г', 'В. Г.', 'п', 'п', 'admin')").run();
  assert.equal(migrated.prepare('SELECT COUNT(*) n FROM users').get().n, 2);
  migrated.close();
});
