import './check-node.js';
import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { createApp } from './app.js';

const config = loadConfig();
const db = openDb(config.dbPath);

const users = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
if (users === 0) {
  console.warn('В базе нет пользователей. Выполните: npm run seed');
}

const server = createApp({ db, config }).listen(config.port, config.host, () => {
  console.log(`АСУ ГО и ЧС: http://${config.host}:${config.port}  (база: ${config.dbPath})`);
});

// Корректное завершение: закрываем сервер и базу.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => { db.close(); process.exit(0); }));
}
