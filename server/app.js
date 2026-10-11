import express from 'express';
import { authRouter } from './routes/auth.js';
import { meRouter } from './routes/me.js';
import { adminRouter } from './routes/admin.js';

// style-src-attr 'unsafe-inline' нужен для inline-атрибутов style (ширина индикаторов).
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'"
].join('; ');

function securityHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin'
  });
  next();
}

// Запросы, меняющие состояние, принимаются только с нашего же сайта.
function sameOriginOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (req.get('sec-fetch-site') === 'cross-site') return res.status(403).json({ error: 'Запрос отклонён.' });

  const origin = req.get('origin');
  if (origin) {
    try {
      if (new URL(origin).host !== req.get('host')) throw new Error('foreign origin');
    } catch {
      return res.status(403).json({ error: 'Запрос отклонён.' });
    }
  }
  next();
}

export function createApp({ db, config }) {
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', config.trustProxy);

  app.use(securityHeaders);

  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  app.use('/api', sameOriginOnly, express.json({ limit: '10kb' }));
  app.use('/api/auth', authRouter({ db, config }));
  app.use('/api', meRouter({ db }));
  app.use('/api/admin', adminRouter({ db }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Не найдено.' }));

  // Отдаём только папку public: файл базы данных лежит вне её.
  app.use(express.static(config.publicDir, { dotfiles: 'ignore' }));

  app.use((error, req, res, next) => {
    if (error.type === 'entity.parse.failed') return res.status(400).json({ error: 'Некорректный запрос.' });
    if (error.type === 'entity.too.large') return res.status(413).json({ error: 'Слишком большой запрос.' });
    console.error(error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера.' });
  });

  return app;
}
