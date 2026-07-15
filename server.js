// ── The Codex — backend (пример) ──────────────────────────────────────────
// Минимальный сервер: регистрация, вход, продление подписки по вебхуку от
// платёжки. Хранит данные в обычном JSON-файле (db.json) — без "тяжёлых"
// зависимостей с компиляцией, чтобы npm install отрабатывал без проблем
// на любом хостинге (в т.ч. Railway/ISPmanager).
//
// ВАЖНО про Express 4: если внутри async-обработчика происходит ошибка и она
// не поймана вручную — Express НЕ отправляет никакого ответа вообще, запрос
// просто зависает навсегда на стороне клиента. Поэтому каждый обработчик
// здесь обёрнут в asyncHandler(), который гарантированно шлёт JSON-ошибку,
// даже если что-то пошло не так.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());              // Electron-клиент шлёт запросы без обычного браузерного Origin —
app.use(express.json());      // разрешаем всем; при желании сузьте allowlist по домену сайта.

// Оборачивает async-обработчик так, чтобы любая ошибка (включая отклонённый
// промис) гарантированно превращалась в JSON-ответ 500, а не в зависший запрос.
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// ── "База данных" — один JSON-файл ─────────────────────────────────────────
// ⚠️ На Railway файловая система по умолчанию ЭФЕМЕРНАЯ: db.json будет
// обнуляться при каждом новом деплое. Для реального продакшена подключите
// Railway Volume (Settings → Volumes) и укажите DB_PATH на путь внутри него,
// либо перейдите на настоящую БД (Postgres как плагин Railway). Для теста
// сейчас — сойдёт и так.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db.json');

function loadDb() {
  if (!fs.existsSync(DB_PATH)) return { users: [], payments: [] };
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch (e) { return { users: [], payments: [] }; }
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

const PLAN_DAYS  = { '1m': 30, '6m': 183, '12m': 365 };
const PLAN_PRICE = { '1m': 150, '6m': 600, '12m': 1500 };

// ── ПРОВЕРКА ЖИВОСТИ ────────────────────────────────────────────────────────
// Открыть в браузере https://api.the-codex.ru/health — если видно "ok:true",
// сервер и диск (запись файла) работают.
app.get('/health', asyncHandler(async (req, res) => {
  const testPath = path.join(path.dirname(DB_PATH), '.write-test');
  try {
    fs.writeFileSync(testPath, 'ok');
    fs.unlinkSync(testPath);
    res.json({ ok: true, diskWritable: true, dbPath: DB_PATH, node: process.version });
  } catch (e) {
    res.json({ ok: true, diskWritable: false, error: e.message, dbPath: DB_PATH, node: process.version });
  }
}));

// ── РЕГИСТРАЦИЯ ───────────────────────────────────────────────────────────
app.post('/register', asyncHandler(async (req, res) => {
  const { login, email, password } = req.body || {};
  if (!login || !email || !password || password.length < 6) {
    return res.status(400).json({ ok: false, error: 'Проверьте поля формы (пароль от 6 символов).' });
  }
  const db = loadDb();
  const loginLc = login.toLowerCase(), emailLc = email.toLowerCase();
  if (db.users.some(u => u.login === loginLc || u.email === emailLc)) {
    return res.status(409).json({ ok: false, error: 'Такой логин или e-mail уже зарегистрирован.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  db.users.push({
    id: crypto.randomUUID(),
    login: loginLc,
    email: emailLc,
    passwordHash,
    deviceId: null,
    subscriptionUntil: null,   // NULL = доступа к приложению ещё нет
    createdAt: new Date().toISOString()
  });
  saveDb(db);
  res.json({ ok: true });
}));

// ── ВХОД (main.js вызывает это вместо чтения локального users.json) ───────
app.post('/login', asyncHandler(async (req, res) => {
  const { login, password, deviceId } = req.body || {};
  const db = loadDb();
  const user = db.users.find(u => u.login === (login || '').toLowerCase());
  if (!user) return res.status(401).json({ ok: false, error: 'Пользователь не найден.' });

  const valid = await bcrypt.compare(password || '', user.passwordHash);
  if (!valid) return res.status(401).json({ ok: false, error: 'Неверный пароль.' });

  if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    return res.status(403).json({ ok: false, error: 'Аккаунт привязан к другому устройству.' });
  }
  if (!user.deviceId && deviceId) { user.deviceId = deviceId; saveDb(db); }

  const active = !!user.subscriptionUntil && new Date(user.subscriptionUntil) > new Date();
  if (!active) {
    // Сервер, а не клиент, решает — истекла подписка или нет.
    return res.status(402).json({
      ok: false,
      error: 'Подписка не активна.',
      subscriptionExpired: true,
      subscriptionUntil: user.subscriptionUntil,
      renewUrl: `https://the-codex.ru/#pricing`
    });
  }
  res.json({ ok: true, subscriptionUntil: user.subscriptionUntil });
}));

// ── ПРОВЕРКА ПОДПИСКИ (можно дёргать раз в час, пока оверлей открыт) ───────
app.get('/check-subscription', asyncHandler(async (req, res) => {
  const db = loadDb();
  const login = (req.query.login || '').toLowerCase();
  const user = db.users.find(u => u.login === login);
  if (!user) return res.status(404).json({ ok: false, error: 'Не найдено.' });
  const active = !!user.subscriptionUntil && new Date(user.subscriptionUntil) > new Date();
  res.json({ ok: true, active, subscriptionUntil: user.subscriptionUntil });
}));

// ── ВЕБХУК ОТ ПЛАТЁЖКИ ─────────────────────────────────────────────────────
// Провайдер (ЮKassa / Robokassa) стучится сюда сам после успешной оплаты.
app.post('/webhook/payment', asyncHandler(async (req, res) => {
  // ⚠️ ЗАМЕНИТЕ на реальную проверку подписи/источника вашей платёжки —
  // без неё кто угодно сможет "продлить" себе подписку одним запросом.
  if (!verifyWebhookSignature(req)) return res.status(400).send('bad signature');

  const { login, plan, providerId, amount } = req.body || {};
  const days = PLAN_DAYS[plan];
  if (!login || !days) return res.status(400).send('bad payload');

  const db = loadDb();

  if (providerId && db.payments.some(p => p.providerId === providerId)) {
    return res.send('OK');
  }

  const user = db.users.find(u => u.login === login.toLowerCase());
  if (!user) return res.status(404).send('user not found');

  const base = (user.subscriptionUntil && new Date(user.subscriptionUntil) > new Date())
    ? new Date(user.subscriptionUntil)
    : new Date();
  base.setDate(base.getDate() + days);
  user.subscriptionUntil = base.toISOString();

  db.payments.push({
    login: login.toLowerCase(), plan,
    amount: amount || PLAN_PRICE[plan] || 0,
    providerId: providerId || crypto.randomUUID(),
    createdAt: new Date().toISOString()
  });
  saveDb(db);

  res.send('OK');
}));

function verifyWebhookSignature(req) {
  // TODO: подставьте проверку под вашу платёжку.
  return true;
}

// ── Обработчик 404 для неизвестных путей ────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Такого маршрута нет.' });
});

// ── Глобальный обработчик ошибок — последняя страховка от "зависших" запросов ─
app.use((err, req, res, next) => {
  console.error('[unhandled]', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ ok: false, error: 'Внутренняя ошибка сервера: ' + err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`The Codex backend слушает порт ${PORT}, БД: ${DB_PATH}`));
