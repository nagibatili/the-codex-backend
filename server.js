// ── The Codex — backend (пример) ──────────────────────────────────────────
// Минимальный сервер: регистрация, вход, продление подписки по вебхуку от
// платёжки. Хранит данные в обычном JSON-файле (db.json) — специально без
// "тяжёлых" зависимостей с компиляцией (как better-sqlite3), чтобы npm install
// через ISPmanager отрабатывал без проблем на любом хостинге.
//
// Установка (через ISPmanager: кнопка «Npm install» сделает это сама):
//   npm install
// Запуск (через ISPmanager: обработчик сайта = Node.js, он запустит сам):
//   npm start

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

// ── "База данных" — один JSON-файл ─────────────────────────────────────────
const DB_PATH = path.join(__dirname, 'db.json');
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

// ── РЕГИСТРАЦИЯ ───────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
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
});

// ── ВХОД (main.js вызывает это вместо чтения локального users.json) ───────
app.post('/login', async (req, res) => {
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
});

// ── ПРОВЕРКА ПОДПИСКИ (можно дёргать раз в час, пока оверлей открыт) ───────
app.get('/check-subscription', (req, res) => {
  const db = loadDb();
  const login = (req.query.login || '').toLowerCase();
  const user = db.users.find(u => u.login === login);
  if (!user) return res.status(404).json({ ok: false, error: 'Не найдено.' });
  const active = !!user.subscriptionUntil && new Date(user.subscriptionUntil) > new Date();
  res.json({ ok: true, active, subscriptionUntil: user.subscriptionUntil });
});

// ── ВЕБХУК ОТ ПЛАТЁЖКИ ─────────────────────────────────────────────────────
// Провайдер (ЮKassa / Robokassa) стучится сюда сам после успешной оплаты.
app.post('/webhook/payment', (req, res) => {
  // ⚠️ ЗАМЕНИТЕ на реальную проверку подписи/источника вашей платёжки —
  // без неё кто угодно сможет "продлить" себе подписку одним запросом.
  if (!verifyWebhookSignature(req)) return res.status(400).send('bad signature');

  const { login, plan, providerId, amount } = req.body || {};
  const days = PLAN_DAYS[plan];
  if (!login || !days) return res.status(400).send('bad payload');

  const db = loadDb();

  // Защита от повторной обработки одного и того же платежа (провайдеры иногда
  // присылают вебхук повторно).
  if (providerId && db.payments.some(p => p.providerId === providerId)) {
    return res.send('OK');
  }

  const user = db.users.find(u => u.login === login.toLowerCase());
  if (!user) return res.status(404).send('user not found');

  // Если подписка ещё активна — продлеваем ОТ ДАТЫ ОКОНЧАНИЯ, а не от "сейчас",
  // чтобы досрочное продление не "сжигало" уже оплаченные дни.
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

  res.send('OK'); // провайдеры обычно ждут 200/"OK" как подтверждение обработки
});

function verifyWebhookSignature(req) {
  // TODO: подставьте проверку под вашу платёжку. Пока — заглушка, которая
  // ничего не проверяет, поэтому эндпоинт нельзя открывать в production как есть.
  return true;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`The Codex backend слушает порт ${PORT}`));
