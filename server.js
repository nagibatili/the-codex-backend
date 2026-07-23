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

// ── Постоянные сессии по токену ────────────────────────────────────────────
// Чтобы не заставлять человека вводить пароль каждый раз, при успешном входе
// выдаём случайный токен и сохраняем его у пользователя. Дальше сайт может
// подтверждать личность токеном вместо пароля — токен живёт, пока не разлогинятся.
function issueToken(user) {
  user.token = crypto.randomUUID();
  return user.token;
}
function findUserByToken(db, token) {
  if (!token) return null;
  return db.users.find(u => u.token === token) || null;
}

// ── ЮKassa: базовые настройки ────────────────────────────────────────────
// Возьмите shopId и secretKey в личном кабинете ЮKassa (Настройки → API).
// Пока идёт проверка вашей заявки — там же доступны ТЕСТОВЫЕ ключи, можно
// проверить всё на фальшивых картах уже сейчас.
const YOOKASSA_SHOP_ID    = (process.env.YOOKASSA_SHOP_ID || '').trim();
const YOOKASSA_SECRET_KEY = (process.env.YOOKASSA_SECRET_KEY || '').trim();
const YOOKASSA_AUTH = 'Basic ' + Buffer.from(`${YOOKASSA_SHOP_ID}:${YOOKASSA_SECRET_KEY}`).toString('base64');
const SITE_URL = process.env.SITE_URL || 'https://the-codex.ru';

// ── EMAIL: подтверждение почты через Resend ────────────────────────────────
// Resend — сервис отправки писем (resend.com), бесплатный лимит хватает для
// старта. Возьмите API-ключ в личном кабинете Resend (Dashboard → API Keys)
// и впишите его в переменные окружения на Railway.
const RESEND_API_KEY = (process.env.RESEND_API_KEY || '').trim();
// Пока не подтвердите свой домен в Resend, отправлять можно только с этого
// служебного адреса — это ограничение Resend, а не наше. Как только домен
// подтверждён (Resend → Domains → Add the-codex.ru), замените на
// 'The Codex <noreply@the-codex.ru>'.
const EMAIL_FROM = process.env.EMAIL_FROM || 'The Codex <onboarding@resend.dev>';

async function sendVerificationEmail(email, code) {
  if (!RESEND_API_KEY) {
    console.warn(`[email] RESEND_API_KEY не задан — код для ${email}: ${code}`);
    return { ok: false, error: 'Отправка почты не настроена на сервере (нет RESEND_API_KEY).' };
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [email],
        subject: `Код подтверждения: ${code}`,
        html: `
          <div style="font-family:sans-serif;background:#05070d;color:#eef1f6;padding:32px;border-radius:14px">
            <h2 style="color:#4ade80;margin:0 0 12px">The Codex</h2>
            <p>Ваш код подтверждения e-mail:</p>
            <p style="font-size:32px;font-weight:700;letter-spacing:6px;color:#d8b073">${code}</p>
            <p style="color:#8a93a6;font-size:13px">Код действует 15 минут. Если вы не регистрировались на the-codex.ru — просто проигнорируйте это письмо.</p>
          </div>`
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.message || 'Resend отклонил отправку письма.' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Не удалось связаться с сервисом отправки почты.' };
  }
}

function makeVerificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 цифр
}


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
  const code = makeVerificationCode();
  const user = {
    id: crypto.randomUUID(),
    login: loginLc,
    email: emailLc,
    passwordHash,
    deviceId: null,
    token: null,
    emailVerified: false,
    emailCode: code,
    emailCodeExpires: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    emailCodeSentAt: new Date().toISOString(),
    subscriptionUntil: null,   // NULL = доступа к приложению ещё нет
    createdAt: new Date().toISOString()
  };
  issueToken(user);
  db.users.push(user);
  saveDb(db);

  const mail = await sendVerificationEmail(user.email, code);
  if (!mail.ok) console.warn('[register] письмо не отправлено:', mail.error);

  res.json({ ok: true, token: user.token, login: user.login, emailSendError: mail.ok ? null : mail.error });
}));

// ── ПОДТВЕРЖДЕНИЕ ПОЧТЫ ────────────────────────────────────────────────────
app.post('/verify-email', asyncHandler(async (req, res) => {
  const { token, code } = req.body || {};
  const db = loadDb();
  const user = findUserByToken(db, token);
  if (!user) return res.status(401).json({ ok: false, error: 'Сессия истекла, войдите заново.' });
  if (user.emailVerified) return res.json({ ok: true, alreadyVerified: true });

  if (!user.emailCode || !user.emailCodeExpires || new Date(user.emailCodeExpires) < new Date()) {
    return res.status(400).json({ ok: false, error: 'Код истёк. Запросите новый.' });
  }
  if (String(code || '').trim() !== user.emailCode) {
    return res.status(400).json({ ok: false, error: 'Неверный код.' });
  }

  user.emailVerified = true;
  user.emailCode = null;
  user.emailCodeExpires = null;
  saveDb(db);
  res.json({ ok: true });
}));

// ── ПОВТОРНАЯ ОТПРАВКА КОДА ─────────────────────────────────────────────────
app.post('/resend-code', asyncHandler(async (req, res) => {
  const { token } = req.body || {};
  const db = loadDb();
  const user = findUserByToken(db, token);
  if (!user) return res.status(401).json({ ok: false, error: 'Сессия истекла, войдите заново.' });
  if (user.emailVerified) return res.json({ ok: true, alreadyVerified: true });

  // Не чаще одного письма в 60 секунд — чтобы не заспамить почту и не упереться в лимит Resend.
  if (user.emailCodeSentAt && (Date.now() - new Date(user.emailCodeSentAt).getTime()) < 60000) {
    return res.status(429).json({ ok: false, error: 'Подождите минуту перед повторной отправкой.' });
  }

  const code = makeVerificationCode();
  user.emailCode = code;
  user.emailCodeExpires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  user.emailCodeSentAt = new Date().toISOString();
  saveDb(db);

  const mail = await sendVerificationEmail(user.email, code);
  if (!mail.ok) return res.status(502).json({ ok: false, error: mail.error });
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

  // Выдаём токен и приложению — пригодится для /logout и для будущих запросов
  // из самого приложения (например, к /account), не пересылая пароль повторно.
  const token = issueToken(user);
  saveDb(db);

  res.json({ ok: true, token, subscriptionUntil: user.subscriptionUntil });
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

// ── ЛИЧНЫЙ КАБИНЕТ: полная информация об аккаунте ─────────────────────────
// Принимает ЛИБО { token } (постоянная сессия — не нужен пароль), ЛИБО
// { login, password } (первый вход на новом устройстве/браузере).
app.post('/account', asyncHandler(async (req, res) => {
  const { login, password, token } = req.body || {};
  const db = loadDb();

  let user = null;
  if (token) {
    user = findUserByToken(db, token);
    if (!user) return res.status(401).json({ ok: false, error: 'Сессия истекла, войдите заново.' });
  } else {
    if (!login || !password) return res.status(400).json({ ok: false, error: 'Введите логин и пароль.' });
    user = db.users.find(u => u.login === login.toLowerCase());
    if (!user) return res.status(401).json({ ok: false, error: 'Пользователь не найден.' });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ ok: false, error: 'Неверный пароль.' });
  }

  issueToken(user); // продлеваем/выдаём токен при каждом успешном обращении
  saveDb(db);

  const active = !!user.subscriptionUntil && new Date(user.subscriptionUntil) > new Date();
  const payments = db.payments
    .filter(p => p.login === user.login)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({
    ok: true,
    token: user.token,
    login: user.login,
    email: user.email,
    emailVerified: !!user.emailVerified,
    createdAt: user.createdAt,
    active,
    subscriptionUntil: user.subscriptionUntil,
    deviceLinked: !!user.deviceId,
    payments
  });
}));

// ── ВЫХОД: аннулирует токен на сервере ────────────────────────────────────
app.post('/logout', asyncHandler(async (req, res) => {
  const { token } = req.body || {};
  const db = loadDb();
  const user = findUserByToken(db, token);
  if (user) { user.token = null; saveDb(db); }
  res.json({ ok: true });
}));

// ── СОЗДАНИЕ ПЛАТЕЖА (ЮKassa) ─────────────────────────────────────────────
// Фронтенд вызывает это, когда пользователь жмёт «Оплатить». Мы создаём
// платёж на стороне ЮKassa и возвращаем ссылку, куда браузер должен перейти —
// там ЮKassa сама покажет форму оплаты картой/СБП.
app.post('/create-payment', asyncHandler(async (req, res) => {
  if (!YOOKASSA_SHOP_ID || !YOOKASSA_SECRET_KEY) {
    return res.status(503).json({ ok: false, error: 'Оплата ещё не подключена на сервере (нет ключей ЮKassa).' });
  }
  const { login, password, token, plan } = req.body || {};
  const price = PLAN_PRICE[plan];
  if (!price) return res.status(400).json({ ok: false, error: 'Неизвестный тариф.' });

  const db = loadDb();
  let user = null;
  if (token) {
    user = findUserByToken(db, token);
    if (!user) return res.status(401).json({ ok: false, error: 'Сессия истекла, войдите заново.' });
  } else {
    if (!login || !password) return res.status(400).json({ ok: false, error: 'Проверьте логин и пароль.' });
    user = db.users.find(u => u.login === login.toLowerCase());
    if (!user) return res.status(401).json({ ok: false, error: 'Пользователь не найден.' });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ ok: false, error: 'Неверный пароль.' });
  }

  const ykRes = await fetch('https://api.yookassa.ru/v3/payments', {
    method: 'POST',
    headers: {
      'Authorization': YOOKASSA_AUTH,
      'Content-Type': 'application/json',
      'Idempotence-Key': crypto.randomUUID()
    },
    body: JSON.stringify({
      amount: { value: price.toFixed(2), currency: 'RUB' },
      capture: true,
      confirmation: { type: 'redirect', return_url: `${SITE_URL}/?paid=1` },
      description: `The Codex — тариф ${plan}`,
      metadata: { login: user.login, plan }
    })
  });
  const payment = await ykRes.json();
  if (!ykRes.ok) {
    return res.status(502).json({ ok: false, error: payment.description || 'ЮKassa отклонила запрос на оплату.' });
  }

  res.json({ ok: true, confirmationUrl: payment.confirmation.confirmation_url });
}));


// ── ВЕБХУК ОТ ЮKASSA ───────────────────────────────────────────────────────
// ЮKassa стучится сюда сама после изменения статуса платежа (event:
// "payment.succeeded"). Телу вебхука напрямую не доверяем — кто угодно может
// прислать сюда поддельный POST. Вместо этого берём id платежа из уведомления
// и переспрашиваем его статус напрямую у ЮKassa нашим secretKey — подделать
// такой ответ снаружи невозможно.
app.post('/webhook/payment', asyncHandler(async (req, res) => {
  const notification = req.body || {};
  const paymentId = notification.object && notification.object.id;
  if (!paymentId) return res.status(400).send('bad payload');

  // Не решаем по присланным данным — идём и спрашиваем у ЮKassa напрямую.
  const checkRes = await fetch(`https://api.yookassa.ru/v3/payments/${paymentId}`, {
    headers: { 'Authorization': YOOKASSA_AUTH }
  });
  const payment = await checkRes.json();
  if (!checkRes.ok || payment.status !== 'succeeded') {
    // Платёж ещё не подтверждён/отменён — ничего не продлеваем, просто отвечаем ОК,
    // чтобы ЮKassa не повторяла вебхук бесконечно.
    return res.send('OK');
  }

  const login = payment.metadata && payment.metadata.login;
  const plan  = payment.metadata && payment.metadata.plan;
  const days  = PLAN_DAYS[plan];
  if (!login || !days) return res.status(400).send('bad metadata');

  const db = loadDb();

  // Защита от повторной обработки одного и того же платежа — ЮKassa иногда
  // присылает уведомление больше одного раза.
  if (db.payments.some(p => p.providerId === paymentId)) {
    return res.send('OK');
  }

  const user = db.users.find(u => u.login === login);
  if (!user) return res.status(404).send('user not found');

  // Если подписка ещё активна — продлеваем ОТ ДАТЫ ОКОНЧАНИЯ, а не от "сейчас",
  // чтобы досрочное продление не "сжигало" уже оплаченные дни.
  const base = (user.subscriptionUntil && new Date(user.subscriptionUntil) > new Date())
    ? new Date(user.subscriptionUntil)
    : new Date();
  base.setDate(base.getDate() + days);
  user.subscriptionUntil = base.toISOString();

  db.payments.push({
    login, plan,
    amount: Number(payment.amount && payment.amount.value) || PLAN_PRICE[plan] || 0,
    providerId: paymentId,
    createdAt: new Date().toISOString()
  });
  saveDb(db);

  res.send('OK'); // ЮKassa ждёт 200 как подтверждение, что уведомление обработано
}));

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
