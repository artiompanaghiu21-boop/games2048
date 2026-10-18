// Запуск: node server.js  (Node 18+). client_secret хранится только в переменных окружения сервера.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { CLIENT_ID, CLIENT_SECRET, PORT = 3000 } = process.env;
if (!CLIENT_ID || !CLIENT_SECRET) { console.error('Задайте CLIENT_ID и CLIENT_SECRET'); process.exit(1); }

const API = 'https://huevo.su/api/apps/v1';
const AUTH = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
const COST = 100;                 // цена возрождения в монэтках
const MAX_AGE = 24 * 3600;        // свежесть подписи запуска, с

const sessions = new Map();       // token -> { userId, test, exp }
// Таблица лидеров: userId -> { name, score }. Хранится в файле рядом с сервером.
const BOARD_FILE = path.join(__dirname, 'leaderboard.json');
const board = new Map();
try { for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(BOARD_FILE, 'utf8')))) board.set(Number(k), v); } catch {}
const saveBoard = () => { try { fs.writeFileSync(BOARD_FILE, JSON.stringify(Object.fromEntries(board))); } catch (e) { console.error(e.message); } };
const intents = new Map();        // intent_id -> { userId, used, busy }  (в продакшене — в БД)

// --- Проверка подписанных параметров запуска hu_* (docs: «Авторизация пользователя») ---
function verifyLaunch(query) {
  const params = Object.fromEntries(new URLSearchParams(query));
  const data = Object.keys(params).filter(k => k.startsWith('hu_') && k !== 'hu_hash')
    .sort().map(k => `${k}=${params[k]}`).join('\n');
  const key = crypto.createHash('sha256').update(CLIENT_SECRET).digest(); // бинарный дайджест
  const expected = crypto.createHmac('sha256', key).update(data).digest('hex');
  const given = params.hu_hash || '';
  if (!given) { console.log('login: в адресе нет hu_hash. Найдены параметры:', Object.keys(params).join(',') || 'никаких'); return null; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given))) {
    console.log('login: подпись не совпала. Длина CLIENT_SECRET на сервере =', CLIENT_SECRET.length, '(лишний пробел или кавычки меняют длину)');
    return null;
  }
  const age = Date.now() / 1000 - Number(params.hu_ts);
  if (!(age >= 0 && age <= MAX_AGE)) { console.log('login: подпись устарела, возраст, с:', Math.round(age)); return null; }
  return params;
}

// --- Вызов huEVO Apps API ---
async function huevo(method, p, body) {
  const r = await fetch(API + p, {
    method,
    headers: { Authorization: AUTH, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 429) throw new Error('rate_limited, Retry-After=' + r.headers.get('retry-after'));
  const j = await r.json();
  if (!j.ok) throw new Error((j.error && j.error.code) || 'huevo_error');
  return j;
}

const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const readJson = req => new Promise(ok => {
  const c = []; req.on('data', d => c.push(d));
  req.on('end', () => { try { ok(JSON.parse(Buffer.concat(c).toString() || '{}')) } catch { ok({}) } });
});
function session(req) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  const s = sessions.get(t);
  return s && s.exp > Date.now() ? s : null;
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
    }

    // 1. Вход: проверяем подпись, выдаём свой токен сеанса
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { query } = await readJson(req);
      const p = verifyLaunch(String(query || ''));
      if (!p) return send(res, 401, { ok: false });
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, { userId: Number(p.hu_user_id), name: String(p.hu_display_name || p.hu_username || 'Игрок').slice(0, 40), test: p.hu_mode === 'test', exp: Date.now() + MAX_AGE * 1000 });
      return send(res, 200, { ok: true, token });
    }

    const s = session(req);

    // Таблица лидеров: топ-10 и место текущего игрока
    if (req.method === 'GET' && url.pathname === '/api/leaderboard') {
      const all = [...board.entries()].sort((a, b) => b[1].score - a[1].score);
      const top = all.slice(0, 10).map(([id, e]) => ({ name: e.name, score: e.score, me: !!s && s.userId === id }));
      let mine = null;
      if (s) { const i = all.findIndex(([id]) => id === s.userId); if (i >= 0) mine = { rank: i + 1, score: all[i][1].score }; }
      return send(res, 200, { ok: true, top, mine });
    }

    if (!s) return send(res, 401, { ok: false });

    // Сохраняем лучший счёт игрока
    if (req.method === 'POST' && url.pathname === '/api/score') {
      const { score } = await readJson(req);
      if (!Number.isInteger(score) || score < 0 || score > 4000000) return send(res, 400, { ok: false });
      const cur = board.get(s.userId);
      if (!cur || score > cur.score) { board.set(s.userId, { name: s.name, score }); saveBoard(); }
      return send(res, 200, { ok: true });
    }

    // 2. Создаём намерение оплаты (POST /payments)
    if (req.method === 'POST' && url.pathname === '/api/revive/start') {
      const p = await huevo('POST', '/payments', {
        user_id: s.userId,
        amount: COST,
        description: 'Возрождение в игре 2048',
        idempotency_key: 'rv_' + crypto.randomUUID(),
        test: s.test,
      });
      intents.set(p.intent_id, { userId: s.userId, used: false, busy: false });
      return send(res, 200, { ok: true, intent_id: p.intent_id });
    }

    // 3. Статус: источник истины — GET /payments/{intent_id}. Возрождение выдаётся один раз.
    if (req.method === 'GET' && url.pathname === '/api/revive/status') {
      const id = url.searchParams.get('intent_id');
      const it = intents.get(id);
      if (!it || it.userId !== s.userId) return send(res, 404, { ok: false });
      if (it.used) return send(res, 200, { ok: true, status: 'used' });
      if (it.busy) return send(res, 200, { ok: true, status: 'pending' });
      it.busy = true;
      try {
        const p = await huevo('GET', '/payments/' + encodeURIComponent(id));
        if (p.status === 'succeeded' && p.amount === COST && p.user_id === it.userId) {
          it.used = true;
          return send(res, 200, { ok: true, status: 'succeeded', granted: true });
        }
        return send(res, 200, { ok: true, status: p.status, error: p.error });
      } finally { it.busy = false; }
    }
    send(res, 404, { ok: false });
  } catch (e) {
    console.error(e.message);
    send(res, 500, { ok: false });
  }
}).listen(PORT, () => console.log('http://localhost:' + PORT));
