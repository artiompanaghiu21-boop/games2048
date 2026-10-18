// Запуск: node server.js  (нужен Node 18+). Секрет клиента хранится ТОЛЬКО здесь, в .env
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { CLIENT_ID, CLIENT_SECRET, PORT = 3000, PUBLIC_URL } = process.env;
const API = 'https://huevo.su/api/apps/v1';
const AUTH = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
const COST = 100;

// intent_id -> 'pending' | 'paid' | 'declined' | 'used'. Для продакшена храните в БД.
const intents = new Map();

async function huevo(p, body) {
  const r = await fetch(API + p, {
    method: 'POST',
    headers: { Authorization: AUTH, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (r.status === 429) throw new Error('Лимит запросов, повтор через ' + r.headers.get('retry-after') + ' с');
  const j = await r.json();
  if (!j.ok) throw new Error((j.error && j.error.message) || 'Ошибка huevo');
  return j;
}

// Подпись: HMAC-SHA256 тела, ключ = sha256(client_secret). Формат ключа в скриншоте не уточнён,
// поэтому проверяем оба варианта (hex-строка и сырые байты).
function validSignature(raw, header) {
  if (!header) return false;
  const given = String(header).replace(/^sha256=/i, '').toLowerCase();
  const h = crypto.createHash('sha256').update(CLIENT_SECRET);
  const keyBytes = h.copy().digest(), keyHex = h.digest('hex');
  return [keyBytes, keyHex].some(k => {
    const calc = crypto.createHmac('sha256', k).update(raw).digest('hex');
    return calc.length === given.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(given));
  });
}

const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(ok => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => ok(Buffer.concat(c))); });

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
    }

    // 1. Игрок нажал «Возродиться» -> создаём платёж
    if (req.method === 'POST' && url.pathname === '/api/revive/start') {
      // TODO: путь и поля уточните в документации huevo (раздел «Кошелёк» / платежи)
      const j = await huevo('/payments/intents', {
        amount: COST,
        description: 'Возрождение в 2048',
        callback_url: PUBLIC_URL + '/huevo/callback',
      });
      intents.set(j.intent_id, 'pending');
      return send(res, 200, { ok: true, intent_id: j.intent_id, pay_url: j.pay_url });
    }

    // 2. Callback от huevo после решения игрока
    if (req.method === 'POST' && url.pathname === '/huevo/callback') {
      const raw = await readBody(req);
      if (!validSignature(raw, req.headers['x-huevo-signature'])) return send(res, 401, { ok: false });
      const d = JSON.parse(raw.toString());
      // TODO: названия полей (intent_id, status) сверьте с документацией
      const id = d.intent_id;
      if (intents.get(id) === 'pending') intents.set(id, d.status === 'paid' ? 'paid' : 'declined');
      return send(res, 200, { ok: true }); // повторы безопасны: пересчитываем по intent_id
    }

    // 3. Браузер опрашивает статус; «paid» отдаётся один раз
    if (req.method === 'GET' && url.pathname === '/api/revive/status') {
      const id = url.searchParams.get('intent_id');
      const st = intents.get(id) || 'unknown';
      if (st === 'paid') intents.set(id, 'used');
      return send(res, 200, { ok: true, status: st });
    }
    send(res, 404, { ok: false });
  } catch (e) {
    console.error(e.message);
    send(res, 500, { ok: false, error: 'server_error' });
  }
}).listen(PORT, () => console.log('http://localhost:' + PORT));
