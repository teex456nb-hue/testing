"""Сервер сайта MTA Ukraine RP: только стандартная библиотека Python 3.10+.
Запуск: python server.py  ->  http://localhost:8080
Переменные окружения: PORT, DB_PATH, ADMIN_NICK, PAYMENTS_TEST (1/0), COOKIE_SECURE (1 за HTTPS)."""
import hashlib, hmac, json, os, re, secrets, sqlite3, time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).parent
DB = os.getenv("DB_PATH", str(BASE / "site.db"))
PORT = int(os.getenv("PORT", "8080"))
ADMIN_NICK = os.getenv("ADMIN_NICK", "").strip().lower()
PAYMENTS_TEST = os.getenv("PAYMENTS_TEST", "1") == "1"
SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
# Цены только здесь: клиенту доверять нельзя
PACKAGES = {"start": ("Стартовый", 100, 10000), "standard": ("Стандарт", 250, 30000), "premium": ("Премиум", 500, 75000)}
FACTIONS = {"zsu", "police", "medic"}
NICK_RE = re.compile(r"^[\w\-]{3,20}$")
_hits: dict[str, list[float]] = {}


def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(key TEXT PRIMARY KEY, nick TEXT, salt TEXT, hash TEXT, created TEXT, admin INTEGER, balance INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS chars(id TEXT PRIMARY KEY, user_key TEXT, faction TEXT, name TEXT, rank_i INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS apps(id TEXT PRIMARY KEY, user_key TEXT, faction TEXT, name TEXT, age INTEGER, about TEXT, status TEXT, date TEXT);
        CREATE TABLE IF NOT EXISTS donations(id TEXT PRIMARY KEY, user_key TEXT, name TEXT, price INTEGER, date TEXT);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_key TEXT, expires REAL);
        """)


today = lambda: datetime.now(timezone.utc).strftime("%d.%m.%Y")
uid = lambda: secrets.token_hex(4)
pw_hash = lambda pw, salt: hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def user_json(c, key):
    u = c.execute("SELECT * FROM users WHERE key=?", (key,)).fetchone()
    out = {
        "nick": u["nick"], "admin": bool(u["admin"]), "created": u["created"], "balance": u["balance"],
        "chars": [{"id": r["id"], "faction": r["faction"], "name": r["name"], "rank": r["rank_i"]}
                  for r in c.execute("SELECT * FROM chars WHERE user_key=?", (key,))],
        "apps": [dict(id=r["id"], faction=r["faction"], name=r["name"], age=r["age"], about=r["about"], status=r["status"], date=r["date"])
                 for r in c.execute("SELECT * FROM apps WHERE user_key=? ORDER BY rowid", (key,))],
        "donations": [dict(name=r["name"], price=r["price"], date=r["date"])
                      for r in c.execute("SELECT * FROM donations WHERE user_key=? ORDER BY rowid", (key,))],
    }
    if u["admin"]:
        out["pending"] = [
            {"k": r["user_key"], "nick": r["nick"], "a": dict(id=r["id"], faction=r["faction"], name=r["name"], age=r["age"], about=r["about"])}
            for r in c.execute("SELECT a.*, u.nick FROM apps a JOIN users u ON u.key=a.user_key WHERE a.status='pending' ORDER BY a.rowid")]
    return out


class Err(Exception):
    def __init__(self, msg, code=400):
        self.msg, self.code = msg, code


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj=None, body=None, ctype="application/json; charset=utf-8", cookie=None):
        data = body if body is not None else json.dumps(obj or {}, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def session_key(self, c):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        if "sid" not in ck:
            return None
        r = c.execute("SELECT user_key FROM sessions WHERE token=? AND expires>?", (ck["sid"].value, time.time())).fetchone()
        return r["user_key"] if r else None

    def start_session(self, c, key):
        t = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (t, key, time.time() + 30 * 86400))
        return f"sid={t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000" + ("; Secure" if SECURE else "")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self.reply(200, body=(BASE / "index.html").read_bytes(), ctype="text/html; charset=utf-8")
        if self.path == "/api/me":
            with db() as c:
                k = self.session_key(c)
                return self.reply(200, {"user": user_json(c, k) if k else None})
        self.reply(404, {"error": "Не найдено"})

    def do_POST(self):
        try:
            if "application/json" not in self.headers.get("Content-Type", ""):
                raise Err("Неверный запрос")
            n = int(self.headers.get("Content-Length", 0))
            if n > 10_000:
                raise Err("Слишком большой запрос", 413)
            d = json.loads(self.rfile.read(n) or b"{}")
            route = self.path.removeprefix("/api/")
            with db() as c:
                cookie = self.dispatch(c, route, d)
                k = self.session_key(c) if not cookie else cookie[1]
                user = user_json(c, k) if k else None
            self.reply(200, {"user": user}, cookie=cookie[0] if cookie else None)
        except Err as e:
            self.reply(e.code, {"error": e.msg})
        except (ValueError, KeyError, TypeError):
            self.reply(400, {"error": "Неверный запрос"})

    def dispatch(self, c, route, d):
        """Возвращает (set-cookie, user_key) для входа/регистрации, иначе None."""
        if route in ("register", "login"):
            ip = self.client_address[0]
            hits = [t for t in _hits.get(ip, []) if t > time.time() - 60]
            if len(hits) >= 10:
                raise Err("Слишком много попыток, подожди минуту", 429)
            _hits[ip] = hits + [time.time()]
            nick, pw = str(d["nick"]).strip(), str(d["pass"])
            key = nick.lower()
            if route == "register":
                if not NICK_RE.match(nick): raise Err("Ник: 3–20 символов, буквы, цифры, «_» и «-».")
                if len(pw) < 6: raise Err("Пароль должен быть не короче 6 символов.")
                if c.execute("SELECT 1 FROM users WHERE key=?", (key,)).fetchone(): raise Err("Такой ник уже занят.", 409)
                first = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                salt = secrets.token_hex(16)
                c.execute("INSERT INTO users VALUES(?,?,?,?,?,?,0)", (key, nick, salt, pw_hash(pw, salt), today(), int(first or key == ADMIN_NICK)))
            else:
                u = c.execute("SELECT * FROM users WHERE key=?", (key,)).fetchone()
                if not u or not hmac.compare_digest(u["hash"], pw_hash(pw, u["salt"])): raise Err("Неверный ник или пароль.", 401)
            return self.start_session(c, key), key

        if route == "logout":
            ck = SimpleCookie(self.headers.get("Cookie", ""))
            if "sid" in ck: c.execute("DELETE FROM sessions WHERE token=?", (ck["sid"].value,))
            return "sid=; HttpOnly; Path=/; Max-Age=0", None

        key = self.session_key(c)
        if not key: raise Err("Нужно войти в аккаунт", 401)

        if route == "apply":
            f, name, age = d["faction"], str(d["name"]).strip(), int(d["age"])
            if f not in FACTIONS: raise Err("Неизвестная фракция")
            if len(name) < 5 or " " not in name or len(name) > 40: raise Err("Укажи имя и фамилию персонажа.")
            if not 18 <= age <= 80: raise Err("Возраст персонажа: от 18 до 80.")
            if c.execute("SELECT 1 FROM chars WHERE user_key=? AND faction=?", (key, f)).fetchone(): raise Err("Персонаж в этой фракции уже есть")
            if c.execute("SELECT 1 FROM apps WHERE user_key=? AND faction=? AND status='pending'", (key, f)).fetchone(): raise Err("Заявка уже на рассмотрении")
            c.execute("INSERT INTO apps VALUES(?,?,?,?,?,?,'pending',?)", (uid(), key, f, name, age, str(d.get("about", ""))[:500], today()))
        elif route == "decide":
            if not c.execute("SELECT admin FROM users WHERE key=?", (key,)).fetchone()["admin"]: raise Err("Нет доступа", 403)
            if d["decision"] not in ("accepted", "rejected"): raise Err("Неверное решение")
            a = c.execute("SELECT * FROM apps WHERE id=? AND user_key=? AND status='pending'", (d["id"], d["key"])).fetchone()
            if not a: raise Err("Заявка не найдена или уже обработана", 404)
            c.execute("UPDATE apps SET status=? WHERE id=?", (d["decision"], a["id"]))
            if d["decision"] == "accepted" and not c.execute("SELECT 1 FROM chars WHERE user_key=? AND faction=?", (a["user_key"], a["faction"])).fetchone():
                c.execute("INSERT INTO chars VALUES(?,?,?,?,0)", (uid(), a["user_key"], a["faction"], a["name"]))
        elif route == "buy":
            if not PAYMENTS_TEST: raise Err("Оплата ещё не подключена", 501)
            p = PACKAGES.get(d["id"])
            if not p: raise Err("Пакет не найден", 404)
            c.execute("UPDATE users SET balance=balance+? WHERE key=?", (p[2], key))
            c.execute("INSERT INTO donations VALUES(?,?,?,?,?)", (uid(), key, p[0], p[1], today()))
        else:
            raise Err("Не найдено", 404)
        return None


if __name__ == "__main__":
    init()
    print(f"Сайт: http://localhost:{PORT}  (тестовые платежи: {'ВКЛ' if PAYMENTS_TEST else 'выкл'})")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
