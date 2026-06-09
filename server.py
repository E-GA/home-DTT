import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import uuid
from datetime import date
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
SESSION_COOKIE = "cal_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60
MAX_BODY_BYTES = 20_000


def load_env_file():
    env_path = ROOT / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or "=" not in value:
            continue

        key, raw = value.split("=", 1)
        key = key.strip()
        raw = raw.strip()
        if not key or key in os.environ:
            continue

        if (raw.startswith('"') and raw.endswith('"')) or (
            raw.startswith("'") and raw.endswith("'")
        ):
            raw = raw[1:-1]

        os.environ[key] = raw


load_env_file()

PASSCODE = os.environ.get("CALENDAR_PASSCODE", "")
SESSION_SECRET = os.environ.get("CALENDAR_SESSION_SECRET") or secrets.token_hex(32)
COOKIE_SECURE = os.environ.get("COOKIE_SECURE") == "true"
PORT = int(os.environ.get("PORT", "3000"))
DATA_FILE_NAME = os.environ.get("CALENDAR_EVENTS_FILE", "calendar-events.json")
DATA_FILE = Path(DATA_FILE_NAME)
if not DATA_FILE.is_absolute():
    DATA_FILE = ROOT / DATA_FILE

if not PASSCODE:
    print(
        "Missing CALENDAR_PASSCODE. Put it in .env or set it as an environment variable.",
        file=sys.stderr,
    )
    sys.exit(1)


class CalendarHandler(BaseHTTPRequestHandler):
    server_version = "CalendarServer/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/events":
            self.send_json(200, {"events": read_events()})
            return

        if parsed.path == "/api/auth":
            self.send_json(200, {"authenticated": self.is_authenticated()})
            return

        self.serve_index(parsed.path, include_body=True)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        self.serve_index(parsed.path, include_body=False)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/login":
            body = self.read_json()
            if not secure_passcode_match(body.get("code", "")):
                self.send_json(401, {"error": "รหัสไม่ถูกต้อง"})
                return

            self.send_json(
                200,
                {"ok": True},
                {"Set-Cookie": build_session_cookie(create_session_token())},
            )
            return

        if parsed.path == "/api/logout":
            self.send_json(200, {"ok": True}, {"Set-Cookie": clear_session_cookie()})
            return

        if parsed.path == "/api/events":
            if not self.require_auth():
                return

            body = self.read_json()
            event = validate_event_input(body)
            if not event["ok"]:
                self.send_json(400, {"error": event["error"]})
                return

            events = read_events()
            events.setdefault(event["key"], [])
            events[event["key"]].append(
                {
                    "id": str(uuid.uuid4()),
                    "title": event["title"],
                    "time": event["time"],
                    "color": event["color"],
                }
            )
            events[event["key"]].sort(key=event_sort_key)
            write_events(events)
            self.send_json(200, {"events": events})
            return

        self.send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)

        if parsed.path != "/api/events":
            self.send_json(404, {"error": "Not found"})
            return

        if not self.require_auth():
            return

        result = delete_event(self.read_json())
        if not result["ok"]:
            self.send_json(result.get("status", 400), {"error": result["error"]})
            return

        self.send_json(200, {"events": result["events"]})

    def serve_index(self, path, include_body):
        if path not in ("/", "/index.html"):
            self.send_text(404, "Not found")
            return

        body = (ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0

        if length > MAX_BODY_BYTES:
            return {}

        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}

        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def require_auth(self):
        if self.is_authenticated():
            return True

        self.send_json(401, {"error": "ต้องยืนยันรหัสก่อน"})
        return False

    def is_authenticated(self):
        cookie_header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(cookie_header)
        except cookies.CookieError:
            return False

        morsel = jar.get(SESSION_COOKIE)
        return bool(morsel and verify_session_token(morsel.value))

    def send_json(self, status, data, headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status, message):
        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def read_events():
    if not DATA_FILE.exists():
        return {}

    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    return normalize_events(data)


def write_events(events):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = DATA_FILE.with_name(f"{DATA_FILE.name}.{os.getpid()}.tmp")
    temp_file.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_file, DATA_FILE)


def normalize_events(events):
    clean = {}
    for key, value in events.items():
        if not is_valid_date_key(key) or not isinstance(value, list):
            continue

        items = []
        for event in value:
            if not isinstance(event, dict):
                continue

            title = str(event.get("title", ""))[:120].strip()
            if not title:
                continue

            raw_color = event.get("color", 1)
            try:
                color = int(raw_color)
            except (TypeError, ValueError):
                color = 1

            time_value = str(event.get("time", "")).strip()
            items.append(
                {
                    "id": str(event.get("id") or uuid.uuid4()),
                    "title": title,
                    "time": time_value if is_valid_time(time_value) else "",
                    "color": color if color in (1, 2, 3, 4) else 1,
                }
            )

        if items:
            clean[key] = sorted(items, key=event_sort_key)

    return clean


def validate_event_input(body):
    key = str(body.get("key", ""))
    title = str(body.get("title", "")).strip()
    time_value = str(body.get("time", "")).strip()

    try:
        color = int(body.get("color", 1))
    except (TypeError, ValueError):
        color = 1

    if not is_valid_date_key(key):
        return {"ok": False, "error": "วันที่ไม่ถูกต้อง"}
    if not title:
        return {"ok": False, "error": "กรุณากรอกชื่อกิจกรรม"}
    if len(title) > 120:
        return {"ok": False, "error": "ชื่อกิจกรรมยาวเกินไป"}
    if time_value and not is_valid_time(time_value):
        return {"ok": False, "error": "เวลาไม่ถูกต้อง"}
    if color not in (1, 2, 3, 4):
        return {"ok": False, "error": "สีไม่ถูกต้อง"}

    return {"ok": True, "key": key, "title": title, "time": time_value, "color": color}


def delete_event(body):
    key = str(body.get("key", ""))
    if not is_valid_date_key(key):
        return {"ok": False, "error": "วันที่ไม่ถูกต้อง"}

    events = read_events()
    items = events.get(key, [])
    event_id = body.get("id") if isinstance(body.get("id"), str) else ""
    index = next((i for i, event in enumerate(items) if event["id"] == event_id), -1)

    if index == -1 and isinstance(body.get("index"), int):
        index = body["index"]

    if index < 0 or index >= len(items):
        return {"ok": False, "status": 404, "error": "ไม่พบกิจกรรม"}

    items.pop(index)
    if items:
        events[key] = sorted(items, key=event_sort_key)
    elif key in events:
        del events[key]

    write_events(events)
    return {"ok": True, "events": events}


def event_sort_key(event):
    return event.get("time") or "99:99"


def is_valid_date_key(key):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", key):
        return False

    year, month, day = [int(part) for part in key.split("-")]
    try:
        date(year, month, day)
    except ValueError:
        return False

    return True


def is_valid_time(value):
    return bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(value or "")))


def secure_passcode_match(value):
    return hmac.compare_digest(passcode_digest(value), passcode_digest(PASSCODE))


def passcode_digest(value):
    return hashlib.sha256(str(value).encode("utf-8")).digest()


def create_session_token():
    expires_at = str(int(time.time()) + SESSION_MAX_AGE_SECONDS)
    nonce = secrets.token_hex(16)
    payload = f"{expires_at}.{nonce}"
    return f"{payload}.{sign(payload)}"


def verify_session_token(token):
    parts = str(token).split(".")
    if len(parts) != 3:
        return False

    expires_at, nonce, signature = parts
    try:
        if int(expires_at) < int(time.time()):
            return False
    except ValueError:
        return False

    payload = f"{expires_at}.{nonce}"
    return hmac.compare_digest(signature, sign(payload))


def sign(payload):
    return hmac.new(
        SESSION_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_session_cookie(token):
    flags = [
        f"{SESSION_COOKIE}={token}",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        f"Max-Age={SESSION_MAX_AGE_SECONDS}",
    ]
    if COOKIE_SECURE:
        flags.append("Secure")
    return "; ".join(flags)


def clear_session_cookie():
    return f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


def main():
    server = ThreadingHTTPServer(("", PORT), CalendarHandler)
    print(f"Calendar server running at http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
