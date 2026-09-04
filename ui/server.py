#!/usr/bin/env python3
"""
INJ Control Panel — локальный веб-интерфейс для управления инжектором.

Только стандартная библиотека Python 3. Запуск: make ui / python3 ui/server.py
Слушает исключительно 127.0.0.1.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
UI_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = ROOT / "scripts"
LOGS_DIR = UI_DIR / "logs"
DYLIB = ROOT / "payload.dylib"

UID = os.getuid()
IPC_SOCKET = f"/tmp/inj_ipc_{UID}.sock"
IPC_SOCKET_FALLBACK = str(ROOT / "inj_ipc.sock")
PAYLOAD_LOG = f"/tmp/inj_payload_{UID}.log"

DEFAULT_TARGET = "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
DEFAULT_PORT = 8777
EXEC_TIMEOUT = 20
PROC_SCAN_RE = re.compile(r"roblox", re.IGNORECASE)


# ----------------------------------------------------------------- helpers

def ipc_socket_path():
    for p in (IPC_SOCKET, IPC_SOCKET_FALLBACK):
        if os.path.exists(p):
            return p
    return None


def ipc_send(code: str, timeout: float = EXEC_TIMEOUT):
    """Отправить код в IPC-сокет payload'а и вернуть ответ."""
    path = ipc_socket_path()
    if not path:
        return None, "IPC-сокет не найден. Payload не загружен в целевой процесс?"
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(code.encode())
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
        s.close()
        return b"".join(chunks).decode(errors="replace").strip(), None
    except Exception as e:  # noqa: BLE001 - возвращаем текст ошибки в UI
        return None, str(e)


def run_cmd(args, timeout=120, cwd=ROOT):
    try:
        p = subprocess.run(args, cwd=str(cwd), timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return -1, f"Таймаут ({timeout} c) — команда не завершилась."
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def dylib_info():
    if not DYLIB.exists():
        return {"exists": False}
    st = DYLIB.stat()
    rc, out = run_cmd(["lipo", "-info", str(DYLIB)], timeout=10)
    archs = out.split(":")[-1].strip() if rc == 0 and out else "unknown"
    return {
        "exists": True,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "archs": archs,
    }


def find_processes():
    rc, out = run_cmd(["pgrep", "-fl", "-i", "roblox"], timeout=10)
    procs = []
    if rc == 0 and out:
        for line in out.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                procs.append({"pid": int(parts[0]), "name": parts[1]})
    return procs


def tail_file(path, lines=200):
    try:
        with open(path, "r", errors="replace") as f:
            content = f.readlines()
        return "".join(content[-lines:])
    except FileNotFoundError:
        return ""
    except Exception as e:  # noqa: BLE001
        return f"Ошибка чтения лога: {e}"


SCRIPT_NAME_RE = re.compile(r"^[\w\-. ]{1,80}$", re.UNICODE)


def sanitize_script_name(name: str):
    name = (name or "").strip()
    if not name or ".." in name or "/" in name or "\\" in name:
        return None
    if not SCRIPT_NAME_RE.match(name):
        return None
    if not name.endswith(".lua"):
        name += ".lua"
    return name


# ----------------------------------------------------------------- API

def api_status():
    pong, _ = ipc_send("__PING__", timeout=3)
    sock_path = ipc_socket_path()
    return {
        "dylib": dylib_info(),
        "socket": {"path": sock_path or IPC_SOCKET, "exists": bool(sock_path), "ping": pong},
        "processes": find_processes(),
        "log": {"path": PAYLOAD_LOG, "exists": os.path.exists(PAYLOAD_LOG)},
        "tools": {
            "lldb": shutil.which("lldb") is not None,
            "nc": shutil.which("nc") is not None,
            "lua_lib": os.path.exists("/opt/homebrew/lib/liblua.dylib")
                       or os.path.exists("/usr/local/lib/liblua.dylib"),
        },
        "default_target": DEFAULT_TARGET,
        "target_exists": os.path.exists(DEFAULT_TARGET),
        "time": int(time.time()),
    }


def api_build():
    rc, out = run_cmd(["bash", "build.sh"], timeout=180)
    return {"ok": rc == 0, "output": out}


def api_launch(body):
    target = os.path.expanduser((body.get("target") or DEFAULT_TARGET).strip())
    if not os.path.exists(target):
        return {"ok": False, "output": f"Исполняемый файл не найден: {target}"}
    LOGS_DIR.mkdir(exist_ok=True)
    log_path = LOGS_DIR / "launch.log"
    env = dict(os.environ)
    env["DYLD_INSERT_LIBRARIES"] = str(DYLIB)
    try:
        with open(log_path, "ab") as lf:
            subprocess.Popen([target], env=env, cwd=str(ROOT),
                             stdout=lf, stderr=subprocess.STDOUT,
                             start_new_session=True)
        return {"ok": True,
                "output": f"Цель запущена с DYLD_INSERT_LIBRARIES.\nЛог запуска: {log_path}\n"
                          f"Примечание: на подписанных бинарях macOS может проигнорировать инъекцию."}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "output": str(e)}


def api_inject(body):
    proc = (body.get("process") or "RobloxPlayer").strip()
    if not re.match(r"^[\w.\- ]{1,60}$", proc):
        return {"ok": False, "output": "Недопустимое имя процесса."}
    rc, out = run_cmd(["bash", "live_inject.sh", proc], timeout=180)
    return {"ok": rc == 0, "output": out}


def api_execute(body):
    code = body.get("code") or ""
    if not code.strip():
        return {"ok": False, "error": "Пустой код."}
    resp, err = ipc_send(code)
    if err:
        return {"ok": False, "error": err}
    is_err = resp.startswith(("COMPILE ERR", "RUNTIME ERR", "ERR"))
    return {"ok": not is_err, "response": resp}


def api_control(body):
    cmd = body.get("command") or ""
    if cmd not in ("__PING__", "__RESET__"):
        return {"ok": False, "error": "Неизвестная команда."}
    resp, err = ipc_send(cmd)
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "response": resp}


def api_scripts_list():
    SCRIPTS_DIR.mkdir(exist_ok=True)
    items = []
    for p in sorted(SCRIPTS_DIR.glob("*.lua")):
        try:
            items.append({"name": p.name,
                          "content": p.read_text(errors="replace"),
                          "size": p.stat().st_size})
        except OSError:
            continue
    return {"scripts": items}


def api_script_save(body):
    name = sanitize_script_name(body.get("name"))
    if not name:
        return {"ok": False, "error": "Недопустимое имя файла."}
    SCRIPTS_DIR.mkdir(exist_ok=True)
    try:
        (SCRIPTS_DIR / name).write_text(body.get("content") or "")
        return {"ok": True, "name": name}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def api_script_delete(body):
    name = sanitize_script_name(body.get("name"))
    if not name:
        return {"ok": False, "error": "Недопустимое имя файла."}
    try:
        (SCRIPTS_DIR / name).unlink()
        return {"ok": True}
    except FileNotFoundError:
        return {"ok": False, "error": "Файл не найден."}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def api_logs(query):
    lines = 300
    try:
        lines = min(2000, max(10, int(parse_qs(query).get("lines", ["300"])[0])))
    except ValueError:
        pass
    return {"path": PAYLOAD_LOG, "content": tail_file(PAYLOAD_LOG, lines)}


# ----------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "InjUI/1.0"

    def log_message(self, fmt, *args):  # тише в консоли
        sys.stderr.write("[ui] %s\n" % (fmt % args))

    # -- utils
    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 10 * 1024 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except (ValueError, UnicodeDecodeError):
            return {}

    # -- routes
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            self._serve_index()
        elif path == "/api/status":
            self._send_json(api_status())
        elif path == "/api/scripts":
            self._send_json(api_scripts_list())
        elif path == "/api/logs":
            self._send_json(api_logs(parsed.query))
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        routes = {
            "/api/build": lambda: api_build(),
            "/api/launch": lambda: api_launch(body),
            "/api/inject": lambda: api_inject(body),
            "/api/execute": lambda: api_execute(body),
            "/api/control": lambda: api_control(body),
            "/api/scripts/save": lambda: api_script_save(body),
            "/api/scripts/delete": lambda: api_script_delete(body),
        }
        handler = routes.get(path)
        if handler:
            self._send_json(handler())
        else:
            self._send_json({"error": "not found"}, 404)

    def _serve_index(self):
        index = UI_DIR / "index.html"
        try:
            data = index.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self._send_json({"error": "index.html missing"}, 500)


def main():
    port = int(os.environ.get("INJ_UI_PORT", DEFAULT_PORT))
    no_browser = "--no-browser" in sys.argv

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"[+] INJ Control Panel: {url}")
    print("[i]  Только локальный доступ (127.0.0.1). Ctrl+C для остановки.")

    if not no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[i] Остановлено.")


if __name__ == "__main__":
    main()
