"""MCP server for a GoldHEN-jailbroken PS4.

Gives Claude tools to check the console, browse/read/download files over
GoldHEN's FTP server, push builds under /data, read the kernel log, and send
payloads to the binloader port.

Env vars:
  PS4_HOST          console IP (required, e.g. 192.168.0.50)
  PS4_FTP_PORT      GoldHEN FTP port (default 2121)
  PS4_PAYLOAD_PORT  binloader port (default 9090)
  PS4_KLOG_PORT     kernel log port (default 3232)
  PS4_DEBUG_PORT    ps4debug payload port (default 744), for check_cheats / read_memory / port_cheats
  PS4_WORKDIR       local folder Claude may read from / write to (default ./work)
  PS4_MCP_TOKEN     bearer token for --http mode (default: generated once and
                    kept in <workdir>/.mcp_token)
  PS4_MCP_PUBLIC_URL  public https base URL (e.g. https://ps4.example.ts.net). When set,
                    --http mode also runs an OAuth 2.1 server (dynamic client registration,
                    PKCE) so it can be added as a claude.ai custom connector. The owner
                    approves each sign-in by pasting the access token on /login.
  MCP_NO_AUTH=1     turn off the token check in --http mode (testing only)

Run:  python ps4_mcp.py            (stdio, for Claude Code; no token needed)
      python ps4_mcp.py --http     (streamable HTTP; needs Authorization: Bearer <token>
                                    or an OAuth access token)
"""

import asyncio
import ftplib
import hashlib
import hmac
import html
import io
import json
import os
import posixpath
import re
import secrets
import socket
import struct
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer  # mcp 2.x (was FastMCP in 1.x)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

HOST = os.environ.get("PS4_HOST", "").strip()
if not HOST:
    sys.exit("ps4-mcp: set PS4_HOST to your PS4's IP address (e.g. PS4_HOST=192.168.0.50)")
FTP_PORT = int(os.environ.get("PS4_FTP_PORT", "2121"))
PAYLOAD_PORT = int(os.environ.get("PS4_PAYLOAD_PORT", "9090"))
KLOG_PORT = int(os.environ.get("PS4_KLOG_PORT", "3232"))
WORKDIR = Path(os.environ.get("PS4_WORKDIR", Path(__file__).parent / "work")).resolve()
WORKDIR.mkdir(parents=True, exist_ok=True)

TOKEN_FILE = WORKDIR / ".mcp_token"         # files named .mcp_* are never reachable
OAUTH_FILE = WORKDIR / ".mcp_oauth.json"    # through the file tools
WRITE_ROOT = "/data"  # uploads and deletes are confined here
MAX_TEXT = 200_000    # cap on bytes returned by read_text / read_klog

PUBLIC_URL = os.environ.get("PS4_MCP_PUBLIC_URL", "").strip().rstrip("/")
OAUTH = "--http" in sys.argv and bool(PUBLIC_URL) and os.environ.get("MCP_NO_AUTH") != "1"
ACCESS_TTL = 3600              # OAuth access tokens: 1 hour (clients refresh)
REFRESH_TTL = 90 * 24 * 3600   # refresh tokens: 90 days, rotated on every use
CLAUDE_CALLBACKS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)


# ---------- access token (static) ----------

_static_token_cache: list[str] = []


def _load_token() -> str:
    if _static_token_cache:
        return _static_token_cache[0]
    token = os.environ.get("PS4_MCP_TOKEN", "").strip()
    if not token and TOKEN_FILE.is_file():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    if not token:
        token = secrets.token_urlsafe(32)
        TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
        try:
            TOKEN_FILE.chmod(0o600)
        except OSError:
            pass
        # Shown once so the owner can copy it from the app logs.
        print(f"ps4-mcp: generated a new access token (saved to {TOKEN_FILE}): {token}",
              file=sys.stderr, flush=True)
    _static_token_cache.append(token)
    return token


def _token_matches(given: str) -> bool:
    return hmac.compare_digest(given.strip().encode(), _load_token().encode())


# ---------- OAuth authorization server (only with PS4_MCP_PUBLIC_URL) ----------

def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _redirect_ok(uri: str) -> bool:
    """Only Claude's connector callback, or a loopback URL (Claude Code, local tests)."""
    if uri in CLAUDE_CALLBACKS:
        return True
    u = urlparse(uri)
    return u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")


class Ps4OAuth:
    """Single-owner OAuth provider. Clients and tokens persist in OAUTH_FILE
    (tokens stored as SHA-256 hashes); pending sign-ins and codes live in memory."""

    MAX_CLIENTS = 200

    def __init__(self):
        self.pending: dict[str, dict] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.failures: list[float] = []
        self.db: dict = {"clients": {}, "access": {}, "refresh": {}}
        if OAUTH_FILE.is_file():
            try:
                self.db.update(json.loads(OAUTH_FILE.read_text(encoding="utf-8")))
            except ValueError:
                print("ps4-mcp: OAuth store unreadable, starting empty", file=sys.stderr, flush=True)

    def _save(self) -> None:
        now = time.time()
        for kind in ("access", "refresh"):
            self.db[kind] = {k: v for k, v in self.db[kind].items() if v["exp"] > now}
        tmp = OAUTH_FILE.with_name(".mcp_oauth.tmp")
        tmp.write_text(json.dumps(self.db), encoding="utf-8")
        os.replace(tmp, OAUTH_FILE)
        try:
            OAUTH_FILE.chmod(0o600)
        except OSError:
            pass

    # --- clients (dynamic registration) ---
    async def get_client(self, client_id: str):
        d = self.db["clients"].get(client_id)
        return OAuthClientInformationFull.model_validate(d) if d else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not _redirect_ok(str(uri)):
                raise RegistrationError("invalid_redirect_uri", f"redirect URI not allowed: {uri}")
        if len(self.db["clients"]) >= self.MAX_CLIENTS:
            raise RegistrationError("invalid_client_metadata", "too many registered clients")
        self.db["clients"][client_info.client_id] = client_info.model_dump(mode="json", exclude_none=True)
        self._save()

    # --- authorization: hand off to the owner approval page ---
    async def authorize(self, client: OAuthClientInformationFull, params) -> str:
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v["exp"] > now}
        rid = secrets.token_urlsafe(24)
        self.pending[rid] = {
            "client_id": client.client_id,
            "client_name": client.client_name or client.client_id,
            "params": params,
            "exp": now + 600,
            "tries": 0,
        }
        return f"{PUBLIC_URL}/login?req={rid}"

    def approve(self, rid: str) -> str:
        p = self.pending.pop(rid)
        params = p["params"]
        code = secrets.token_urlsafe(32)
        self.codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=time.time() + 300,
            client_id=p["client_id"],
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject="owner",
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(self, client, authorization_code: str):
        c = self.codes.get(authorization_code)
        if c and c.client_id == client.client_id and c.expires_at > time.time():
            return c
        return None

    async def exchange_authorization_code(self, client, authorization_code) -> OAuthToken:
        self.codes.pop(authorization_code.code, None)
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    # --- tokens ---
    def _issue(self, client_id: str, scopes: list[str], resource) -> OAuthToken:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        rec = {"client_id": client_id, "scopes": list(scopes), "resource": resource}
        self.db["access"][_sha(access)] = dict(rec, exp=now + ACCESS_TTL)
        self.db["refresh"][_sha(refresh)] = dict(rec, exp=now + REFRESH_TTL)
        self._save()
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          refresh_token=refresh, scope=" ".join(scopes) or None)

    async def load_refresh_token(self, client, refresh_token: str):
        d = self.db["refresh"].get(_sha(refresh_token))
        if not d or d["client_id"] != client.client_id or d["exp"] < time.time():
            return None
        return RefreshToken(token=refresh_token, client_id=d["client_id"], scopes=d["scopes"],
                            expires_at=d["exp"], resource=d.get("resource"), subject="owner")

    async def exchange_refresh_token(self, client, refresh_token, scopes: list[str]) -> OAuthToken:
        self.db["refresh"].pop(_sha(refresh_token.token), None)  # rotate
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token: str):
        if _token_matches(token):  # the static token keeps working (Claude Code)
            return AccessToken(token=token, client_id="static-token", scopes=[], subject="owner")
        d = self.db["access"].get(_sha(token))
        if not d or d["exp"] < time.time():
            return None
        return AccessToken(token=token, client_id=d["client_id"], scopes=d["scopes"],
                           expires_at=d["exp"], resource=d.get("resource"), subject="owner")

    async def revoke_token(self, token) -> None:
        self.db["access"].pop(_sha(token.token), None)
        self.db["refresh"].pop(_sha(token.token), None)
        self._save()


if OAUTH:
    _u = urlparse(PUBLIC_URL)
    if _u.scheme != "https" and _u.hostname not in ("localhost", "127.0.0.1"):
        sys.exit("ps4-mcp: PS4_MCP_PUBLIC_URL must be https:// (or localhost for testing)")
    oauth = Ps4OAuth()
    mcp = MCPServer(
        "ps4",
        auth_server_provider=oauth,
        auth=AuthSettings(
            issuer_url=PUBLIC_URL,
            resource_server_url=PUBLIC_URL + "/mcp",
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )
else:
    oauth = None
    mcp = MCPServer("ps4")


# ---------- owner approval page ----------

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ps4-mcp sign-in</title>
<style>
body { font-family: system-ui, sans-serif; background: #111; color: #eee; margin: 0;
       display: flex; min-height: 100vh; align-items: center; justify-content: center; }
main { width: min(420px, 100vw - 32px); background: #1c1c1c; border: 1px solid #333;
       border-radius: 10px; padding: 24px; }
h1 { font-size: 1.2rem; margin: 0 0 12px; }
p { color: #bbb; line-height: 1.4; }
input[type=password] { width: 100%; box-sizing: border-box; padding: 10px; margin: 8px 0 16px;
       border-radius: 6px; border: 1px solid #444; background: #000; color: #eee; }
button { padding: 10px 16px; border: 0; border-radius: 6px; background: #2f6fed; color: #fff;
       font-size: 1rem; cursor: pointer; }
.err { color: #ff8080; }
</style></head><body><main>@@BODY@@</main></body></html>"""


def _page(body: str, status: int = 200):
    from starlette.responses import HTMLResponse
    return HTMLResponse(_PAGE.replace("@@BODY@@", body), status_code=status, headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
    })


if OAUTH:
    @mcp.custom_route("/login", methods=["GET", "POST"])
    async def login(request):
        from starlette.responses import RedirectResponse

        if request.method == "POST":
            form = await request.form()
            rid, given = str(form.get("req", "")), str(form.get("token", ""))
        else:
            rid, given = request.query_params.get("req", ""), ""
        p = oauth.pending.get(rid)
        if not p or p["exp"] < time.time():
            oauth.pending.pop(rid, None)
            return _page("<h1>Sign-in expired</h1><p>Start the connection again from Claude.</p>", 400)

        now = time.time()
        oauth.failures = [t for t in oauth.failures if t > now - 600]
        locked = len(oauth.failures) >= 20
        error = ""
        if request.method == "POST" and not locked:
            if _token_matches(given):
                return RedirectResponse(oauth.approve(rid), status_code=303)
            oauth.failures.append(now)
            p["tries"] += 1
            await asyncio.sleep(1)
            if p["tries"] >= 5:
                oauth.pending.pop(rid, None)
                return _page("<h1>Too many attempts</h1><p>Start the connection again from Claude.</p>", 403)
            error = '<p class="err">That token is not right.</p>'
        if locked:
            return _page("<h1>Locked</h1><p>Too many wrong tokens. Try again in 10 minutes.</p>", 429)

        name = html.escape(p["client_name"])
        dest = html.escape(urlparse(str(p["params"].redirect_uri)).netloc or "?")
        body = (
            f"<h1>Allow {name} to use your PS4?</h1>"
            f"<p>It will be able to browse files, read logs, upload under /data and send payloads. "
            f"After approval you are sent back to <b>{dest}</b>.</p>"
            f"{error}"
            f'<form method="post" action="/login">'
            f'<input type="hidden" name="req" value="{html.escape(rid)}">'
            f'<label for="t">Paste your ps4-mcp access token to approve:</label>'
            f'<input id="t" name="token" type="password" autocomplete="off" required autofocus>'
            f"<button type=\"submit\">Approve</button></form>"
        )
        return _page(body)


# ---------- helpers ----------

def _ftp() -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.connect(HOST, FTP_PORT, timeout=15)
    ftp.login()  # GoldHEN accepts anonymous
    ftp.set_pasv(True)
    return ftp


def _ps4_path(path: str) -> str:
    p = posixpath.normpath("/" + path.lstrip("/"))
    return p


def _writable(path: str) -> str:
    p = _ps4_path(path)
    if p != WRITE_ROOT and not p.startswith(WRITE_ROOT + "/"):
        raise ValueError(f"writes are only allowed under {WRITE_ROOT}: {p}")
    return p


def _local(path: str) -> Path:
    p = (WORKDIR / path).resolve()
    if p != WORKDIR and WORKDIR not in p.parents:
        raise ValueError(f"local path must be inside {WORKDIR}")
    if any(part.startswith(".mcp_") for part in p.relative_to(WORKDIR).parts):
        raise ValueError("that file is off limits")
    return p


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=3):
            return True
    except OSError:
        return False


# ---------- tools ----------

@mcp.tool()
def ps4_status() -> dict:
    """Check which GoldHEN services on the PS4 are reachable."""
    return {
        "host": HOST,
        "ftp": _port_open(FTP_PORT),
        "payload": _port_open(PAYLOAD_PORT),
        "klog": _port_open(KLOG_PORT),
        "ps4debug": _port_open(DEBUG_PORT),
        "workdir": str(WORKDIR),
    }


@mcp.tool()
def list_dir(path: str = "/data") -> str:
    """List a directory on the PS4 (raw LIST output)."""
    lines: list[str] = []
    with _ftp() as ftp:
        ftp.retrlines(f"LIST {_ps4_path(path)}", lines.append)  # GoldHEN lacks MLSD
    return "\n".join(lines) or "(empty)"


@mcp.tool()
def read_text(path: str, tail_bytes: int = 0) -> str:
    """Read a text file from the PS4, e.g. /data/MyApp/log.txt.
    tail_bytes > 0 returns only the last N bytes."""
    buf = io.BytesIO()
    with _ftp() as ftp:
        ftp.retrbinary(f"RETR {_ps4_path(path)}", buf.write)
    data = buf.getvalue()
    if tail_bytes > 0:
        data = data[-tail_bytes:]
    if len(data) > MAX_TEXT:
        data = data[-MAX_TEXT:]
    return data.decode("utf-8", errors="replace")


@mcp.tool()
def download(path: str, local_name: str = "") -> str:
    """Download a file from the PS4 into the local workdir."""
    src = _ps4_path(path)
    dest = _local(local_name or posixpath.basename(src))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _ftp() as ftp, open(dest, "wb") as f:
        ftp.retrbinary(f"RETR {src}", f.write)
    return f"saved {src} -> {dest} ({dest.stat().st_size} bytes)"


@mcp.tool()
def upload(local_name: str, remote_path: str) -> str:
    """Upload a file from the local workdir to the PS4 (under /data only)."""
    src = _local(local_name)
    dest = _writable(remote_path)
    if not src.is_file():
        raise FileNotFoundError(src)
    with _ftp() as ftp, open(src, "rb") as f:
        ftp.storbinary(f"STOR {dest}", f)
    return f"uploaded {src} -> {dest} ({src.stat().st_size} bytes)"


@mcp.tool()
def make_dir(remote_path: str) -> str:
    """Create a directory on the PS4 (under /data only)."""
    dest = _writable(remote_path)
    with _ftp() as ftp:
        ftp.mkd(dest)
    return f"created {dest}"


@mcp.tool()
def delete(remote_path: str) -> str:
    """Delete a file on the PS4 (under /data only). Ask the user first."""
    dest = _writable(remote_path)
    if dest == WRITE_ROOT:
        raise ValueError("refusing to delete /data itself")
    with _ftp() as ftp:
        ftp.delete(dest)
    return f"deleted {dest}"


@mcp.tool()
def read_klog(seconds: float = 5.0) -> str:
    """Capture the PS4 kernel log stream for a few seconds (crash details
    show up here). Closes the socket cleanly; GoldHEN's klog wedges if
    clients die uncleanly and then needs a PS4 restart."""
    chunks: list[bytes] = []
    total = 0
    sock = socket.create_connection((HOST, KLOG_PORT), timeout=5)
    try:
        sock.settimeout(max(0.5, seconds))
        import time
        end = time.monotonic() + seconds
        while time.monotonic() < end and total < MAX_TEXT:
            sock.settimeout(max(0.1, end - time.monotonic()))
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
    return b"".join(chunks).decode("utf-8", errors="replace") or "(no output)"


_TITLE_DIR = re.compile(r"([A-Z]{4}\d{5})_\d{3}")  # e.g. CUSA12345_000, ABCD00001_000


def _parse_sfo(data: bytes) -> dict:
    """Parse a PS4 param.sfo into {key: str|int}."""
    if data[:4] != b"\x00PSF":
        raise ValueError("not a param.sfo")
    key_tab, data_tab, count = struct.unpack_from("<III", data, 8)
    out: dict = {}
    for i in range(count):
        k_off, fmt, length, _max, d_off = struct.unpack_from("<HHIII", data, 20 + i * 16)
        end = data.index(b"\x00", key_tab + k_off)
        key = data[key_tab + k_off:end].decode("utf-8", "replace")
        raw = data[data_tab + d_off:data_tab + d_off + length]
        if fmt == 0x0404:
            out[key] = int.from_bytes(raw[:4], "little")
        else:
            out[key] = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return out


@mcp.tool()
def current_game() -> dict:
    """Show which game or app is running on the PS4 right now.
    Reads the open app sandboxes under /mnt/sandbox (system NPXS apps are
    skipped) and the title name from each app's param.sfo."""
    lines: list[str] = []
    running: list[dict] = []
    with _ftp() as ftp:
        ftp.retrlines("LIST /mnt/sandbox", lines.append)
        ids: list[str] = []
        for line in lines:
            parts = line.split()
            m = _TITLE_DIR.fullmatch(parts[-1]) if parts else None
            if m and not m.group(1).startswith("NPXS") and m.group(1) not in ids:
                ids.append(m.group(1))
        for tid in ids:
            info: dict = {"title_id": tid}
            buf = io.BytesIO()
            try:
                ftp.retrbinary(f"RETR /system_data/priv/appmeta/{tid}/param.sfo", buf.write)
                sfo = _parse_sfo(buf.getvalue())
                info["title"] = sfo.get("TITLE", "")
                info["version"] = sfo.get("APP_VER") or sfo.get("VERSION", "")
                info["content_id"] = sfo.get("CONTENT_ID", "")
                info["category"] = sfo.get("CATEGORY", "")
            except (ftplib.Error, ValueError, struct.error) as e:
                info["title"] = f"(param.sfo unreadable: {e})"
            running.append(info)
    if not running:
        return {"running": [], "note": "no game running (home screen or a system app)"}
    return {"running": running}


_ID = re.compile(r"[A-Z]{4}\d{5}")
CHEAT_ROOT = "/data/GoldHEN/cheats"
CHEAT_FORMATS = ("json", "shn", "mc4")


def _names(ftp: ftplib.FTP, path: str) -> list[str]:
    """File names in a PS4 directory (empty if it does not exist)."""
    lines: list[str] = []
    try:
        ftp.retrlines(f"LIST {path}", lines.append)
    except ftplib.Error:
        return []
    out = []
    for line in lines:
        parts = line.split(None, 8)
        if len(parts) == 9 and parts[8] not in (".", ".."):
            out.append(parts[8])
    return out


def _cheat_index(ftp: ftplib.FTP) -> dict[str, dict[str, list[str]]]:
    """{title_id: {game version: [cheat file paths]}} from GoldHEN's cheat folders."""
    index: dict[str, dict[str, list[str]]] = {}
    for fmt in CHEAT_FORMATS:
        for name in _names(ftp, f"{CHEAT_ROOT}/{fmt}"):
            m = re.match(r"([A-Z]{4}\d{5})_(\d\d[._]\d\d)", name)
            if m:
                ver = m.group(2).replace("_", ".")
                index.setdefault(m.group(1), {}).setdefault(ver, []).append(f"{CHEAT_ROOT}/{fmt}/{name}")
    return index


@mcp.tool()
def installed_games(include_cheats: bool = True) -> dict:
    """List every game and app installed on the PS4 (internal and extended
    storage), with title, version and category. System NPXS apps are skipped.
    With include_cheats, also shows which GoldHEN cheat files exist for each
    title: 'cheats' are files matching the installed version (APP_VER or the
    param.sfo VERSION, either of which GoldHEN may use), 'cheat_versions' lists
    every version GoldHEN has cheats for, and 'hint' flags games where GoldHEN
    may not find them (fix with alias_cheat)."""
    base = "/system_data/priv/appmeta"
    games: list[dict] = []
    with _ftp() as ftp:
        meta_dirs: dict[str, list[str]] = {}  # title id -> appmeta folders that hold it
        for path in (base, f"{base}/external"):
            for name in _names(ftp, path):
                if _ID.fullmatch(name) and not name.startswith("NPXS"):
                    meta_dirs.setdefault(name, []).append(f"{path}/{name}")
        on_internal = set(_names(ftp, "/user/app"))
        patched = set(_names(ftp, "/user/patch"))
        dlc = set(_names(ftp, "/user/addcont"))
        cheats = _cheat_index(ftp) if include_cheats else {}
        for tid, dirs in meta_dirs.items():
            info: dict = {"title_id": tid, "storage": "internal" if tid in on_internal else "extended"}
            sfo = None
            for d in dirs:
                buf = io.BytesIO()
                try:
                    ftp.retrbinary(f"RETR {d}/param.sfo", buf.write)
                    sfo = _parse_sfo(buf.getvalue())
                    break
                except (ftplib.Error, ValueError, struct.error):
                    continue
            if sfo is None:
                continue  # leftover metadata with no param.sfo (not a launchable title)
            app_ver, sfo_ver = str(sfo.get("APP_VER", "")), str(sfo.get("VERSION", ""))
            info["title"] = sfo.get("TITLE", "")
            info["version"] = app_ver or sfo_ver
            if sfo_ver and app_ver and sfo_ver != app_ver:
                info["sfo_version"] = sfo_ver
            info["category"] = sfo.get("CATEGORY", "")
            if tid in patched:
                info["update_installed"] = True
            if tid in dlc:
                info["dlc_installed"] = True
            if include_cheats and tid in cheats:
                found_files: list[str] = []
                for v in dict.fromkeys(x for x in (app_ver, sfo_ver) if x):
                    found_files += cheats[tid].get(v, [])
                info["cheats"] = found_files
                info["cheat_versions"] = sorted(cheats[tid])
                hint = _version_hint(tid, app_ver, sfo_ver, set(cheats[tid]))
                if hint:
                    info["hint"] = hint
            games.append(info)
    games.sort(key=lambda g: str(g.get("title", "")).lower())
    return {"count": len(games), "games": games}


def _retr(ftp: ftplib.FTP, path: str) -> bytes:
    buf = io.BytesIO()
    ftp.retrbinary(f"RETR {path}", buf.write)
    return buf.getvalue()


def _installed_versions(ftp: ftplib.FTP, tid: str) -> tuple[str, str]:
    """(APP_VER, VERSION) from the installed title's param.sfo; ("", "") if not installed.
    GoldHEN's cheat menu usually matches APP_VER, but for some games (e.g. a title with
    APP_VER 01.00 but VERSION 01.06) it looks for VERSION instead."""
    for d in ("/system_data/priv/appmeta", "/system_data/priv/appmeta/external"):
        try:
            sfo = _parse_sfo(_retr(ftp, f"{d}/{tid}/param.sfo"))
            return str(sfo.get("APP_VER", "")), str(sfo.get("VERSION", ""))
        except (ftplib.Error, ValueError, struct.error):
            continue
    return "", ""


def _version_hint(tid: str, app_ver: str, sfo_ver: str, have: set[str]) -> str:
    # Seen so far: GoldHEN uses the higher of the two (APP_VER 01.00 / VERSION 01.06 -> 01.06;
    # APP_VER 01.03 / VERSION 01.00 -> 01.03).
    if app_ver and sfo_ver and sfo_ver > app_ver and app_ver in have and sfo_ver not in have:
        return (f"GoldHEN may look for version {sfo_ver} instead of {app_ver}. If its cheat menu says "
                f"'not found' for {tid} {sfo_ver}, run alias_cheat({tid}, {app_ver}, {sfo_ver}).")
    if app_ver and sfo_ver and sfo_ver > app_ver and sfo_ver in have and app_ver not in have:
        return (f"GoldHEN will likely load the {sfo_ver} cheats, but the game reports APP_VER {app_ver}; "
                f"they may target different code. Back up saves first and stop if the game misbehaves.")
    return ""


def _cheat_names(fmt: str, data: bytes) -> list[str]:
    """Cheat names inside a GoldHEN cheat file (json or shn; mc4 is encrypted)."""
    if fmt == "json":
        doc = json.loads(data.decode("utf-8-sig"))
        return [str(m.get("name", "?")) for m in doc.get("mods", [])]
    if fmt == "shn":
        text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8-sig", "replace")
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            raise ValueError("shn file has a DTD; refusing to parse")
        import xml.etree.ElementTree as ET
        root = ET.fromstring(re.sub(r'encoding="[^"]+"', "", text, count=1).encode("utf-8"))
        return [el.get("Text", "?") for el in root.iter("Cheat")]
    raise ValueError("mc4 files are encrypted (PS4 Cheats Manager format)")


@mcp.tool()
def list_cheats(title_id: str, version: str = "") -> dict:
    """List the GoldHEN cheats available for a game, with the cheat names in
    each file. version: game version like "01.09"; empty = all versions.
    Reports the installed version (APP_VER) and the param.sfo VERSION; GoldHEN
    may use either, so files matching both are marked. Cheats are switched on
    in-game from GoldHEN's cheat menu."""
    tid = title_id.strip().upper()
    if not _ID.fullmatch(tid):
        raise ValueError("title_id must look like CUSA12345")
    ver = version.strip()
    files: list[dict] = []
    with _ftp() as ftp:
        installed, sfo_ver = _installed_versions(ftp, tid)
        wanted = {v for v in (installed, sfo_ver) if v}
        for fmt in CHEAT_FORMATS:
            for name in _names(ftp, f"{CHEAT_ROOT}/{fmt}"):
                m = re.match(r"([A-Z]{4}\d{5})_(\d\d[._]\d\d)", name)
                if not m or m.group(1) != tid:
                    continue
                fver = m.group(2).replace("_", ".")
                if ver and fver != ver:
                    continue
                entry: dict = {"file": f"{CHEAT_ROOT}/{fmt}/{name}", "format": fmt, "version": fver,
                               "matches_installed": fver in wanted}
                try:
                    entry["cheats"] = _cheat_names(fmt, _retr(ftp, entry["file"]))
                except (ValueError, ftplib.Error, UnicodeDecodeError) as e:
                    entry["cheats"] = []
                    entry["note"] = str(e)[:200]
                files.append(entry)
    files.sort(key=lambda e: (not e["matches_installed"], e["version"], e["format"]))
    out: dict = {"title_id": tid, "installed_version": installed or "(not installed)", "files": files}
    if sfo_ver and sfo_ver != installed:
        out["sfo_version"] = sfo_ver
    if not files:
        out["note"] = "GoldHEN has no cheat files for this title" + (f" version {ver}" if ver else "")
    hint = _version_hint(tid, installed, sfo_ver, {f["version"] for f in files})
    if hint:
        out["hint"] = hint
    return out


@mcp.tool()
def alias_cheat(title_id: str, from_version: str, to_version: str) -> str:
    """Copy a game's GoldHEN JSON cheat files from one version to another, e.g.
    when GoldHEN's menu says 'cheats not found for <ID> 01.06' but cheats exist
    for 01.00 and the game's code really is 01.00 (param.sfo VERSION vs APP_VER).
    Writes <ID>_<to_version>*.json next to the originals with "version" updated;
    never overwrites an existing file. Only use it when the game's code matches
    from_version, or the cheats will patch the wrong addresses."""
    tid = title_id.strip().upper()
    src_v, dst_v = from_version.strip(), to_version.strip()
    if not _ID.fullmatch(tid):
        raise ValueError("title_id must look like CUSA12345")
    for v in (src_v, dst_v):
        if not re.fullmatch(r"\d\d\.\d\d", v):
            raise ValueError('versions must look like "01.00"')
    if src_v == dst_v:
        raise ValueError("from_version and to_version are the same")
    folder = f"{CHEAT_ROOT}/json"
    done: list[str] = []
    skipped: list[str] = []
    with _ftp() as ftp:
        names = _names(ftp, folder)
        prefix = f"{tid}_{src_v}"
        sources = [n for n in names if n.startswith(prefix) and n.endswith(".json")]
        if not sources:
            raise ValueError(f"no JSON cheat files for {tid} {src_v} in {folder}")
        for name in sources:
            target = f"{tid}_{dst_v}{name[len(prefix):]}"
            if target in names:
                skipped.append(target)
                continue
            doc = json.loads(_retr(ftp, f"{folder}/{name}").decode("utf-8-sig"))
            doc["version"] = dst_v
            ftp.storbinary(f"STOR {_writable(f'{folder}/{target}')}",
                           io.BytesIO(json.dumps(doc, indent=2).encode("utf-8")))
            done.append(target)
    msg = f"copied {len(done)} file(s) to {folder}: {', '.join(done) or '-'}"
    if skipped:
        msg += f"; already there, left as is: {', '.join(skipped)}"
    return msg


_HEX = re.compile(r"[0-9A-Fa-f]+")


@mcp.tool()
def add_cheat(title_id: str, version: str, cheat_name: str, memory: list[dict],
              game_name: str = "", process: str = "eboot.bin", replace: bool = False) -> str:
    """Add a cheat to the PS4 as a GoldHEN JSON cheat. It goes into
    /data/GoldHEN/cheats/json/<ID>_<version>_custom.json, so GoldHEN's own cheat
    files (and cheat database updates) are never touched; existing cheats in that
    custom file are kept. memory: list of {"offset": hex, "on": hex bytes,
    "off": hex bytes} (same format as GoldHEN cheat files; on/off same length).
    replace=True overwrites a cheat with the same name. Turn it on in-game from
    GoldHEN's cheat menu."""
    tid = title_id.strip().upper()
    ver = version.strip()
    if not _ID.fullmatch(tid):
        raise ValueError("title_id must look like CUSA12345")
    if not re.fullmatch(r"\d\d\.\d\d", ver):
        raise ValueError('version must look like "01.00"')
    name = cheat_name.strip()
    if not name:
        raise ValueError("cheat_name is empty")
    if not memory:
        raise ValueError("memory needs at least one {offset, on, off} entry")
    lines = []
    for i, m in enumerate(memory):
        off = str(m.get("offset", "")).strip().removeprefix("0x").removeprefix("0X")
        on = re.sub(r"[\s-]", "", str(m.get("on", "")))
        offv = re.sub(r"[\s-]", "", str(m.get("off", "")))
        if not (_HEX.fullmatch(off) and _HEX.fullmatch(on) and _HEX.fullmatch(offv)):
            raise ValueError(f"memory[{i}]: offset, on and off must be hex")
        if len(on) % 2 or len(on) != len(offv):
            raise ValueError(f"memory[{i}]: on and off must be whole bytes of the same length")
        lines.append({"offset": off.upper(), "on": on.upper(), "off": offv.upper()})

    path = _writable(f"{CHEAT_ROOT}/json/{tid}_{ver}_custom.json")
    with _ftp() as ftp:
        try:
            doc = json.loads(_retr(ftp, path).decode("utf-8-sig"))
        except ftplib.Error:
            doc = {"name": game_name or tid, "id": tid, "version": ver, "process": process,
                   "credits": ["custom"], "mods": []}
        mods = doc.setdefault("mods", [])
        existing = [i for i, mod in enumerate(mods) if mod.get("name") == name]
        new_mod = {"name": name, "type": "checkbox", "memory": lines}
        if existing and not replace:
            raise ValueError(f'"{name}" is already in {path}; pass replace=True to overwrite it')
        if existing:
            mods[existing[0]] = new_mod
        else:
            mods.append(new_mod)
        if game_name:
            doc["name"] = game_name
        ftp.storbinary(f"STOR {path}", io.BytesIO(json.dumps(doc, indent=2).encode("utf-8")))
    action = "replaced" if existing else "added"
    return f'{action} "{name}" in {path} ({len(mods)} cheat(s) in the file, {len(lines)} memory line(s))'


# ---------- ps4debug (read-only game memory) ----------
# Needs the ps4debug(-NG) payload loaded (send_payload). Only the process list, maps,
# info and READ commands are used: nothing here writes game memory or attaches the
# debugger (a watchpoint on a hot write path crashed a game once).

DEBUG_PORT = int(os.environ.get("PS4_DEBUG_PORT", "744"))
_DBG_MAGIC = 0xFFAABBCC
_DBG_OK = 0x80000000
_READ_CHUNK = 0x100000


class _Ps4Debug:
    def __init__(self):
        try:
            self.s = socket.create_connection((HOST, DEBUG_PORT), timeout=30)
        except OSError as e:
            raise RuntimeError(f"ps4debug is not answering on {HOST}:{DEBUG_PORT} ({e}). Load the "
                               "ps4debug payload first: turn on GoldHEN's BinLoader, then "
                               "send_payload('ps4debug-ng.bin').") from None

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _rx(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise RuntimeError("ps4debug closed the connection")
            buf += chunk
        return bytes(buf)

    def _cmd(self, cmd: int, data: bytes = b"") -> None:
        self.s.sendall(struct.pack("<III", _DBG_MAGIC, cmd, len(data)) + data)
        status = struct.unpack("<I", self._rx(4))[0]
        if status != _DBG_OK:
            raise RuntimeError(f"ps4debug command {cmd:#x} failed with status {status:#x}")

    def procs(self) -> list[tuple[str, int]]:
        self._cmd(0xBDAA0001)
        n = struct.unpack("<I", self._rx(4))[0]
        out = []
        for _ in range(n):
            b = self._rx(36)
            out.append((b[:32].split(b"\0")[0].decode(errors="replace"), struct.unpack("<I", b[32:])[0]))
        return out

    def info(self, pid: int) -> dict:
        self._cmd(0xBDAA000A, struct.pack("<I", pid))
        b = self._rx(188)
        s = lambda a, z: b[a:z].split(b"\0")[0].decode(errors="replace")
        return {"pid": pid, "name": s(4, 44), "path": s(44, 108), "title_id": s(108, 124),
                "content_id": s(124, 188)}

    def maps(self, pid: int) -> list[tuple[str, int, int, int]]:
        self._cmd(0xBDAA0004, struct.pack("<I", pid))
        n = struct.unpack("<I", self._rx(4))[0]
        out = []
        for _ in range(n):
            b = self._rx(58)
            start, end, _off, prot = struct.unpack("<QQQH", b[32:])
            out.append((b[:32].split(b"\0")[0].decode(errors="replace"), start, end, prot))
        return out

    def read(self, pid: int, addr: int, length: int) -> bytes:
        out = bytearray()
        while length > 0:
            n = min(_READ_CHUNK, length)
            self._cmd(0xBDAA0002, struct.pack("<IQI", pid, addr, n))
            out += self._rx(n)
            addr += n
            length -= n
        return bytes(out)


def _find_game(dbg: _Ps4Debug, title_id: str = "") -> dict:
    """The running game's process: pid, title id and its code segment (the first r-x map).
    Several processes can be called eboot.bin (Itemzflow is one); title_id picks the right one."""
    found = []
    for name, pid in dbg.procs():
        if name != "eboot.bin":
            continue
        info = dbg.info(pid)
        if not _ID.fullmatch(info["title_id"]) or info["title_id"].startswith(("NPXS", "ITEM")):
            continue
        if title_id and info["title_id"] != title_id:
            continue
        text = [(s, e) for n, s, e, p in dbg.maps(pid) if n == "executable" and p & 4]
        if text:
            info["base"], info["text_end"] = text[0]
            found.append(info)
    if not found:
        raise RuntimeError("no running game" + (f" with title id {title_id}" if title_id else "") +
                           " found through ps4debug; start the game first")
    if len(found) > 1:
        raise RuntimeError("several games running: " + ", ".join(f["title_id"] for f in found) +
                           "; pass title_id")
    return found[0]


def _cheat_doc(ftp: ftplib.FTP, tid: str, ver: str) -> tuple[str, dict]:
    folder = f"{CHEAT_ROOT}/json"
    names = sorted(n for n in _names(ftp, folder) if n.startswith(f"{tid}_{ver}") and n.endswith(".json"))
    if not names:
        raise ValueError(f"no JSON cheat file for {tid} {ver} in {folder}")
    plain = f"{tid}_{ver}.json"
    name = plain if plain in names else names[0]
    return f"{folder}/{name}", json.loads(_retr(ftp, f"{folder}/{name}").decode("utf-8-sig"))


def _hexb(s) -> bytes:
    return bytes.fromhex(re.sub(r"[\s-]", "", str(s)))


@mcp.tool()
def check_cheats(title_id: str = "", version: str = "") -> dict:
    """Read the running game's memory (ps4debug) and report, for each cheat in its GoldHEN JSON
    file, whether it is ON (patched), OFF (original bytes) or MISMATCH (neither: the file does not
    fit this game version, or another patch changed those bytes). Defaults: the running game and
    its installed version. Read-only. Needs the ps4debug payload loaded."""
    tid = title_id.strip().upper()
    with _Ps4Debug() as dbg:
        game = _find_game(dbg, tid)
        tid = game["title_id"]
        with _ftp() as ftp:
            ver = version.strip()
            if not ver:
                app_ver, sfo_ver = _installed_versions(ftp, tid)
                ver = max(app_ver, sfo_ver)
            path, doc = _cheat_doc(ftp, tid, ver)
        base = game["base"]
        # Variants of one cheat (EXP x1000 / x5000 ...) patch the same spot; when one is on,
        # the others see its bytes there, which is "off" for them, not a mismatch.
        site_on: dict[int, list[bytes]] = {}
        for mod in doc.get("mods", []):
            for e in mod.get("memory", []):
                site_on.setdefault(int(str(e["offset"]), 16), []).append(_hexb(e["on"]))
        cheats, counts = [], {"on": 0, "off": 0, "mismatch": 0, "partial": 0}
        for mod in doc.get("mods", []):
            states = []
            for e in mod.get("memory", []):
                on, off = _hexb(e["on"]), _hexb(e["off"])
                o = int(str(e["offset"]), 16)
                live = dbg.read(game["pid"], base + o, len(on))
                if live == on:
                    states.append("on")
                elif live == off or any(live == x[:len(live)] or live[:len(x)] == x
                                        for x in site_on[o] if x != on):
                    states.append("off")
                else:
                    states.append("mismatch")
                if not any(off):
                    states[-1] = "cave-" + states[-1]  # GoldHEN can leave a cave written after turning off
            hooks = [s for s in states if not s.startswith("cave-")]
            caves = [s[5:] for s in states if s.startswith("cave-")]
            if hooks and "on" in hooks and any(c != "on" for c in caves):
                hooks.append("mismatch")  # jumping into a cave that is not there would crash
            states = hooks or caves
            if "mismatch" in states:
                st = "mismatch"
            elif all(s == "on" for s in states):
                st = "on"
            elif all(s == "off" for s in states):
                st = "off"
            else:
                st = "partial"
            counts[st] += 1
            cheats.append({"name": mod.get("name", "?"), "state": st})
    out = {"title_id": tid, "file": path, "pid": game["pid"], "summary": counts, "cheats": cheats}
    if counts["mismatch"]:
        out["note"] = ("MISMATCH means the bytes at that offset are neither the cheat's 'on' nor 'off' "
                       "bytes. If most cheats show it, the file was made for a different game version: "
                       "try port_cheats.")
    return out


@mcp.tool()
def read_memory(offset: str, length: int = 64, title_id: str = "", absolute: bool = False) -> dict:
    """Read up to 4096 bytes of the running game's memory as hex (ps4debug, read-only).
    offset is hex; by default it is relative to the game's code base, like GoldHEN cheat offsets.
    absolute=True treats it as a process address."""
    if not 0 < length <= 4096:
        raise ValueError("length must be 1..4096")
    off = int(offset.strip().removeprefix("0x").removeprefix("0X"), 16)
    with _Ps4Debug() as dbg:
        game = _find_game(dbg, title_id.strip().upper())
        addr = off if absolute else game["base"] + off
        data = dbg.read(game["pid"], addr, length)
    return {"title_id": game["title_id"], "address": f"{addr:#x}", "base": f"{game['base']:#x}",
            "hex": data.hex()}


# --- cheat porting ---

def _rel32_sites(code: bytes):
    """(position, instruction length) of possible rel32 jmp/call/jcc in a byte string. Heuristic:
    without a disassembler an E8/E9 byte inside an immediate looks the same, so callers only act
    on sites whose target lands somewhere meaningful."""
    for i in range(len(code)):
        if code[i] in (0xE8, 0xE9) and i + 5 <= len(code):
            yield i, 5
        elif code[i] == 0x0F and i + 6 <= len(code) and 0x80 <= code[i + 1] <= 0x8F:
            yield i, 6


def _port_doc(doc: dict, mem: bytes, to_version: str) -> tuple[dict, list[dict], str]:
    """Port a GoldHEN cheat document to new code `mem` (bytes from the code base).
    Returns (new doc, per-cheat report, cave range). Offsets are relative to the code base.

    - Patch sites: entries with non-zero 'off' bytes. Their original bytes are searched for in the
      new code. A unique hit wins; with several hits the one whose shift best matches the
      nearest uniquely found site wins (code usually moves in blocks).
    - Code caves: entries whose 'off' bytes are all zero. They are moved into the zero padding at
      the end of the new code segment, and every rel32 jump/call in any entry is re-aimed: into a
      cave -> the cave's new spot; into game code -> shifted like the nearest patch site.
    """
    import copy

    mods = doc.get("mods", [])
    entries = [(mi, ei, e) for mi, m in enumerate(mods) for ei, e in enumerate(m.get("memory", []))]

    # 1. locate patch sites
    sites: dict[int, list[int]] = {}
    lens: dict[int, int] = {}
    for _, _, e in entries:
        off = _hexb(e["off"])
        if any(off):
            o = int(str(e["offset"]), 16)
            if o not in sites:
                sites[o] = [m.start() for m in re.finditer(re.escape(off), mem)]
                lens[o] = len(off)
    unique = sorted((o, h[0] - o) for o, h in sites.items() if len(h) == 1)

    def near_shift(o: int):
        return min(unique, key=lambda u: abs(u[0] - o))[1] if unique else None

    new_site: dict[int, int] = {}
    site_how: dict[int, str] = {}
    for o, hits in sites.items():
        if len(hits) == 1:
            new_site[o], site_how[o] = hits[0], "unique"
        elif hits:
            ns = near_shift(o)
            if ns is None:
                continue
            new_site[o] = min(hits, key=lambda h: abs((h - o) - ns))
            site_how[o] = f"best of {len(hits)} matches"

    site_shifts = sorted((o, n - o) for o, n in new_site.items())

    def shift_for(addr: int):
        if not site_shifts:
            return None, None
        o, s = min(site_shifts, key=lambda x: abs(x[0] - addr))
        return s, abs(o - addr)

    # 2. free space: zero run at the end of the code segment, 0x40 past the last used byte
    last = len(mem.rstrip(b"\0"))
    cave_start = (last + 0x40 + 15) & ~15
    caves_old: dict[int, int] = {}  # old cave offset -> size (variants sharing a cave keep sharing)
    for _, _, e in entries:
        if not any(_hexb(e["off"])):
            o = int(str(e["offset"]), 16)
            caves_old[o] = max(caves_old.get(o, 0), len(_hexb(e["on"])))
    cave_new: dict[int, int] = {}
    alloc = cave_start
    for o in sorted(caves_old):
        cave_new[o] = alloc
        alloc = (alloc + caves_old[o] + 15) & ~15
    cave_end = alloc
    if cave_end > len(mem):
        raise ValueError(f"not enough free space at the end of the code segment: caves need "
                         f"{cave_end - cave_start:#x} bytes, {len(mem) - cave_start:#x} free")

    def map_target(t: int):
        """New address for an old absolute (base-relative) branch target, and how sure we are."""
        for o, size in caves_old.items():
            if o <= t < o + size:
                return cave_new[o] + (t - o), "cave"
        s, dist = shift_for(t)
        if s is None:
            return None, None
        return t + s, ("near hook" if dist <= 0x400 else f"far ({dist:#x} from nearest hook)")

    # 3. rewrite
    out = copy.deepcopy(doc)
    out["version"] = to_version
    report = []
    for mi, m in enumerate(mods):
        issues, notes = [], []
        for ei, e in enumerate(m.get("memory", [])):
            o = int(str(e["offset"]), 16)
            on = bytearray(_hexb(e["on"]))
            off = _hexb(e["off"])
            if any(off):
                if o not in new_site:
                    issues.append(f"original bytes at {o:X} not found in the new code")
                    continue
                n = new_site[o]
                if site_how[o] != "unique":
                    notes.append(f"{o:X}: {site_how[o]}")
            else:
                n = cave_new[o]
                if any(mem[n:n + len(on)]):
                    issues.append(f"cave space at {n:X} is not empty")
            in_cave = not any(off)
            for i, ln in _rel32_sites(bytes(on)):
                rel = struct.unpack_from("<i", on, i + ln - 4)[0]
                t = o + i + ln + rel
                if in_cave and o <= t < o + len(on):
                    continue  # jump inside the same cave: moves with it
                is_cave = any(co <= t < co + sz for co, sz in caves_old.items())
                if not is_cave and not (0 <= t < len(mem)):
                    continue  # target outside the code: not a real branch
                if not in_cave and not is_cave:
                    continue  # plain patch branching into game code: same relative distance after the move
                nt, how = map_target(t)
                if nt is None:
                    issues.append(f"cannot re-aim branch at {o:X}+{i}")
                    continue
                struct.pack_into("<i", on, i + ln - 4, nt - (n + i + ln))
                if how.startswith("far"):
                    notes.append(f"branch at {n:X}+{i} goes to game code {how}; check it")
            ne = dict(e, offset=f"{n:X}", on=bytes(on).hex().upper())
            out["mods"][mi]["memory"][ei] = ne
        report.append({"name": m.get("name", "?"), "ok": not issues, **({"issues": issues} if issues else {}),
                       **({"notes": notes} if notes else {})})
    return out, report, f"{cave_start:X}-{cave_end:X}"


@mcp.tool()
def port_cheats(title_id: str, from_version: str, to_version: str = "", write: bool = False,
                overwrite: bool = False) -> dict:
    """Port a game's GoldHEN JSON cheats from one game version to the version that is RUNNING now.
    Start the game first and load the ps4debug payload. Reads the game's code (read-only), finds
    each patch site by its original bytes, moves code caves into free space at the end of the code
    and re-aims their jumps. Reports per cheat: ok, notes (guesses to double-check) or issues
    (skipped). write=True uploads /data/GoldHEN/cheats/json/<ID>_<to_version>.json (refuses an
    existing file unless overwrite=True, which saves a .bak-<time> copy first) and keeps a copy in
    the workdir. Cheats whose sites were not found are left out of the written file.
    Limits: it cannot fix version-specific constants inside caves (absolute addresses, struct
    offsets, pointer checks such as a "this character only" compare), so every ported cheat still
    needs an in-game test; relaunch the game after writing, GoldHEN loads cheat files at launch."""
    tid = title_id.strip().upper()
    if not _ID.fullmatch(tid):
        raise ValueError("title_id must look like CUSA12345")
    src_v = from_version.strip()
    with _Ps4Debug() as dbg:
        game = _find_game(dbg, tid)
        with _ftp() as ftp:
            dst_v = to_version.strip()
            if not dst_v:
                dst_v = max(_installed_versions(ftp, tid))
            if src_v == dst_v:
                raise ValueError("from_version and to_version are the same")
            src_path, doc = _cheat_doc(ftp, tid, src_v)
            try:
                _, active_doc = _cheat_doc(ftp, tid, dst_v)
            except ValueError:
                active_doc = None
        mem = bytearray(dbg.read(game["pid"], game["base"], game["text_end"] - game["base"]))
    # Cheats from the running version's own file may be switched on; undo them in the copy so
    # the search sees original code and the cave space looks free again.
    undone = 0
    if active_doc:
        for mod in active_doc.get("mods", []):
            for e in mod.get("memory", []):
                o, on, off = int(str(e["offset"]), 16), _hexb(e["on"]), _hexb(e["off"])
                if on != off and mem[o:o + len(on)] == on:
                    mem[o:o + len(off)] = off
                    undone += 1
    new_doc, report, caves = _port_doc(doc, bytes(mem), dst_v)
    ok = [r for r in report if r["ok"]]
    bad = [r for r in report if not r["ok"]]
    new_doc["mods"] = [m for m, r in zip(new_doc["mods"], report) if r["ok"]]
    credits = new_doc.setdefault("credits", [])
    if isinstance(credits, list):
        credits.append(f"ported {src_v} -> {dst_v} by ps4-mcp port_cheats")
    out: dict = {"title_id": tid, "source": src_path, "to_version": dst_v, "cave_space": caves,
                 "ported": len(ok), "failed": len(bad), "cheats": report}
    if undone:
        out["active_patches_ignored"] = undone
    if write:
        if not ok:
            raise ValueError("nothing ported; not writing a file")
        target = _writable(f"{CHEAT_ROOT}/json/{tid}_{dst_v}.json")
        body = json.dumps(new_doc, indent=2, ensure_ascii=False).encode("utf-8")
        local = _local(f"{tid}_{dst_v}.json")
        local.write_bytes(body)
        with _ftp() as ftp:
            exists = posixpath.basename(target) in _names(ftp, posixpath.dirname(target))
            if exists and not overwrite:
                raise ValueError(f"{target} already exists; pass overwrite=True (a backup is kept). "
                                 f"The ported file is in the workdir as {local.name}.")
            if exists:
                backup = _writable(f"{target}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
                ftp.storbinary(f"STOR {backup}", io.BytesIO(_retr(ftp, target)))
                out["backup"] = backup
            ftp.storbinary(f"STOR {target}", io.BytesIO(body))
        out["written"] = target
        out["next"] = "Relaunch the game, turn cheats on one at a time, and check_cheats to see what is applied."
    return out


GH_CONFIG = "/data/GoldHEN/config.ini"
_INI_VALUE = re.compile(r"[A-Za-z0-9_.\-]{1,32}")


def _ini_section(line: str):
    t = line.strip()
    return t[1:-1] if t.startswith("[") and t.endswith("]") else None


def _parse_ini(text: str) -> dict:
    out: dict = {}
    sec = None
    for line in text.splitlines():
        name = _ini_section(line)
        if name is not None:
            sec = out.setdefault(name, {})
        elif sec is not None and "=" in line:
            k, v = line.split("=", 1)
            sec[k.strip()] = v.strip()
    return out


@mcp.tool()
def goldhen_config(section: str = "", key: str = "", value: str = "") -> dict:
    """Read or change GoldHEN's config.ini. With no arguments returns every setting.
    With section, key and value, changes ONE existing setting in place (keys that do not exist are
    refused) after saving a backup next to it as config.ini.bak-<time>. Takes effect after GoldHEN
    reloads (reboot / re-inject). Ask the user before changing."""
    ftp = _ftp()
    try:
        text = _retr(ftp, GH_CONFIG).decode("utf-8", "replace")
        cfg = _parse_ini(text)
        if not (section or key or value):
            return cfg
        if not (section and key and value):
            raise ValueError("give section, key and value together")
        if not _INI_VALUE.fullmatch(value):
            raise ValueError("value must be letters, digits, _ . - only")
        if key not in cfg.get(section, {}):
            raise ValueError(f"{section}/{key} not found; existing keys in that section: "
                             f"{list(cfg.get(section, {}))}")
        old = cfg[section][key]
        lines = text.splitlines(keepends=True)
        cur = None
        for i, line in enumerate(lines):
            name = _ini_section(line)
            if name is not None:
                cur = name
            elif cur == section and "=" in line and line.split("=", 1)[0].strip() == key:
                nl = "\r\n" if line.endswith("\r\n") else "\n"
                lines[i] = f"{key} = {value}{nl}"
                break
        backup = _writable(f"{GH_CONFIG}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        ftp.storbinary(f"STOR {backup}", io.BytesIO(text.encode("utf-8")))
        ftp.storbinary(f"STOR {_writable(GH_CONFIG)}", io.BytesIO("".join(lines).encode("utf-8")))
        return {"changed": f"{section}/{key}: {old} -> {value}", "backup": backup}
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


@mcp.tool()
def send_payload(local_name: str) -> str:
    """Send a .bin/.elf payload from the workdir to the binloader port.
    Ask the user before sending."""
    src = _local(local_name)
    if src.suffix.lower() not in (".bin", ".elf"):
        raise ValueError("payload must be a .bin or .elf file")
    data = src.read_bytes()
    with socket.create_connection((HOST, PAYLOAD_PORT), timeout=10) as s:
        s.sendall(data)
    return f"sent {src.name} ({len(data)} bytes) to {HOST}:{PAYLOAD_PORT}"


# Raw x86-64 payload: kill(1, 30), i.e. SIGUSR1 to init, which the PS4 treats as a reboot
# request (the usual homebrew reboot). Built in so no third-party payload file is needed.
#   mov eax, 37 ; mov edi, 1 ; mov esi, 30 ; mov r10, rcx ; syscall ; ret
_REBOOT_PAYLOAD = bytes.fromhex("b825000000" "bf01000000" "be1e000000" "4989ca" "0f05" "c3")


@mcp.tool()
def reboot_ps4(confirm: bool = False) -> dict:
    """Reboot the PS4 by sending a tiny built-in reboot payload to GoldHEN's binloader.
    Needs BinLoader on (port 9090 open). After the reboot the console is stock: GoldHEN,
    FTP, klog and the binloader are gone until the user runs the exploit again, so every other
    tool stops working. Any running game is closed without saving. ALWAYS ask the user first,
    then call with confirm=True."""
    if not confirm:
        raise ValueError("not sent: ask the user first, then call reboot_ps4(confirm=True)")
    if not _port_open(PAYLOAD_PORT):
        raise RuntimeError(f"binloader port {PAYLOAD_PORT} is closed (BinLoader off or GoldHEN "
                           "not loaded); reboot from the console instead")
    with socket.create_connection((HOST, PAYLOAD_PORT), timeout=10) as s:
        s.sendall(_REBOOT_PAYLOAD)
    # The console takes a few seconds to start shutting down; FTP going away confirms it.
    for _ in range(15):
        time.sleep(2)
        if not _port_open(FTP_PORT):
            return {"sent": True, "rebooting": True,
                    "note": "FTP went down. Run the exploit again once the PS4 is back up."}
    return {"sent": True, "rebooting": False,
            "note": "payload sent but FTP is still up after 30 s; the reboot may not have worked"}


# ---------- HTTP serving ----------

class BearerAuth:
    """ASGI wrapper: every HTTP request must carry Authorization: Bearer <token>."""

    def __init__(self, app, token: str):
        self.app = app
        self.expected = token.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            auth = dict(scope.get("headers") or []).get(b"authorization", b"")
            scheme, _, given = auth.partition(b" ")
            if scheme.lower() != b"bearer" or not hmac.compare_digest(given.strip(), self.expected):
                body = json.dumps({"error": "unauthorized"}).encode()
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b'Bearer realm="ps4-mcp"'),
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def _run_http() -> None:
    import uvicorn

    host = os.environ.get("MCP_BIND", "127.0.0.1")
    port = int(os.environ.get("MCP_PORT", "8000"))
    app = mcp.streamable_http_app(host=host)
    if os.environ.get("MCP_NO_AUTH") == "1":
        print("ps4-mcp: WARNING, token check is off (MCP_NO_AUTH=1)", file=sys.stderr, flush=True)
    elif OAUTH:
        _load_token()  # create it now so the owner can copy it before the first sign-in
        print(f"ps4-mcp: OAuth on, issuer {PUBLIC_URL}, connector URL {PUBLIC_URL}/mcp",
              file=sys.stderr, flush=True)
    else:
        app = BearerAuth(app, _load_token())
        print("ps4-mcp: static token auth (set PS4_MCP_PUBLIC_URL to enable OAuth)",
              file=sys.stderr, flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    if "--http" in sys.argv:
        _run_http()
    else:
        mcp.run()
