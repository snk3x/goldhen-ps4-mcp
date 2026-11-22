"""Phone hints page: shows hints for whatever game is running on the PS4, with
cheat on/off switches (whole game, and per cheat for JSON cheat files).

Run:  python hints_server.py            (serves http://0.0.0.0:8780)
Hints live in hints/<TITLEID>.md (e.g. hints/CUSA12345.md). Format: a normal
markdown subset: "# title", "## section", "- item", "- [ ] checkbox", plain
paragraphs, **bold**. Edit a file and the page picks it up on the next refresh.

Env: HINTS_PORT (8780), HINTS_BIND (0.0.0.0), HINTS_DIR (./hints), plus the
PS4_* settings that ps4_mcp.py reads (PS4_HOST etc.).

No login: serve it only on a private network (LAN or tailnet), never Funnel.
Read-only: it lists the PS4 sandbox over FTP and never writes anything.
"""

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.argv = [a for a in sys.argv if a != "--http"]  # never start the MCP HTTP mode from here
import ps4_mcp  # noqa: E402  (reuses current_game and the PS4 settings)

HERE = Path(__file__).parent
HINTS_DIR = Path(os.environ.get("HINTS_DIR", HERE / "hints"))
PORT = int(os.environ.get("HINTS_PORT", "8780"))
BIND = os.environ.get("HINTS_BIND", "0.0.0.0")
CACHE_SECONDS = 5

_lock = threading.Lock()
_cache: dict = {"at": 0.0, "game": None}


def _game() -> dict:
    """Running game, cached a few seconds so several phones do not hammer FTP."""
    with _lock:
        if time.time() - _cache["at"] < CACHE_SECONDS and _cache["game"] is not None:
            return _cache["game"]
        try:
            res = ps4_mcp.current_game()
            running = res.get("running", [])
            # skip launchers/homebrew with no readable param.sfo; prefer a title that has hints
            real = [g for g in running if not g.get("title", "").startswith("(param.sfo")]
            real.sort(key=lambda g: _hints_for(g.get("title_id", "")) is None)
            game = real[0] if real else {"title_id": "", "title": ""}
            game["online"] = True
        except Exception as e:  # PS4 off / FTP down: say so instead of failing the page
            game = {"title_id": "", "title": "", "online": False, "error": str(e)[:200]}
        _cache.update(at=time.time(), game=game)
        return game


def _hints_for(title_id: str) -> str | None:
    if not re.fullmatch(r"[A-Z]{4}\d{5}", title_id or ""):
        return None
    path = HINTS_DIR / f"{title_id}.md"
    return path.read_text(encoding="utf-8") if path.is_file() else None


# Switching cheats off MOVES their files out of the folders GoldHEN scans, into OFF_ROOT, and
# back. Per-cheat switches (JSON files only) take single cheats out of a file's "mods" list;
# the removed entries are kept in STATE_ROOT so they can be put back exactly. Nothing is ever
# written to game memory, and every change applies the next time the game starts.
OFF_ROOT = "/data/GoldHEN/cheats_off"
STATE_ROOT = "/data/ps4-mcp/cheat-state"
_TID = re.compile(r"[A-Z]{4}\d{5}")
_CHEAT_NAME = re.compile(r"([A-Z]{4}\d{5})_(\d\d[._]\d\d)(?:_\d+)?\.(?:json|shn)")
_games_cache: dict = {"at": 0.0, "list": None}


def _mkdir(ftp, path: str) -> None:
    try:
        ftp.mkd(path)
    except Exception:
        pass  # already there


def _cheat_files(ftp, tid: str) -> list[tuple[str, str, bool]]:
    """(format, file name, switched on) for every cheat file of a title."""
    out = []
    for fmt in ps4_mcp.CHEAT_FORMATS:
        for root, on in ((ps4_mcp.CHEAT_ROOT, True), (OFF_ROOT, False)):
            out += [(fmt, n, on) for n in ps4_mcp._names(ftp, f"{root}/{fmt}") if n.startswith(tid + "_")]
    return out


def _cheats(tid: str) -> dict | None:
    """{"files": n, "enabled": n} or None when the title has no cheat files."""
    if not _TID.fullmatch(tid or ""):
        return None
    try:
        with ps4_mcp._ftp() as ftp:
            files = _cheat_files(ftp, tid)
    except Exception:
        return None
    if not files:
        return None
    return {"files": len(files), "enabled": sum(1 for _, _, on in files if on)}


def _set_cheats(tid: str, enable: bool) -> dict:
    """Move a title's cheat files out of / back into GoldHEN's folders (never overwrites)."""
    if not _TID.fullmatch(tid):
        raise ValueError("bad title id")
    with _lock, ps4_mcp._ftp() as ftp:
        _mkdir(ftp, OFF_ROOT)
        for fmt, name, on in _cheat_files(ftp, tid):
            if on == enable:
                continue
            src_root, dst_root = (OFF_ROOT, ps4_mcp.CHEAT_ROOT) if enable else (ps4_mcp.CHEAT_ROOT, OFF_ROOT)
            _mkdir(ftp, f"{dst_root}/{fmt}")
            if name in ps4_mcp._names(ftp, f"{dst_root}/{fmt}"):
                continue  # target already exists: leave both alone
            ftp.rename(f"{src_root}/{fmt}/{name}", f"{dst_root}/{fmt}/{name}")
    return _cheats(tid) or {"files": 0, "enabled": 0}


def _read(ftp, path: str) -> bytes | None:
    import io
    buf = io.BytesIO()
    try:
        ftp.retrbinary(f"RETR {path}", buf.write)
    except Exception:
        return None
    return buf.getvalue()


def _write(ftp, path: str, data: bytes) -> None:
    import io
    ftp.storbinary(f"STOR {path}", io.BytesIO(data))


def _canon(doc: dict, side: dict) -> tuple[list, list]:
    """All cheats of a file in their original order, and which of them are on."""
    mods = list(doc.get("mods", []))
    on = [True] * len(mods)
    for r in sorted(side.get("removed", []), key=lambda r: r["index"]):
        mods.insert(r["index"], r["mod"])
        on.insert(r["index"], False)
    return mods, on


def _pick_files(names: list[str], tid: str, version: str) -> list[str]:
    """The per-cheat-capable files (json, shn) GoldHEN would use: the running version's
    (no version given: the newest)."""
    found = []
    for n in names:
        m = _CHEAT_NAME.fullmatch(n)
        if m and m.group(1) == tid:
            found.append((m.group(2).replace("_", "."), n))
    if version:  # a game: only the file for its own version (others would not be loaded)
        return sorted(n for v, n in found if v == version)
    if not found:
        return []
    newest = max(v for v, _ in found)
    return sorted(n for v, n in found if v == newest)


_SHN_CHEAT = re.compile(r"<Cheat\b[^>]*?/>|<Cheat\b[^>]*>.*?</Cheat>", re.S)
_SHN_TEXT = re.compile(r'\bText="([^"]*)"')


def _unescape(t: str) -> str:
    import html
    return html.unescape(t)


def _parse(fmt: str, raw: bytes) -> tuple[list, list[str], object]:
    """(items, display names, rebuild(kept items) -> bytes) for a json or shn cheat file."""
    if fmt == "json":
        doc = json.loads(raw.decode("utf-8-sig"))
        items = list(doc.get("mods", []))
        names = [str(m.get("name") or f"cheat {i + 1}") for i, m in enumerate(items)]

        def rebuild(kept: list) -> bytes:
            doc["mods"] = kept
            return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
        return items, names, rebuild
    bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    text = raw.decode("utf-8-sig")  # shn files are plain-text XML (their utf-16 header is nominal)
    blocks = [m for m in _SHN_CHEAT.finditer(text)]
    if not blocks:
        raise ValueError("no cheats found in that file")
    head, tail = text[: blocks[0].start()], text[blocks[-1].end():]
    items = [m.group(0) for m in blocks]
    names = []
    for i, blk in enumerate(items):
        t = _SHN_TEXT.search(blk)
        names.append(_unescape(t.group(1)) if t else f"cheat {i + 1}")

    def rebuild(kept: list) -> bytes:
        return bom + (head.rstrip() + "\n  " + "\n  ".join(kept) + "\n" + tail.lstrip()).encode("utf-8")
    return items, names, rebuild


def _locked(name: str) -> bool:
    """Master-code entries that the other cheats depend on stay on."""
    n = name.lower()
    return "mastercode" in n or "master code" in n


def _games() -> list[dict]:
    """Installed titles that have cheat files (cached a minute; reading every param.sfo is slow)."""
    with _lock:
        if time.time() - _games_cache["at"] < 60 and _games_cache["list"] is not None:
            return _games_cache["list"]
    try:
        res = ps4_mcp.installed_games(include_cheats=True)
        out = [{"id": g["title_id"], "title": g.get("title", ""), "version": g.get("version", "")}
               for g in res.get("games", []) if g.get("cheats") or g.get("cheat_versions")]
    except Exception:
        out = []
    with _lock:
        _games_cache.update(at=time.time(), list=out)
    return out


def _version_of(tid: str) -> str:
    return next((g["version"] for g in _games() if g["id"] == tid), "")


def _mods(tid: str, version: str = "") -> dict | None:
    """Per-cheat lists for a title's json/shn cheat file(s), or None if there are none."""
    if not _TID.fullmatch(tid or ""):
        return None
    try:
        with ps4_mcp._ftp() as ftp:
            files = []
            for fmt in ("json", "shn"):
                d = f"{ps4_mcp.CHEAT_ROOT}/{fmt}"
                for n in _pick_files([x for x in ps4_mcp._names(ftp, d) if x.endswith("." + fmt)], tid, version):
                    raw = _read(ftp, f"{d}/{n}")
                    if raw is None:
                        continue
                    side_raw = _read(ftp, f"{STATE_ROOT}/{n}.mods")
                    items, names, _ = _parse(fmt, raw)
                    items, names, on = _merge(items, names, json.loads(side_raw) if side_raw else {}, fmt)
                    files.append({"file": n, "mods": [
                        {"i": i, "name": nm, "on": e, "locked": _locked(nm)}
                        for i, (nm, e) in enumerate(zip(names, on))]})
    except Exception:
        return None
    return {"files": files} if files else None


def _merge(items: list, names: list, side: dict, fmt: str) -> tuple[list, list, list]:
    """Put switched-off cheats back into the list in their original positions."""
    on = [True] * len(items)
    for r in sorted(side.get("removed", []), key=lambda r: r["index"]):
        items.insert(r["index"], r["mod"])
        if fmt == "json":
            nm = str(r["mod"].get("name") or f"cheat {r['index'] + 1}")
        else:
            t = _SHN_TEXT.search(r["mod"])
            nm = _unescape(t.group(1)) if t else f"cheat {r['index'] + 1}"
        names.insert(r["index"], nm)
        on.insert(r["index"], False)
    return items, names, on


def _set_mod(tid: str, file: str, i: int, enable: bool) -> dict:
    m = _CHEAT_NAME.fullmatch(file or "")
    if not m or m.group(1) != tid:
        raise ValueError("bad cheat file")
    fmt = file.rsplit(".", 1)[1]
    with _lock, ps4_mcp._ftp() as ftp:
        path = f"{ps4_mcp.CHEAT_ROOT}/{fmt}/{file}"
        raw = _read(ftp, path)
        if raw is None:
            raise ValueError("that cheat file is switched off or missing")
        side_raw = _read(ftp, f"{STATE_ROOT}/{file}.mods")
        items, names, rebuild = _parse(fmt, raw)
        items, names, on = _merge(items, names, json.loads(side_raw) if side_raw else {}, fmt)
        if not 0 <= i < len(items):
            raise ValueError("no such cheat")
        if not enable and _locked(names[i]):
            raise ValueError("that is a master code the other cheats need; it stays on")
        on[i] = enable
        _mkdir(ftp, "/data/ps4-mcp")
        _mkdir(ftp, STATE_ROOT)
        if _read(ftp, f"{STATE_ROOT}/{file}.orig") is None:
            _write(ftp, f"{STATE_ROOT}/{file}.orig", raw)  # untouched original, kept once
        kept = [x for x, e in zip(items, on) if e]
        side = {"removed": [{"index": k, "mod": x} for k, (x, e) in enumerate(zip(items, on)) if not e]}
        _write(ftp, f"{STATE_ROOT}/{file}.mods", json.dumps(side, ensure_ascii=False).encode("utf-8"))
        _write(ftp, path + ".tmp", rebuild(kept))
        ftp.delete(path)
        ftp.rename(path + ".tmp", path)
    return _mods(tid, m.group(2).replace("_", ".")) or {"files": []}


def _state() -> dict:
    game = _game()
    tid = game.get("title_id", "")
    games = _games()
    titles = {g["id"]: g["title"] for g in games}
    ids = sorted({p.stem for p in HINTS_DIR.glob("*.md")} | set(titles))
    return {"game": game, "hints": _hints_for(tid), "cheats": _cheats(tid),
            "mods": _mods(tid, game.get("version", "")),
            "available": [{"id": i, "title": titles.get(i, "")} for i in ids]}


def _icon(size: int) -> bytes:
    """Plain PNG app icon (dark tile, blue ring), built without extra libraries."""
    import struct
    import zlib
    c, r_out, r_in = size / 2, size * 0.30, size * 0.20
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            d = ((x - c) ** 2 + (y - c) ** 2) ** 0.5
            rows += bytes((90, 162, 255, 255)) if r_in <= d <= r_out else bytes((11, 15, 26, 255))
    def chunk(t: bytes, data: bytes) -> bytes:
        body = t + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))


MANIFEST = json.dumps({
    "name": "PS4 Hints", "short_name": "PS4 Hints", "start_url": "./", "scope": "./",
    "display": "standalone", "background_color": "#0b0f1a", "theme_color": "#0b0f1a",
    "icons": [{"src": f"icon-{s}.png", "sizes": f"{s}x{s}", "type": "image/png", "purpose": "any maskable"}
              for s in (192, 512)],
})


PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0b0f1a">
<link rel="manifest" href="manifest.webmanifest">
<link rel="icon" href="icon-192.png">
<title>PS4 Hints</title>
<style>
:root{--bg:#0b0f1a;--card:#141a2b;--ink:#e8ecf6;--mute:#8d97b3;--acc:#5aa2ff;--ok:#4cd08a;--line:#232b42}
@media (prefers-color-scheme:light){:root{--bg:#f4f6fb;--card:#fff;--ink:#141a2b;--mute:#5b6580;--acc:#1b63d6;--ok:#16895a;--line:#dde2ee}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:16px;padding-bottom:40px}
header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
h1{font-size:20px;margin:0;flex:1}
.dot{width:10px;height:10px;border-radius:50%;background:var(--mute)}
.dot.on{background:var(--ok)}
.sub{color:var(--mute);font-size:13px;margin:-8px 0 14px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:12px}
section h2{font-size:15px;margin:0 0 6px;color:var(--acc)}
ul{margin:0;padding:0;list-style:none}
li{padding:7px 0;border-top:1px solid var(--line)}
li:first-child{border-top:0}
li label{display:flex;gap:10px;align-items:flex-start}
li input{margin-top:5px;width:18px;height:18px;flex:none}
li.done span{text-decoration:line-through;color:var(--mute)}
p{margin:6px 0}
.empty{color:var(--mute)}
code{background:var(--line);padding:1px 5px;border-radius:5px;font-size:14px}
.cheat{display:flex;align-items:center;gap:12px}
.cheat div{flex:1}.cheat b{display:block}.cheat small{color:var(--mute)}
.sw{flex:none;width:54px;height:32px;border-radius:16px;border:0;background:var(--line);position:relative;cursor:pointer}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:26px;height:26px;border-radius:50%;background:var(--mute);transition:.15s}
.sw.on{background:var(--ok)}.sw.on::after{left:25px;background:#fff}
.sw:disabled{opacity:.5}
li.cheat{padding:9px 0}li.cheat div{flex:1;min-width:0}
select{width:100%;padding:10px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit;margin-bottom:12px}
</style></head><body>
<header><span id="dot" class="dot"></span><h1 id="title">PS4 Hints</h1></header>
<div class="sub" id="sub">connecting…</div>
<select id="pick" hidden></select>
<main id="main"></main>
<script>
const $=id=>document.getElementById(id);
let manual="", last="";
const esc=s=>s.replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const inl=s=>esc(s).replace(/\\*\\*(.+?)\\*\\*/g,"<b>$1</b>").replace(/`(.+?)`/g,"<code>$1</code>");
function store(k,v){try{if(v===undefined)return localStorage.getItem(k);localStorage.setItem(k,v)}catch(e){return null}}
function render(md,tid){
  let out="",open=false,list=false,i=0;
  const closeList=()=>{if(list){out+="</ul>";list=false}};
  const closeSec=()=>{closeList();if(open){out+="</section>";open=false}};
  for(const raw of md.split("\\n")){
    const l=raw.trimEnd();
    if(/^# /.test(l)){continue}
    if(/^## /.test(l)){closeSec();out+="<section><h2>"+inl(l.slice(3))+"</h2>";open=true;continue}
    if(!open){out+="<section>";open=true}
    let m;
    if((m=l.match(/^- \\[( |x)\\] (.*)/i))){
      if(!list){out+="<ul>";list=true}
      const key=tid+":"+(i++)+":"+m[2];const done=store(key)==="1"||(store(key)===null&&m[1].toLowerCase()==="x");
      out+='<li class="'+(done?"done":"")+'"><label><input type="checkbox" data-k="'+esc(key)+'" '+(done?"checked":"")+'><span>'+inl(m[2])+"</span></label></li>";
    }else if((m=l.match(/^- (.*)/))){
      if(!list){out+="<ul>";list=true}
      out+="<li>"+inl(m[1])+"</li>";
    }else if(l.trim()){closeList();out+="<p>"+inl(l)+"</p>"}
  }
  closeSec();return out;
}
async function tick(){
  let s;
  try{s=await (await fetch("api/state",{cache:"no-store"})).json()}catch(e){$("dot").className="dot";$("sub").textContent="page server unreachable";return}
  const g=s.game, pick=$("pick");
  if(s.available.length){
    pick.hidden=false;
    const want=JSON.stringify(s.available);
    if(pick.dataset.o!==want){pick.dataset.o=want;pick.innerHTML='<option value="">Follow the running game</option>'+s.available.map(a=>'<option value="'+a.id+'">'+esc(a.title?a.title+" ("+a.id+")":a.id)+'</option>').join("")}
    pick.value=manual;
  }
  $("dot").className="dot"+(g.online?" on":"");
  let tid=manual||g.title_id, md=s.hints;
  if(manual){const r=await fetch("api/hints/"+manual);md=r.ok?await r.text():null}
  $("title").textContent=manual?((s.available.find(a=>a.id===manual)||{}).title||manual):(g.title||"PS4 Hints");
  $("sub").textContent=!g.online?"PS4 not reachable (off, or FTP down)":manual?"viewing "+manual+" (not following the console)":g.title_id?g.title_id+(g.version?" · v"+g.version:""):"no game running";
  let ch=manual?null:s.cheats;
  if(manual){try{ch=await (await fetch("api/cheats/"+manual,{cache:"no-store"})).json()}catch(e){}}
  cur=tid;
  const card=ch?'<section class="cheat"><div><b>Cheats</b><small>'+(ch.enabled===ch.files?"on":ch.enabled?"partly on":"off")+" · "+ch.files+" file"+(ch.files>1?"s":"")+' · applies next game launch</small></div><button id="sw" class="sw'+(ch.enabled?" on":"")+'" aria-label="Toggle cheats"></button></section>':"";
  let mo=manual?null:s.mods;
  if(manual){try{mo=await (await fetch("api/mods/"+manual,{cache:"no-store"})).json()}catch(e){}}
  const modsHtml=(mo&&mo.files&&!(ch&&ch.enabled===0))?mo.files.map(f=>'<section><h2>'+esc(f.file.replace(".json","").replace(".shn",""))+'</h2><ul>'+f.mods.map(m=>'<li class="cheat"><div>'+esc(m.name)+'</div><button class="sw mod'+(m.on?" on":"")+'"'+(m.locked?' disabled title="required by the other cheats"':'')+' data-f="'+esc(f.file)+'" data-i="'+m.i+'" aria-label="'+esc(m.name)+'"></button></li>').join("")+'</ul></section>').join(""):"";
  const html=card+modsHtml+(md?render(md,tid):(tid?'<section><p class="empty">No hints file for <code>'+esc(tid)+'</code> yet. Add <code>hints/'+esc(tid)+'.md</code> on the server.</p></section>':'<section><p class="empty">Start a game on the PS4 and its hints will show here.</p></section>'));
  if(html!==last){const y=scrollY;$("main").innerHTML=html;last=html;scrollTo(0,y)}
}
let cur="";
$("main").addEventListener("click",async e=>{
  const mb=e.target.closest(".mod");
  if(mb&&cur){
    mb.disabled=true;
    try{const r=await fetch("api/mods/"+cur,{method:"POST",headers:{"X-Hints":"1","Content-Type":"application/json"},body:JSON.stringify({file:mb.dataset.f,i:+mb.dataset.i,enabled:!mb.classList.contains("on")})});
      if(!r.ok)alert("Could not change that cheat: "+(await r.text()))}catch(err){alert("Could not reach the page server")}
    last="";tick();return;
  }
  const b=e.target.closest("#sw");if(!b||!cur)return;
  const want=!b.classList.contains("on");
  if(!confirm((want?"Turn cheats ON for ":"Turn cheats OFF for ")+cur+"? It moves the cheat files on the PS4 and takes effect the next time the game starts."))return;
  b.disabled=true;
  try{const r=await fetch("api/cheats/"+cur,{method:"POST",headers:{"X-Hints":"1","Content-Type":"application/json"},body:JSON.stringify({enabled:want})});
    if(!r.ok)alert("Could not change cheats: "+(await r.text()))}catch(err){alert("Could not reach the page server")}
  last="";tick();
});
$("pick").onchange=e=>{manual=e.target.value;last="";tick()};
$("main").addEventListener("change",e=>{const c=e.target;if(c.dataset.k){store(c.dataset.k,c.checked?"1":"0");c.closest("li").classList.toggle("done",c.checked)}});
tick();setInterval(tick,8000);
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/state":
            self._send(200, json.dumps(_state()).encode(), "application/json")
        elif path == "/manifest.webmanifest":
            self._send(200, MANIFEST.encode(), "application/manifest+json")
        elif path in ("/icon-192.png", "/icon-512.png"):
            self._send(200, _icon(int(path[6:9])), "image/png")
        elif path.startswith("/api/mods/"):
            tid = path[len("/api/mods/"):]
            self._send(200, json.dumps(_mods(tid, _version_of(tid))).encode(), "application/json")
        elif path.startswith("/api/cheats/"):
            self._send(200, json.dumps(_cheats(path[len("/api/cheats/"):])).encode(), "application/json")
        elif path.startswith("/api/hints/"):
            md = _hints_for(path[len("/api/hints/"):])
            if md is None:
                self._send(404, b"no hints", "text/plain")
            else:
                self._send(200, md.encode(), "text/plain; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        """POST /api/cheats/<TITLEID> with {"enabled": true|false}. The custom header
        stops a random web page from posting here from a browser on your phone."""
        path = self.path.split("?", 1)[0]
        if not path.startswith(("/api/cheats/", "/api/mods/")) or self.headers.get("X-Hints") != "1":
            self._send(403, b"forbidden", "text/plain")
            return
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 1000)) or b"{}")
            if path.startswith("/api/mods/"):
                res = _set_mod(path[len("/api/mods/"):], str(body.get("file", "")), int(body.get("i", -1)),
                               bool(body.get("enabled")))
            else:
                res = _set_cheats(path[len("/api/cheats/"):], bool(body.get("enabled")))
            with _lock:
                _cache["at"] = 0.0
            self._send(200, json.dumps(res).encode(), "application/json")
        except Exception as e:
            self._send(400, json.dumps({"error": str(e)[:200]}).encode(), "application/json")

    def log_message(self, fmt, *args) -> None:  # keep the console quiet
        pass


if __name__ == "__main__":
    HINTS_DIR.mkdir(exist_ok=True)
    print(f"hints page on http://{BIND}:{PORT}  (hints dir: {HINTS_DIR})", flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
