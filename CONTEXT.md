# Contributor context (paste this into your AI assistant)

This file is a self-contained brief. Paste it, plus the file(s) you want to change, into the AI assistant of
your choice (Claude, ChatGPT, Gemini, a local model, ...) and ask for the change you want. Read the
**Known issues** section first: this project is young and several things are unverified.

## What this project is
`goldhen-ps4-mcp` is a small Python toolkit for a **GoldHEN-jailbroken PS4** (tested on firmware 12.52):

| File | Purpose |
|---|---|
| `ps4_mcp.py` | An MCP server. Tools talk to the console over FTP (GoldHEN, port 2121), the kernel log (port 3232), the binloader (9090) and, read-only, ps4debug-NG (744). Runs over stdio or HTTP (`--http`, bearer token or single-owner OAuth). |
| `hints_server.py` | A tiny web page (stdlib `http.server`, no framework) that follows the running game and shows `hints/<TITLEID>.md`, with cheat on/off switches. Installable on a phone as a web app. Imports `ps4_mcp` for its FTP helpers. |
| `truenas_api.py` | Minimal TrueNAS JSON-RPC client (WebSocket, API key) used to apply the generated app definition. |
| `make_truenas_yaml.py` | Generates a TrueNAS Apps (Docker compose) definition: the MCP server, the hints page, optionally a Tailscale sidecar. The container refuses to start a script whose SHA-256 does not match the pinned hash. |
| `hints/` | Example hints file (`CUSA00000.md`). Real hints are per game. |

## Ground rules (please keep these when changing code)
1. **Writes stay in `/data` on the PS4** (`_writable()` in `ps4_mcp.py`). The hints page additionally touches
   `/data/GoldHEN/cheats*` and `/data/ps4-mcp/cheat-state`. Never write to game folders, system folders or the
   console's save data.
2. **No memory writes to running games** from the MCP tools. `check_cheats`, `read_memory`, `port_cheats` only
   read. Do not add debugger attach, watchpoints or memory patching without an explicit, opt-in design.
3. **No hard-coded addresses, hostnames, names or game titles.** Everything environment-specific comes from
   environment variables (`PS4_HOST`, `TRUENAS_HOST`, ...). This repo is public and sanitized.
4. **The hints page has no login.** It must only be served on a private network or tailnet. Never route it
   through a public tunnel. The write endpoints require an `X-Hints: 1` header; that blocks other web pages,
   it is not authentication.
5. **Reversibility:** anything that edits a cheat file must keep an untouched original and be restorable
   byte for byte (see `_set_mod`).
6. Python 3.10+, standard library where possible (the MCP server needs `mcp[cli]`, the TrueNAS client needs
   `websockets`). Keep files LF-terminated.

## Cheat file formats (GoldHEN)
- **JSON** (`/data/GoldHEN/cheats/json/<TITLEID>_<ver>.json`): `{name,id,version,process,mods:[{name,type,memory:[{offset,on,off}]}]}`.
  Offsets are relative to the first executable segment. Loaded when the game starts.
- **shn** (`.../shn/*.shn`): plain XML, one `<Cheat Text="...">` block per cheat (the header claims UTF-16 but
  the files are ASCII/UTF-8). Entries named `MasterCode` are required by the others.
- **mc4** (`.../mc4/*.mc4`): encrypted; a sibling `.mc4.xml` lists only cheat names. Cannot be edited per cheat.
- GoldHEN matches the game's version against the file name; it appears to use the higher of `APP_VER` and the
  param.sfo `VERSION`.

## How to test changes
- Run `PS4_HOST=<console ip> python ps4_mcp.py` (stdio) or `python hints_server.py` (port 8780).
- For cheat-file edits, test first on a **dummy file for a fake title id** you upload yourself, switch cheats off
  and on, and confirm the restored file equals the original. Delete the dummy afterwards.
- Anything that ports or changes cheats needs a test **in the game itself**; a green check on paper is not enough.

## Known issues and open questions (please help here)
- **Which cheat file does GoldHEN load when a game has several formats for the same version (json, shn, mc4)?**
  Unverified. Per-cheat switching edits json and shn; if GoldHEN loads the mc4 instead, switching has no effect
  for that game. A klog-based check of what GoldHEN actually loaded would settle it.
- **Per-cheat and whole-game switches are only lightly tested:** a dummy json file, and a round trip on one
  real shn file (byte-identical afterwards). Not yet confirmed end to end on a phone, and not yet confirmed that
  GoldHEN omits a switched-off cheat in its in-game menu.
- **mc4 cheats cannot be switched per cheat** (encrypted); those games only get the whole-game switch.
- **Version matching is approximate.** The page uses the running game's `APP_VER`; games whose GoldHEN cheats
  are keyed to a different version string may not show per-cheat switches.
- **Cheat porting is best effort.** `port_cheats` re-aims jumps and code caves but cannot fix constants inside a
  cave (absolute addresses, struct offsets, per-character checks). Every ported cheat needs an in-game test.
  Cheats aliased between versions (`alias_cheat`) can show in the menu yet do nothing.
- **No authentication on the hints page** (see rule 4). A real login would be a welcome addition.
- **The phone app is a web app (manifest + icon), not a native APK.** No service worker; it needs the page server
  to be reachable.
- **Empty `cheats_off` folders** are left behind on the console after switching cheats back on (the file tools
  cannot remove folders).
- **TrueNAS specifics** (hash-pinned scripts, a Tailscale sidecar, API-key deploys) were developed on one
  TrueNAS SCALE 25.04 setup. Other setups may need adjustments.
- No automated tests exist yet. Tests that fake the FTP layer would make cheat-file edits much safer to change.

## Good first contributions
- Tests for `_parse`/`_merge`/`_set_mod` using a fake FTP object.
- Detecting which cheat format GoldHEN actually loaded (kernel log parsing).
- Per-cheat support for more formats, or a read-only "what is on/off right now" view using `check_cheats`.
- A login for the hints page; a service worker for the web app.
- More game-agnostic helpers (version detection, title lookup) in `ps4_mcp.py`.

## Style of a good change
Small, focused, no new dependencies unless needed, an example of how you tested it, and a note of anything you
could not test. If you used an AI assistant, say so in the pull request and check its output against the
ground rules above: models tend to invent file formats and API details, so verify against real files.
