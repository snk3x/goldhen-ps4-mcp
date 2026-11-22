# goldhen-ps4-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI assistant (Claude Code, claude.ai, any MCP
client) work with a **GoldHEN-jailbroken PS4** over your LAN: browse and push files, read the kernel log,
manage GoldHEN cheats, and **port cheats to a new game version** by reading the running game's memory.

Tested on firmware 12.52 with GoldHEN and ps4debug-NG. Unofficial, use at your own risk, only on a console and
games you own.

**Want to contribute?** See [CONTEXT.md](CONTEXT.md): a brief you can paste into your own AI assistant, with the
ground rules and the known issues (several things are still unverified).

## Tools
| Tool | What it does |
|---|---|
| `ps4_status` | Which services (FTP, klog, binloader, ps4debug) are reachable |
| `list_dir`, `read_text`, `download` | Browse and read files on the PS4 (FTP) |
| `upload`, `make_dir`, `delete` | Write files, **confined to `/data`** |
| `read_klog` | Capture the kernel log (crash details) |
| `current_game`, `installed_games` | What is running / installed, with versions and matching cheat files |
| `list_cheats`, `alias_cheat`, `add_cheat` | Inspect, copy between versions, or add GoldHEN JSON cheats |
| `goldhen_config` | Read or change one existing key in `config.ini` (with backup) |
| `send_payload`, `reboot_ps4` | Send a payload to the binloader; reboot (requires `confirm=True`) |
| `check_cheats` | Read the running game's memory: is each cheat **on / off / mismatch**? |
| `read_memory` | Hex dump of the running game's memory (read-only) |
| `port_cheats` | Port a game's cheat file to the **running** game version (see below) |

### Cheat porting
GoldHEN cheats are byte patches at fixed offsets, so a game update usually breaks them. `port_cheats`
reads the running game's code through ps4debug (**read-only**: no debugger attach, no memory writes), then:
1. finds each patch site again by its original bytes (a unique hit wins; otherwise the hit matching the nearest
   site's shift),
2. moves code caves into the zero padding at the end of the code segment,
3. re-aims every relative jump/call, and reports per cheat: ok, notes (guesses) or issues (skipped).

It cannot fix version-specific constants *inside* a cave (absolute addresses, struct offsets, "this character
only" pointer checks), so **every ported cheat still needs an in-game test**. `check_cheats` shows what is
actually applied while you test. Worked example: a 26-cheat file moved between two versions of a large game and
matched a hand port exactly.

## Setup
```
pip install "mcp[cli]"
set PS4_HOST=192.168.0.50      # your PS4's IP (PowerShell: $env:PS4_HOST="192.168.0.50")
python ps4_mcp.py              # stdio, e.g.:  claude mcp add ps4 -- python ps4_mcp.py
```
Needs GoldHEN's FTP server (port 2121 by default). For `check_cheats`/`read_memory`/`port_cheats`, load the
ps4debug-NG payload (v1.3.4 supports 12.52) through GoldHEN's binloader (not bundled here) and make sure the game is
running.

## Phone hints page and cheat switch (`hints_server.py`)
A small web page that follows the game running on the PS4 and shows your own notes for it, with a per-game
**cheats on/off switch**. Open it on a phone (it installs to the home screen as a web app).

- Hints live in `hints/<TITLEID>.md` (see `hints/CUSA00000.md`): `## Section` cards, `- bullets`, `- [ ] checkboxes`
  (ticks are remembered on the phone). Edit a file and the page picks it up on its next refresh.
- A **whole-game switch** moves that title's cheat files out of `/data/GoldHEN/cheats/` into
  `/data/GoldHEN/cheats_off/` (a folder GoldHEN does not scan) and back.
- **Per-cheat switches** appear for games whose JSON or shn (XML) cheat file matches the game version; master-code entries stay on. Switching a cheat off
  removes it from the file's `mods` list; the removed entry and an untouched copy of the original are kept in
  `/data/ps4-mcp/cheat-state/`, so it is restored exactly. (Encrypted mc4 files cannot be split per cheat.) The page also lists every installed title that has cheats, so you can set them before launching.
- Nothing is written to game memory; every change applies the next time the game starts.
- Run it: `PS4_HOST=<ip> python hints_server.py` (port 8780), or as the `ps4-hints` service that
  `make_truenas_yaml.py` adds to the TrueNAS app (tailnet-only on port 8443 with the Tailscale sidecar).
- **No login.** Serve it only on a private network or tailnet; never put it behind a public tunnel. The write
  endpoint needs a custom header, which stops other web pages from toggling cheats, but is not authentication.
- `truenas_api.py` (needs `pip install websockets`, `TRUENAS_HOST` and a TrueNAS API key in
  `TRUENAS_API_KEY` or `~/.truenas/api_key`) applies the generated YAML through the TrueNAS API instead of
  pasting it into the UI.

## Config (environment variables)
| Variable | Default | |
|---|---|---|
| `PS4_HOST` | **required** | PS4 IP address |
| `PS4_FTP_PORT` / `PS4_KLOG_PORT` / `PS4_PAYLOAD_PORT` / `PS4_DEBUG_PORT` | 2121 / 3232 / 9090 / 744 | |
| `PS4_WORKDIR` | `./work` | The only local folder the file tools can read or write |
| `PS4_MCP_TOKEN` | generated | Bearer token for HTTP mode (stored in `<workdir>/.mcp_token`) |
| `HINTS_PORT` / `HINTS_BIND` / `HINTS_DIR` | 8780 / 0.0.0.0 / `./hints` | Hints page (`hints_server.py`) |
| `PS4_MCP_PUBLIC_URL` | unset | Public https URL; turns on a single-owner OAuth server for claude.ai connectors |

## HTTP mode and exposing it
`python ps4_mcp.py --http` serves MCP over HTTP and **requires `Authorization: Bearer <token>`**. Do not
expose it to the internet without OAuth (`PS4_MCP_PUBLIC_URL`) or another auth layer: these tools can write to
your console. `make_truenas_yaml.py` generates a TrueNAS Apps definition (optionally with a Tailscale Funnel
sidecar); see its docstring. (In Git Bash on Windows, set `MSYS_NO_PATHCONV=1` so `/mnt/...` paths are not rewritten.)

## Safety rules built in
- Uploads, deletes and directory creation are confined to `/data` on the PS4.
- Local file access is confined to `PS4_WORKDIR`; files named `.mcp_*` (tokens) are unreachable.
- Memory tools are read-only. `reboot_ps4` and `send_payload` are meant to be used only after asking the user.

## License
MIT. Contributions welcome: issues and pull requests, especially more cheat-format support, porting heuristics
and tests against other games.
