# Developer notes

Hard-won facts about the PS4 side, for anyone changing this server.

## Console services
- **FTP (GoldHEN, default 2121)**: anonymous, full filesystem. It lacks `MLSD`, so use plain `LIST`. FTP v2.2 has
  no reboot command.
- **klog (3232)**: plain text stream. Always close the socket cleanly; if a client dies uncleanly the klog wedges
  until the console restarts. Crash details (exception, registers) appear right after `EXEC /app0/eboot.bin`.
- **binloader (9090)**: accepts ONE connection, then closes. Re-enable "BinLoader Server" in GoldHEN's settings to
  reopen it.
- **ps4debug (744)**: header `0xFFAABBCC, cmd, datalen`; success status `0x80000000`. Used read-only here:
  `PROC_LIST 0xBDAA0001`, `PROC_READ 0xBDAA0002`, `PROC_MAPS 0xBDAA0004`, `PROC_INFO 0xBDAA000A` (188-byte reply,
  title id at +108). Several processes can be called `eboot.bin` (homebrew launchers too), so the game is chosen
  by title id. Attaching the debugger or setting watchpoints on a hot write path crashed a game once, so the
  server never does.

## GoldHEN cheats
- JSON: `{name,id,version,process,mods:[{name,type,memory:[{offset,on,off}]}]}`. Offsets are relative to the first
  executable segment of the game (often `0x400000`). GoldHEN loads the file when the game launches.
- GoldHEN's cheat menu matches the **higher** of `param.sfo` `APP_VER` and `VERSION`. `alias_cheat` copies a file
  to another version name; that only fixes the menu, not the offsets.
- Code-cave cheat: the hook is `E9 rel32` (padded with NOPs) into a cave of free zero bytes that runs the patched
  logic and jumps back. Porting recomputes `rel32 = target - (address after the E9)`.
- Pitfall: caves that identify a specific character/object by a pointer's low bits or a heap address silently
  stop matching after an update. Prefer static addresses.

## Porting limits (`port_cheats`)
See the README. It re-aims branches but cannot understand a cave's logic; its report marks guesses ("best of N
matches", "far from nearest hook"). Test every ported cheat in game.

## Contributing cheats upstream
The community database is `GoldHEN/GoldHEN_Cheat_Repository`: one `json/<ID>_<ver>.json` per pull request,
formatted with `json.dumps(indent=2, ensure_ascii=False)`, original credits kept and yours appended. List what you
tested in game in the PR.
