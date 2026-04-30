# Response & Control Layer (Phase 5)

This subsystem adds **safe, reversible response actions** to the Odysseus-AI alert and scan-result flows. It is intentionally conservative: nothing is auto-quarantined, nothing is auto-killed, and nothing is ever deleted.

## Files

```
include/response/
  ResponseTypes.h     enums, structs, helper signatures
  MiniJson.h          tiny embedded JSON helper (header-only)
  Allowlist.h         user "ignore"  store
  Quarantine.h        reversible file quarantine
  ActionLog.h         append-only audit log
  ResponseManager.h   orchestrator (single entry point for the UI)
include/ui/
  ResponsePanel.h     framework-agnostic UI integration scaffold
src/response/
  ResponseTypes.cpp
  Allowlist.cpp
  Quarantine.cpp
  ActionLog.cpp
  ResponseManager.cpp
  CMakeLists.txt
src/ui/
  ResponsePanel.cpp
config/
  response_config.json  default config flags
tests/
  response_tests.cpp    self-contained test runner
```

## Architecture

```
                    UI button
                        |
                        v
    +-------------------------------------------+
    |              ResponseManager              |
    |   (single entry point, enforces safety)   |
    +-------------------------------------------+
       |          |           |            |
       v          v           v            v
   Allowlist   Quarantine  ProcessControl  ActionLog
                (POSIX kill(2))             (audit trail)
```

## Safety guarantees

| Rule                                          | Where it lives                            |
|-----------------------------------------------|-------------------------------------------|
| No automatic quarantine                       | UI never calls `execute(QuarantineFile)` without confirmation |
| No automatic kill                             | `processKillEnabled = false` by default + per-call `userConfirmed` check |
| No file delete                                | Delete is intentionally **not** in `ActionType` |
| Every destructive action requires confirmation| `requiresConfirmation()` + `ResponseManager::execute()` guard |
| Quarantine is restorable                      | `Quarantine::restore()` with conflict policy |
| Critical processes are never killable         | `criticalProcessBlocklist()` in `ResponseManager` |
| Every action is auditable                     | `ActionLog::append()` is always called |

The critical-process blocklist matches the spec: `launchd, kernel_task, WindowServer, Finder, loginwindow, systemd, init, dbus-daemon, NetworkManager`. Matching is case-insensitive on the basename of the process executable path, so `/sbin/launchd`, `LaunchD`, and `launchd` all hit.

## Storage paths

App data dir:
- macOS: `~/Library/Application Support/Odysseus-AI/`
- Linux: `~/.local/share/Odysseus-AI/` (or `$XDG_DATA_HOME/Odysseus-AI/`)

Files inside it:
- `quarantine/`                        — quarantined files, named `<orig>.<id>.quarantine`, mode 0400
- `quarantine_metadata.jsonl`          — one JSON object per entry
- `odysseus_allowlist.jsonl`           — one entry per line
- `odysseus_action_log.jsonl`          — append-only audit log

## UI integration

The Phase 5 UI work consists of: rendering the buttons returned by `odysseus::ui::buildAlertActions / buildResultActions / buildSystemStatusActions`, showing the prompt from `confirmPromptFor()` for destructive actions, and calling `ResponseManager::execute()` once the user confirms.

Buttons are auto-disabled (with a tooltip explaining why) for actions that don't apply — for example, **Quarantine** is disabled for process alerts, **Kill Process** is disabled for file alerts, **Reset Baseline** is enabled only on integrity findings, and kernel-extension alerts surface only **Investigate**.

## macOS / Linux build notes

The library is C++17 with no third-party dependencies. Use the supplied `src/response/CMakeLists.txt`:

```bash
cmake -S . -B build
cmake --build build --target odysseus_response
```

If you don't yet have a top-level CMake setup, the test runner can be built directly:

```bash
mkdir -p build
g++ -std=c++17 -Iinclude \
    src/response/ResponseTypes.cpp \
    src/response/Allowlist.cpp \
    src/response/Quarantine.cpp \
    src/response/ActionLog.cpp \
    src/response/ResponseManager.cpp \
    tests/response_tests.cpp \
    -o build/response_tests -lpthread
./build/response_tests
```

On macOS, replace `g++` with `clang++` if preferred. `-lpthread` is implicit on Apple toolchains.

## Limitations (deliberate, called out in the spec)

- **No kernel drivers, no network blocking, no cloud submission.** This phase is local-only.
- **`DisablePersistenceItem`** marks the persistence record as disabled in the app DB — it does **not** modify the system loader (e.g. it does not unload a `LaunchAgent` plist). The user must take that step manually after reviewing the data Odysseus surfaces. Tooltip and confirmation prompt say so explicitly.
- **`KillProcess`** uses POSIX `kill(2)`. On macOS/Linux the executable name is fetched best-effort (Linux: `/proc/<pid>/comm`; macOS: relies on `target.processName` populated by the alert source). Windows is out of scope.
- **`Investigate`** is the only action surfaced for kernel-extension alerts. Disabling/unloading kexts requires elevated privileges and is out of scope.
