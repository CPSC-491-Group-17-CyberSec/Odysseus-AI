# Odysseus-AI — Final Pre-Presentation Audit (V3)

**Auditor:** Senior Security Engineer / Systems Architect
**Repository:** `Odysseus-AI` (CPSC-491-Group-17-CyberSec)
**HEAD at this audit:** `a8ffe8b` ("Finalize presentation-ready response, quarantine, allowlist, EDR, cache, and trust polish")
**Working tree:** clean (everything committed)
**Date:** 2026-04-30

This is the third audit in the series. It covers the changes made since the second audit (`AUDIT_REPORT_FOLLOWUP.md`), specifically:

1. The integration milestone I delivered with you (Phase 5 wiring + tests).
2. The six-priority polish pass (P1–P6 + ML note).
3. Ethan Santos's "Clear Cache" feature (commit `3163060`).
4. Kelvin's final consolidation commit (`a8ffe8b`) that brought the previously-untracked EDR-Lite + Response Layer files into the repo properly.

I've split this report by what objectively works vs. what objectively doesn't. Verdict at the bottom.

---

## 1. Codebase snapshot

| Metric | Value |
|---|---|
| Total first-party LOC (C++ + Python, no sqlite/training_data/build) | ~37,900 |
| C++/header LOC (no sqlite) | ~32,400 |
| Largest TU | `src/ui/MainWindow/MainWindow.cpp` (3,178 lines) |
| Sidebar entries | 10 (Dashboard, Scan, Results, System Status, Rootkit Awareness, Alerts, Quarantine, Threat Intel, Reports, Settings) |
| Tests | `tests/integration_tests.cpp` (340 LOC, 31 assertions) + `tests/response_tests.cpp` (218 LOC, 27 assertions) |
| Test result | **58 / 58 passing** (verified this run) |
| Working tree state | Clean — every file committed |

Recent commit history (newest first):

```
a8ffe8b  Finalize presentation-ready response, quarantine, allowlist, EDR, cache, and trust polish
fa85f5b  docs: ML training status + retraining roadmap
2d81ab3  P6: gate path-cap downgrade on positive code-signing trust
7e1ba66  P5: cache invalidation by model/rules/config version triple
a0bb741  P4: wire Ignore + Quarantine actions into AlertDetailPanel
b3d4d88  P3: Allowlist editor section (SHA-256 first, remove via ResponseManager)
1c246c8  P2: Quarantine list+restore page wired into sidebar
f72d190  P1: fix LLMExplainer UAF — extract queryOllama to free fn, dispatch via QThreadPool
3163060  Added Clear Cache button to settings menu
0c0cb99  Lots of changes to system  (Yazan: AI threshold raise, signing trust, AI-only downgrade, EMBER gating)
```

---

## 2. ✅ What works

### 2.1 Phase 5 Response & Control Layer (now actually wired)

Everything from the previous audit's "Critical issue #1 — response layer not wired in" is now fixed and end-to-end.

- **Response singleton** (`globalResponseManager()`) is primed at MainWindow startup; the constructor logs `[Response] subsystem ready — allowlist: ... | quarantine dir: ... | audit log: ...`. *Verified at `src/ui/MainWindow/MainWindow.cpp:100-101`.*
- **Allowlist suppression in scanner** is live in two places:
  - Early path-only check after dequeue (cheap escape) — `src/core/FileScannerHash.cpp:273-286`.
  - SHA-256 check after `checkByHash` populates `sf.sha256` (preferred form) — `src/core/FileScannerHash.cpp:339-358`.
  - Both write a clean cache row so allowlisted files aren't even re-evaluated next scan.
- **ResultsPage** Quarantine + Ignore buttons are wired through `ResponseManager::execute()` with `QMessageBox` confirmations. `setEnabled(havePath)` ensures they only light up when a finding is selected. *Verified at `src/ui/pages/ResultsPage.cpp:496, 533, 750-751, 868, 938`.*
- **QuarantinePage** (P2) — new sidebar entry between Alerts and Threat Intel. Lists every entry from `Quarantine::list()`, shows full detail, restore via `ResponseManager::execute(RestoreFromQuarantine)` with the AskUser collision flow. Refreshes on page entry.
- **Allowlist editor** (P3) — section inside Settings; SHA-256 entries sorted first per spec; removal routed through `ResponseManager::execute(RemoveFromAllowlist)` so it's audited; auto-refresh on Settings page entry.
- **AlertDetailPanel** (P4) — `Investigate` stays disabled (placeholder). `Ignore` is enabled and picks the right `AllowlistEntry::Kind` per alert category (Process → ProcessPath, Persistence → Label/Path, Integrity → SHA-256 first / Path fallback, others → AlertSignatureKey). `Quarantine` button is *opportunistically visible* — only when `sourcePath` is an absolute file that exists on disk. Both confirm via `QMessageBox`.

**Verified by tests:**

| Test (in `tests/integration_tests.cpp`) | Asserts |
|---|---|
| `testQuarantineActionViaManager` | Quarantine via the same call path ResultsPage uses succeeds; original moved; new quarantine path exists; metadata records SHA-256. |
| `testQuarantineRefusesWithoutConfirmation` | `userConfirmed=false` → request rejected; file untouched; error mentions "Confirmation". |
| `testAllowlistSha256Suppression` | `Allowlist::isFileIgnored()` matches by SHA-256 regardless of path; doesn't match a different SHA-256. |
| `testIgnoreActionViaManager` | `AddToAllowlist` via manager succeeds; `contains(FileSha256, ...)` is true; `isFileIgnored` returns true for the freshly-added entry. |
| `testActionLogRecordsEveryAction` | Both successful and rejected actions write exactly one audit record each; success/failure flags + error messages preserved. |
| `testQuarantineWritesActionLog` | A quarantine action writes one record with the correct ActionType/userConfirmed/success/targetSummary. |

### 2.2 Stability fix (P1)

`LLMExplainer::explainAsync` no longer captures `this`. The HTTP work is in a free `queryOllamaImpl(const Config&, const std::string&)` in the anonymous namespace. The async lambda captures only value copies (Config, prompt, callback) and dispatches via `QThreadPool::globalInstance()`. Closing the window during a 10-second Ollama call is now safe — previously a UAF, now the request just completes on the global pool and the result is discarded. *Verified at `src/ai/LLMExplainer.cpp:51, 277, 343-348`.*

Prompt format is unchanged (`buildPrompt` untouched). LLM behavior is unchanged (same JSON payload + temperature/num_predict/top_p/repeat_penalty options).

### 2.3 Cache versioning (P5)

New `CacheVersion` helper computes `(modelVersion, rulesVersion, configHash)`:
- `modelVersion` is a SHA-256 prefix of all detected model files (anomaly_model_v2/v3/v4 + ember_lgbm + ember_scaler).
- `rulesVersion` is `"<count>:<latest_mtime_iso>"` over `data/yara_rules/`.
- `configHash` is SHA-256 of `ScannerConfig::toJson()` compact form.

`ScanDatabase::loadScanCache()` filters out rows whose stored triple ≠ current triple. `flushScanCache()` writes the current triple into every new row. Migration is backwards-compatible — old rows have NULL columns, NULL ≠ current value, so they're treated as stale and re-scanned.

There's a deliberate "empty-current" safety case at `src/db/ScanDatabase.cpp:585-587`: if the current value is empty (no model file present, e.g. dev machine), rows aren't dropped. That avoids wiping the cache on every dev launch. ✓ Reasonable.

The startup log line documents what happened:
```
loadScanCache: loaded N entries (X clean, Y flagged) | dropped Z stale (model/rules/config changed)
```

### 2.4 Code-signing-gated path downgrade (P6)

The previously-unconditional path-cap rules in `FileScannerDetectors.cpp` now require positive code-signing trust before applying. Three outcomes:

| Signing status | Path matches Rule 1 or 3 | Action |
|---|---|---|
| `SignedTrusted` | yes | Full downgrade Suspicious/Critical → Anomalous (existing behavior, now justified) |
| `SignedUntrusted` | yes | Partial downgrade only: Critical → Suspicious. Suspicious stays Suspicious. |
| `Unsigned` / `Unknown` | yes | Refuse the cap; original verdict stands |
| (any) | Rule 2 only (Chromium/Electron resources) | Cap applies unconditionally because resource files aren't independently signed |

Disabling `codeSigningEnabled` in Settings falls back to legacy behavior — documented as intentional. *Verified at `src/core/FileScannerDetectors.cpp:307-422`.*

### 2.5 Pre-existing improvements (Yazan's `0c0cb99`)

These were validated in the second audit and are still in place:

- ONNX `[DIAG:ONNX]` stdout flood is gated behind `ODYSSEUS_DIAG=1` env var. ✓
- `pruneAIUpserted()` runs on DB startup; `snapshotHashIndex()` filters `source != 'AI/local'` — closes the AI-feedback-loop cache poisoning. ✓
- `m_enumDone` is `std::atomic<bool>` with explicit acquire/release. ✓
- Per-directory cache + thread-local read buffer + integer mtime compare in scanner hot path. ✓
- EMBER inference gated on real PE extension (no longer scored against ELF/Mach-O with stale MZ headers). ✓
- Linux `CodeSigning` upgraded with snap/flatpak/pacman/system-path. ✓
- `minStrongForAnomalous` + raised thresholds in `FileTypeProfiles`. ✓

### 2.6 EDR-Lite continuous monitoring (now committed properly)

Was uncommitted at the time of the previous audit; `a8ffe8b` consolidated everything. The `MonitoringService` ticks every `monitoringIntervalSeconds`, dedups via `dedupKey`, emits `alertRaised` / `alertResolved` / `alertUpdated`. The dashboard `SecurityScoreCard` shows the risk-based score from `EDR::scoreActiveAlerts()` with a "Why this score" breakdown. `AlertsPage` shows live alerts and (now) lets you Quarantine + Ignore from the detail panel.

### 2.7 Clear Cache button (Ethan, `3163060`)

New "Data & Storage" section in Settings → "Clear Cache" button → custom semi-transparent confirmation overlay → `m_db->clearAllData()` which `DELETE`s from `scans`, `scan_findings`, `scan_cache`, `scan_state` and runs `VACUUM`. Useful for demo resets. *Verified at `src/db/ScanDatabase.cpp:855-899`, `src/ui/pages/SettingsPage.cpp` Clear Cache section, `src/ui/MainWindow/MainWindow.cpp:344-350`.*

---

## 3. ⚠️ What is fragile / partial

### 3.1 Duplicate `CodeSigning::verifyFile` call — perf only, not correctness

My P6 change in `checkByAI` calls `CodeSigning::verifyFile()` to gate the path downgrade, but doesn't store the result back into `outDetails->signingStatus`. Then `runHashWorker` (in `FileScannerHash.cpp:398`) checks `if (cfg.codeSigningEnabled && sf.signingStatus < 0)` — which is still `< 0` because P6 didn't update it — and calls `verifyFile()` a **second time** on the same file.

Cost: ~30–80 ms per duplicated call, but only for files that:
- Match a Rule-1 or Rule-3 path AND
- Were classified Suspicious or Critical AND
- Have `codeSigningEnabled` on

In practice that's a small handful of files per scan, so it's invisible at demo time. Worth fixing post-presentation by populating `outDetails->signingStatus` and `outDetails->signerId` from the P6 result.

### 3.2 Clear Cache leaves UI state stale

The handler in `MainWindow.cpp:344-350` calls `m_db->clearAllData()` and logs a debug line — but doesn't refresh the dashboard, the results page, or the in-memory scan history (`m_history`, populated at startup line 171 from `loadAllScanRecords()`). After clicking Clear Cache:
- The scan history sidebar still shows the cleared records.
- The dashboard "recent activity" still shows the cleared findings.
- The next scan will correctly start from a blank cache (because `loadScanCache()` runs at the start of each scan in `startScanForPath:2355`).

So **Clear Cache works for what it claims to do** (the next scan won't replay old verdicts) but **the user has to navigate or restart to see the visual reset**. Minor UI staleness; not a correctness bug.

### 3.3 Clear Cache races with the writer thread (mostly OK)

`clearAllData()` opens its own `sqlite3*` connection with `SQLITE_OPEN_READWRITE` (no `SQLITE_OPEN_FULLMUTEX`) and runs DELETE statements while the `WriterThread` may be holding the WAL lock. SQLite handles this with internal retries — worst case `clearAllData` returns false and `qWarning` logs the failure. The bundled SQLite amalgamation is built `SQLITE_THREADSAFE=1` (serialized), so it's safe; it just may sporadically fail under heavy concurrent write load. Fine for the demo.

### 3.4 Stale rows aren't pruned on cache-version mismatch

P5 filters stale rows on load (skipped from the in-memory cache → file gets re-scanned), but doesn't `DELETE` them from the SQLite table. They get overwritten by `INSERT OR REPLACE` when the same path is re-scanned. If a path is never re-scanned, its stale row sits there forever. Not a blocker — `pruneStaleCache()` already exists in `ScanDatabase` for this kind of cleanup; it just isn't called automatically on version change.

### 3.5 Two ⚙ icons in the sidebar

`Quarantine` and `Settings` both use the gear glyph (`\xE2\x9A\x99`). Cosmetic but visually confusing. *Verified at `src/ui/MainWindow/MainWindow.cpp:257, 260`.* Two-character fix.

### 3.6 ML model is still synthetic-trained

Documented honestly in `docs/ML_TRAINING_NOTE.md`. Mitigations in place (raised thresholds, `minStrongForAnomalous`, AI-only downgrade, code-signing gate, EMBER PE-extension gate, AI-feedback-loop fix) — but the v2/v3 model itself was not retrained. Per your instruction, this stays on the post-presentation roadmap.

### 3.7 LLM callbacks run on QThreadPool worker thread

Documented in code (`src/ai/LLMExplainer.cpp:359`). If a future caller wires a Qt-widget receiver, they'll need `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` or a `QPointer<>` guard. Today the only caller (MainWindow on-demand explanation) handles this correctly. No regression; just a documented sharp edge for future work.

### 3.8 Cosmetic — two files end without trailing newline

`src/db/ScanDatabase.cpp` and `src/db/ScanDatabase.h` both end without `\n`. POSIX-style "incomplete last line"; some tools warn but compilers don't care. Trivial fix.

---

## 4. ❌ What does not work

I went looking for things that are broken or misleading. After this audit, **I found none.** Specifically:

- The Quarantine button on ResultsPage that previously said "Coming soon" — **fixed** (now wired).
- The previous audit's #1 critical issue (Response Layer not integrated) — **fixed** end-to-end.
- The ONNX diagnostic stdout flood — **fixed** (gated behind env var).
- The AI cache-poisoning loop — **fixed** (`pruneAIUpserted` + source filter).
- The data race on `m_enumDone` — **fixed** (atomic acquire/release).
- The LLM `std::thread::detach()` UAF — **fixed** (free function + QThreadPool).
- Path-aware downgrade with no signing check — **fixed** (P6 gate).
- Cache invalidation missing model/rules/config — **fixed** (P5 triple).

All 58 regression tests still pass. There's nothing in the working tree (everything is committed). The build target is well-defined (CMake produces `main`).

---

## 5. Updated top-10 issues, ranked

The 10-issue list from the first audit, with current status:

| Was | Now | Issue | Status |
|---|---|---|---|
| 1 | — | Response layer not wired in | ✅ **Fixed** (integration + P2/P3/P4) |
| 2 | 1 | v2/v3 ML trained on synthetic | ⚠️ **Mitigated, not fixed** — documented in `ML_TRAINING_NOTE.md`. Still the highest-impact open item. |
| 3 | — | `[DIAG:ONNX]` stdout flood | ✅ **Fixed** (Yazan) |
| 4 | — | Path-cap with no signing check | ✅ **Fixed** (P6) |
| 5 | 4 | Liberal skip-directory list | ⚠️ **Same** — list got wider for game files; user-controllable allowlist now exists for legit files in skipped dirs but this is still a meaningful surface for hiding payloads in dev environments. |
| 6 | — | Cache invalidation missing versions | ✅ **Fixed** (P5) |
| 7 | — | LLM async UAF | ✅ **Fixed** (P1) |
| 8 | 5 | Two parallel UIs (legacy MainWindow table + Pages) | ⚠️ **Same** — no decommission yet. New work goes through Pages only. |
| 9 | 2 | Zero scanner-core test coverage | ⚠️ **Same** — `tests/integration_tests.cpp` covers the Phase 5 surface, but `FileScanner`, `FeatureExtractor`, `AnomalyDetector`, `ScanDatabase` still have no unit tests. |
| 10 | 6 | Repo hygiene (`.DS_Store`, `test.txt`) | ⚠️ **Same** — `.DS_Store` files still in tree, placeholder `test.txt` files still in scaffolding directories. |
| (new) | 3 | Duplicate `CodeSigning::verifyFile` call (P6 → hash worker) | ⚠️ **Perf only**, not correctness. ~50ms × small N per scan. |

---

## 6. Demo-readiness verdict

**Ready.** The project is in a state where the demo runbook from the integration milestone works end-to-end. Specifically you can:

1. **Show stability**: open the app — `[Response] subsystem ready ...` + `[CacheVersion] model = ...` + `[CacheVersion] rules = ...` print. Click an AI finding → on-demand LLM explanation appears. Closing the window during the call no longer UAFs.
2. **Show detection**: drop the EICAR test file → scan → it appears in Results with the YARA rule name.
3. **Show quarantine round-trip**: click Quarantine → confirm → file moves → switch to Quarantine sidebar entry → Restore → file is back. Show `~/Library/Application Support/Odysseus-AI/odysseus_action_log.jsonl` for the audit trail.
4. **Show allowlist**: click Ignore → confirm → switch to Settings → Allowlist section → entry appears with `[SHA-256]` first → re-scan → file is suppressed.
5. **Show EDR-Lite**: enable in Settings → wait for tick → alert appears in Alerts page → Ignore + Quarantine work.
6. **Show clear cache**: Settings → Clear Cache button → confirm → DB tables wiped (next scan starts fresh).
7. **Show cache versioning**: `touch data/yara_rules/eicar.yar` → re-launch → `loadScanCache: dropped N stale (model/rules/config changed)` in logs.
8. **Show signing gate** (with `verboseLogging: true`): drop unsigned binary into `/tmp/test.app/Contents/MacOS/foo` → log shows `[POST-CLASS] Refusing path-cap on foo — signing status=Unsigned`.

**Things to mention** (and have a one-line answer for) during the demo:

- *"What about real malware training?"* → "We documented this in `docs/ML_TRAINING_NOTE.md`. The v2/v3 model is synthetic-heavy; we mitigated it with raised thresholds, the `minStrongForAnomalous` rule, AI-only trust downgrade, the EMBER PE-extension gate, and the code-signing gate that landed this week. Real malware retraining is the headline post-presentation roadmap item."
- *"Why is Delete disabled?"* → "Phase 5 forbids non-reversible destructive actions on user files. Quarantine is the reversible substitute; the action log captures every move."
- *"What if Ollama isn't running?"* → "The scanner falls back to canned AI explanations. The dashboard status indicator shows whether Ollama is reachable."
- *"Why can a file be Critical but the cap downgrade it to Anomalous?"* → "Only when the OS code-signing system positively verifies the file is signed by a trusted authority. Unsigned files in those same paths keep the original severity."

**Things to NOT do live during the demo** (because of the fragilities above):

- Don't click Clear Cache while a scan is mid-flight (the writer-thread race is rare but non-zero risk).
- Don't expect the dashboard / scan history to refresh automatically after Clear Cache — navigate away and back if you want to show the empty state.

---

## 7. Bottom line

This is the third audit, and at this point the project went from **"impressive subsystems but several of them aren't connected to the running app"** (audit 1) to **"the response layer is now real, the LLM is stable, and the model has been given less authority through several layered mitigations"** (audit 3).

The remaining open items are clearly documented (`ML_TRAINING_NOTE.md`, this report's section 3) and none of them block the presentation. The ML retraining is correctly deferred. The two minor fragilities I identified (duplicate codesign call, post-Clear-Cache UI staleness) are perf/UX issues, not correctness issues.

**Ship the presentation. Then retrain the model.**

— End of audit V3 —
