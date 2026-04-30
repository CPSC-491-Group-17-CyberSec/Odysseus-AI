# Odysseus-AI — Follow-up Audit (post‑teammate changes)

**Audit date:** 2026‑04‑29 (later in the day, after first audit)
**HEAD now:** `0c0cb99` ("Lots of changes to system" — Yazan Khawaldeh)
**HEAD at first audit:** `3ec5a7b`
**New commits since first audit:**
- `1271c25` — File Scanner.h, FileScannerEngine.cpp, FileScannerHash.cpp, ScanDatabase.cpp (+151 / −116, Yazan)
- `0c0cb99` — Lots of changes to system (+336 / −83, Yazan)

There is also a substantial **uncommitted** working‑tree changeset (CMakeLists, ScannerConfig, MainWindow, DashboardPage, SettingsPage, SecurityScoreCard) that wires the EDR-Lite subsystem into the live dashboard. I've included it in the review because the files are saved on disk; just be aware it isn't yet a commit.

Headline: **Yazan's two commits are good, focused, defensive engineering.** Several items I called out as Critical/High are now resolved or materially improved. Two of the most important items from the first audit — the `[DIAG:ONNX]` stdout flood and the AI-cache poisoning loop — are explicitly fixed by name. Nothing in the changeset regresses prior work. Two of my top-tier issues are still open (model retraining, response-layer wiring).

---

## 1. What was changed

### A. Committed by Yazan

**`src/core/FileScanner.h` + `FileScannerEngine.cpp` + `FileScannerHash.cpp` + `ScanDatabase.cpp`** (commit `1271c25`)

Performance + correctness sweep on the hot scanner path, labeled `P1`–`P8` in the diff:

- **P1.** Per-directory work (`toLower()` + skip-dir check) is now cached and only re-evaluated on directory change, instead of per file. Substring matching against ~60 fragments per file was a measurable cost on big trees.
- **P2.** `checkByHash()` now takes an `outSha256` out-param. The SHA-256 it computes is exposed even on a miss, so the YARA/AI fallback paths reuse it instead of re-hashing.
- **P3.** The chunked-read buffer in `hashFileSha256()` is now `static thread_local QByteArray buf(256*1024, Qt::Uninitialized)` — allocated once per worker thread, reused across files. (Bonus: bigger buffer too — 256 KB vs the prior 64 KB stack array.)
- **P4.** `runHashWorker()` snapshots `ScannerConfigStore::current()` and `odysseus_getReputationDB()` once before the loop; the prior code took those mutex-guarded calls per file across 4 worker threads.
- **P5.** `FileWorkItem::lastModified` (Qt::ISODate string) → `lastModifiedMs` (qint64 epoch ms). Cache lookup is now an integer compare; no `QDateTime::toString(Qt::ISODate)` per file. `ScanDatabase::loadScanCache()` pre-computes the integer when loading. `CacheEntry` keeps both fields for DB persistence + fast in-memory comparison.
- **P6.** Removed the `dirCount % 200 == 0 → QThread::yieldCurrentThread()` hack. The bounded queue's `m_workHasSpace` already yields naturally when workers fall behind; the manual yield was redundant.
- **P7.** Local cache buffer flushes in **batches of 500** under the merge lock instead of one giant merge at scan end. Reduces peak memory and lock-hold time at scan finalization.
- **P8.** Progress curve replaced from `min(95, dirCount * 95 / 500)` (which hard-coded a 500-dir target and stalled at 0% on small scans) to an asymptotic `95 * dirCount / (dirCount + 400)`. No hard target; smooth ramp from any tree size.

Concurrency fix:
- `m_enumDone` was previously a plain `bool` read by the worker threads. Now `std::atomic<bool>{false}` with explicit `release` store from the producer and `acquire` load in the workers. **This was an actual data race — that I missed in the first audit** — that the new code closes.

**`src/ai/AnomalyDetector.cpp`** (`0c0cb99`)
- **The `[DIAG:ONNX]` flood is fixed.** `bool diagEnabled = true; // TODO` is now a `static const bool` initialized from `getenv("ODYSSEUS_DIAG")`. Production runs are silent; you can opt in with `ODYSSEUS_DIAG=1`.

**`src/ai/EmberDetector.cpp`** (`0c0cb99`)
- Defensive check in `score()` for zero-variance features: `(s > 1e-10) ? (raw - mean)/s : 0.0`. Previously a constant feature in the scaler would produce `inf`/`nan` that LightGBM would happily accept and propagate.

**`src/core/FileScannerDetectors.cpp`** (`0c0cb99`)
- EMBER inference is now gated not only on `features[16] > 0.5` (isPE flag) but **also** on the file extension being a real Windows PE type (`exe`, `dll`, `sys`, `ocx`, `drv`, `cpl`, `scr`, `ax`, `mui`, or no extension). ELF / Mach-O binaries that happen to have a stale MZ signature in the first two bytes won't be scored against an EMBER model that was never trained on them. This was a quiet false-positive source.

**`src/core/FileScannerYaraReputation.cpp` + `include/reputation/ReputationDB.h` + `src/reputation/ReputationDB.cpp`** (`0c0cb99`)
- New method `ReputationDB::pruneAIUpserted()` deletes every row with `source='AI/local'`. Called once at DB startup in `getReputationDB()`.
- `snapshotHashIndex()` now `WHERE source IS NULL OR source != 'AI/local'` — AI guesses are excluded from the in-memory hash blocklist used for pass-1 detection.
- The header docstring spells out exactly why: *"AI auto-upserted entries cause a self-reinforcing false positive loop (AI FP → hash DB entry → permanent 'Critical' classification on every subsequent scan)."* This is a real bug — and a real fix.

**`include/ai/FileTypeScoring.h`** (`0c0cb99`)
- Per-type ceilings raised across the board (cleanCeiling 0.30→0.42, anomalousCeiling 0.55→0.68, suspiciousCeiling 0.80→0.85; PE goes higher: 0.50/0.70/0.88).
- New `minStrongForAnomalous` field on `FileTypeProfile`, defaulted per category.
- New rule at the bottom of `classifyFileCalibrated()`: if `strongCount < minStrongForAnomalous`, the verdict is suppressed to Clean. That removes the "above threshold but with no concrete indicator" Anomalous noise that the previous model produced.

**`src/core/FileScannerContext.cpp`** (`0c0cb99`)
- Steam game library paths are now in the skip-dir list (`/steamapps/common/`, `/steamapps/shadercache/`, `/steamapps/downloading/`, `/steamapps/temp/`, `~/.steam/steam/steamapps/`, `~/.local/share/Steam/steamapps/`, and the macOS equivalents).
- `m_noHashExtensions` adds **23 game asset / texture / archive extensions** (`tga`, `vtf`, `bsp`, `mdl`, `vpk`, `pk3`, `wad`, `ktx`, `dds`, `hdr`, `exr`, etc.). These never appear in malware hash DBs and produce massive FP noise on packed game data.

**`src/reputation/CodeSigning.cpp`** (`0c0cb99`)
- Linux `verifyFile()` is significantly upgraded:
  - Snap (`/snap/`) and Flatpak (`/var/lib/flatpak/`, `~/.local/share/flatpak/app/`) → `SignedTrusted` with no process spawn.
  - Pacman (`pacman -Qo`) added alongside dpkg/rpm.
  - System-path heuristic (`/usr/bin/`, `/bin/`, `/lib/`, `/opt/`, ...) → `SignedUntrusted` (weak trust) when no package manager is available.
  - Header documents the trust hierarchy explicitly.

**`src/db/ScanDatabase.cpp`** (`1271c25`) — minor: `loadScanCache()` pre-computes `lastModifiedMs`.

### B. Uncommitted (working tree)

**EDR-Lite is being wired into the live application.** This is the biggest user-visible delta in the working tree.

- `CMakeLists.txt` — adds `src/edr/SnapshotDiff.cpp`, `MonitoringService.cpp`, `SecurityScoreEngine.cpp`, `src/ui/pages/AlertsPage.cpp` and the four reusable Alert widgets (`SeverityBadge`, `AlertRow`, `FilterBar`, `AlertDetailPanel`) to the build.
- `ScannerConfig.{h,cpp}` — adds the EDR-Lite toggles (`edrLiteEnabled`, `monitoringIntervalSeconds`, four `alertOn*` flags) to the JSON config.
- `SettingsPage` — new "EDR-Lite Monitoring (Beta)" section: master switch, interval combobox (15s / 30s / 1m / 5m / 15m), and four per-category alert toggles. Wired through `markDirty()` and persisted via the existing save flow.
- `MainWindow` — constructs `MonitoringService`, an `AlertsPage`, adds the page to the sidebar between "Rootkit Awareness" and "Threat Intel", connects six EDR signals (`alertRaised`, `alertResolved`, `alertUpdated`, `tickCompleted`, `monitoringStateChanged`, plus a `SettingsPage::configSaved` hook that calls `m_monitor->reloadConfig()`).
- `DashboardPage` — adds a fifth `StatCard` ("EDR-Lite") that flips Disabled/Active/Critical based on the live tick state, and a `setSecurityReport()` path that switches the dashboard's score from the legacy file-finding count to the risk-based `EDR::scoreActiveAlerts(...)` output.
- `SecurityScoreCard` — new "Why this score" breakdown panel: each line in `ScoreReport.breakdown` becomes a row showing `−N · reason`. Replaces the opaque numeric score with explainable structure.

---

## 2. What this means for the issues from the first audit

| # | Prior issue | Status now | Notes |
|---|---|---|---|
| 1 | **Phase-5 response layer not wired in** | ❌ **Still open** | `Quarantine` button on ResultsPage is still `setEnabled(false)` with tooltip "Coming soon"; `CMakeLists.txt` still doesn't include `src/response/*.cpp`; `Allowlist::isFileIgnored()` is still not called by any detector. The whole `odysseus::response` library remains a stranded subsystem. The teammate's work focused on **EDR-Lite** integration instead, which is a different spec item. |
| 2 | **v2/v3 ML overfit on synthetic data** | ❌ **Still open** | No retraining happened. The `data/anomaly_model_v2.onnx` (1050 bytes) and `anomaly_model_v3.onnx` (1052 bytes) artifacts are unchanged. Metadata still claims `BaggedLogisticEnsemble` and `99.6% accuracy`. **However**, the new threshold raises (cleanCeiling 0.30→0.42, etc.) and the `minStrongForAnomalous` requirement materially reduce the impact — the model is given less authority to flag without a concrete indicator. |
| 3 | **`AnomalyDetector::score()` always logs to stdout** | ✅ **Fixed** | Now gated behind `getenv("ODYSSEUS_DIAG")`. Cached in a `static const bool` so the env lookup happens once. |
| 4 | **Path-aware downgrade with no signing check** | ⚠️ **Partial** | The download/cap rules in `FileScannerDetectors.cpp` still don't require a code-signing check before downgrading. **But** the Linux `CodeSigning` upgrade makes positive trust signals much more available (snap/flatpak/pacman/system-path), which sets up the future "downgrade only when trusted" wiring. |
| 5 | **Liberal skip-directory list** | ⚠️ **Partial / mixed** | The list got **wider** (Steam library, more macOS app bundle internals). On the upside, the additions are well-justified — Steam genuinely is high-noise. On the downside, this is more places an attacker can hide a payload that's never scanned. The new `m_noHashExtensions` additions for game assets are fine (those types genuinely never appear in malware DBs). |
| 6 | **Cache invalidation lacks `model_version`/`rules_version`** | ❌ **Still open** | Cache key is still `(path, mtime, size)`. Stale "clean" verdicts survive ML/rule upgrades. |
| 7 | **`LLMExplainer::explainAsync` UAF risk** | ❌ **Still open** | Still uses `std::thread(...).detach()` capturing `this` by reference. |
| 8 | **Two parallel UIs (legacy MainWindow + Pages)** | ⚠️ **Partial** | The dual rendering wasn't consolidated, **but** the new EDR-Lite integration goes through Pages only, which slows the divergence. The new "Alerts" page is Page-only by design. |
| 9 | **Zero test coverage on scanner core / AI / DB** | ❌ **Still open** | No new tests added in either commit. Worth flagging that the response-library tests still exist and still aren't wired into CI. |
| 10 | **Repo hygiene (committed `build/`, placeholder `test.txt`, `.gitignore.save`)** | ❌ **Still open** | Same as before. |

### Issues newly introduced or surfaced

- **The `m_enumDone` data race** that the new code fixes was present before. So this is a regression *I* failed to catch in the first audit, not something Yazan introduced — but credit where due, the fix is correct (`std::atomic` with `release`/`acquire` semantics).
- **AI auto-upsert feedback loop** that `pruneAIUpserted()` fixes was also a latent bug. I called out cache poisoning in the first audit but missed this related variant — the AI was writing its own guesses into the *reputation database*, which then became permanent pass-1 hash hits. Yazan caught it, fixed it cleanly, and added prune-on-startup to recover from already-poisoned databases.
- **EDR scoring in MainWindow uses `m_monitor->activeAlerts()` to recompute the dashboard score on every tick / alert raised / alert updated / alert resolved.** That's a lot of recomputes; for typical alert volumes it's fine, but worth watching if alert counts ever grow large.

---

## 3. Quality assessment of the changes

**Code quality.** Uniformly good. Each P-tagged change has a clear comment explaining why it was made. The `pruneAIUpserted()` SQL is correctly mutex-guarded and emits an info log. The `static thread_local` buffer is the right idiom. The atomic fix uses explicit memory ordering (not just default seq_cst), which means the author understood what they were doing.

**Defensiveness.** Several improvements are bug fixes with good blast-radius reasoning (`pruneAIUpserted` doesn't just stop the bleed, it cleans up existing damage). The EmberDetector zero-variance guard is the kind of small fix that prevents `nan` from quietly corrupting downstream logic.

**Scope discipline.** Each commit stays inside its title. `1271c25` is purely scanner-core; `0c0cb99` is broader but every file change is justifiable.

**Things to watch.**
- The skip-dir list keeps growing. Long-term, it should be a user-editable JSON file rather than hardcoded substrings — every addition is a place the scanner will silently never look.
- The path-cap rules in `FileScannerDetectors.cpp` are unchanged; the upgraded `CodeSigning::verifyFile` on Linux is now strong enough that a small follow-up could replace string matching with `if (CodeSigning::verifyFile(path).status == SignedTrusted)`. Worth doing while the call sites are fresh.
- The EDR-Lite integration in the working tree is well-architected (signals, dedup, score recompute on tick boundaries) but **isn't committed yet**. If your teammate's machine dies before they push, you lose ~500 lines of UI wiring. Consider asking them to commit even a WIP.

**Things that should still be tightened.**
- `pruneAIUpserted()` runs every time `getReputationDB()` first runs (i.e., every app start). That's correct behavior for unpoisoning, but the comment in the code says "Call once at startup … and after changing AI thresholds." There's no mechanism today for the second case — flipping the AI threshold doesn't invalidate the DB. Worth a TODO.
- The new `minStrongForAnomalous` rule is applied after the existing developer-file / web-content suppression. That's three layers of "don't flag this unless …" gating. The classification path is becoming hard to reason about; a single declarative table would help.
- The risk-based dashboard score path (`setSecurityReport`) replaces the legacy file-finding score entirely when EDR is active. There's no fallback to "scan results" score when EDR is off — the user just sees `setScore(report.score)` with `score=100`. Probably fine; worth verifying explicitly that the dashboard doesn't go silent when monitoring is disabled and a recent scan exists.

---

## 4. Updated top-10 (post-changes)

| Was | Now | Issue |
|---|---|---|
| 1 | 1 | Response library still not integrated (Quarantine button still "Coming soon"; allowlist still un-consulted by detectors). |
| 2 | 2 | v2/v3 ML still trained on synthetic data; metadata claims unchanged. (Mitigated, not fixed, by the new ceiling/`minStrongForAnomalous` raises.) |
| 3 | — | Stdout `[DIAG:ONNX]` flood. **Resolved.** |
| 4 | 4 | Path-aware downgrade still pure substring match; no signing check. (Linux `CodeSigning` upgrade now makes the fix easier.) |
| 5 | 5 | Skip-dir list got wider — more places attacker payloads are invisible. |
| 6 | 3 | Cache invalidation still missing `model_version` / `rules_version`. **Promoted** because the changes to thresholds and EMBER gating mean cached "clean" verdicts from before this commit are now even more stale. |
| 7 | 6 | LLM async UAF risk unchanged. |
| 8 | 8 | UI duplication unchanged in committed code; reduced in the EDR-Lite working tree. |
| 9 | 7 | Zero test coverage on scanner core / AI / DB. (Now urgent: the new threshold/ceiling/`minStrongForAnomalous` changes have no regression tests.) |
| 10 | 10 | Repo hygiene unchanged. |
| (new) | 9 | The EDR-Lite UI integration in the working tree is **uncommitted** — risk of loss. Plus new code paths (`setSecurityReport`, `appendEdrAlert`, `refreshDashboardScore`) are wholly untested. |

---

## 5. Bottom line

These are the right kind of changes: targeted, defensive, with clear rationale. They directly resolve two of the highest-impact items from the first audit (the diagnostic-stdout flood and the AI cache-poisoning loop), close a real data race I missed, raise the ML decision thresholds in a sensible way, and substantially improve Linux code-signing trust signals. The EDR-Lite UI wiring in the working tree is also a real product win.

What didn't move: the response layer is still stranded, the v2/v3 model is still trained on synthetic data, and the cache still doesn't track model versions. Of those, the response-layer integration is the cheapest thing left to do for the most user-visible payoff — the code is already written and tested, it just needs a `ResponseManager` instance in MainWindow, the Quarantine button wired to it, and `Allowlist::isFileIgnored()` calls inserted into the three `checkBy*` functions. That would close issue #1 in roughly the same effort Yazan spent on EDR-Lite.

[View the updated audit](computer:///Users/kelvincuellar/Odysseus-AI/AUDIT_REPORT_FOLLOWUP.md)
