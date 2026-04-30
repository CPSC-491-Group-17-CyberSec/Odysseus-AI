// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: tests/response_tests.cpp
//
// Lightweight self-contained tests. Avoids a unit-test framework dependency
// so it can run anywhere with just g++/clang++ and the standard library.
//
// Build (from repo root):
//   g++ -std=c++17 -Iinclude
//       src/response/ResponseTypes.cpp
//       src/response/Allowlist.cpp
//       src/response/Quarantine.cpp
//       src/response/ActionLog.cpp
//       src/response/ResponseManager.cpp
//       tests/response_tests.cpp
//       -o build/response_tests -lpthread
//   ./build/response_tests
// =============================================================================

#include "response/ActionLog.h"
#include "response/Allowlist.h"
#include "response/Quarantine.h"
#include "response/ResponseManager.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace odysseus::response;

// ---------------------------------------------------------------------------
// Tiny ad-hoc test harness.
// ---------------------------------------------------------------------------
static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__              \
                      << "  " << (msg) << "\n";                                \
            ++g_fail;                                                          \
        } else {                                                               \
            ++g_pass;                                                          \
        }                                                                     \
    } while (0)

// ---------------------------------------------------------------------------
// Test directory helpers — keep all artefacts under a per-run tmp dir so the
// tests don't pollute the user's app-data dir.
// ---------------------------------------------------------------------------
static fs::path makeTempDir() {
    fs::path base = fs::temp_directory_path() / "odysseus_phase5_tests";
    fs::remove_all(base);
    fs::create_directories(base);
    return base;
}

// ---------------------------------------------------------------------------
// Test 1: file quarantine round-trip (quarantine + restore).
// ---------------------------------------------------------------------------
static void testQuarantineRoundTrip(const fs::path& base) {
    fs::path src = base / "victim.txt";
    {
        std::ofstream out(src);
        out << "test suspicious file";
    }
    CHECK(fs::exists(src), "fixture file created");

    Quarantine q((base / "quarantine").string(),
                 (base / "metadata.jsonl").string());
    auto entry = q.quarantine(src.string(), "fakehash", "unit-test", "src-1");
    CHECK(entry.has_value(),
          "quarantine() returned an entry: " + q.getLastError());
    CHECK(!fs::exists(src), "original file no longer at original path");
    CHECK(fs::exists(entry->quarantinePath),
          "file present in quarantine: " + entry->quarantinePath);

    auto res = q.restore(entry->id, RestoreConflictPolicy::Overwrite);
    CHECK(res.success,
          std::string("restore succeeded: ") + res.errorMessage);
    CHECK(fs::exists(src), "file restored to original path");
}

// ---------------------------------------------------------------------------
// Test 2: restore with collision policy = AskUser must request a user choice.
// ---------------------------------------------------------------------------
static void testRestoreConflictAskUser(const fs::path& base) {
    fs::path src = base / "collide.txt";
    { std::ofstream out(src); out << "v1"; }

    Quarantine q((base / "quarantine2").string(),
                 (base / "metadata2.jsonl").string());
    auto entry = q.quarantine(src.string(), "", "", "src-2");
    CHECK(entry.has_value(), "quarantine v1");

    // Recreate the file at the original path so restore hits a collision.
    { std::ofstream out(src); out << "v2"; }
    auto res = q.restore(entry->id, RestoreConflictPolicy::AskUser);
    CHECK(!res.success && res.needsUserChoice,
          "AskUser policy bubbles up needsUserChoice");

    // Restore-with-new-name should succeed and pick a non-conflicting path.
    res = q.restore(entry->id, RestoreConflictPolicy::RestoreWithNewName);
    CHECK(res.success && res.newPath != src.string(),
          "RestoreWithNewName picked a unique destination");
}

// ---------------------------------------------------------------------------
// Test 3: allowlist add/contains/remove + suppression helpers.
// ---------------------------------------------------------------------------
static void testAllowlist(const fs::path& base) {
    Allowlist a((base / "allowlist.jsonl").string());

    AllowlistEntry e;
    e.kind = AllowlistEntry::Kind::FileSha256;
    e.value = "deadbeefcafef00d";
    e.note = "noisy false-positive";
    CHECK(a.add(e), "add by SHA-256");
    CHECK(a.contains(e.kind, e.value), "contains after add");
    CHECK(a.isFileIgnored("/some/path", e.value),
          "isFileIgnored matches by sha256");

    CHECK(a.add(e), "duplicate add is a no-op success");
    CHECK(a.list().size() == 1, "no duplicate appended");

    CHECK(a.remove(e.kind, e.value), "remove succeeds");
    CHECK(!a.contains(e.kind, e.value), "no longer contains after remove");
}

// ---------------------------------------------------------------------------
// Test 4: ResponseManager confirmation guard — destructive without
// userConfirmed must fail with no side effect.
// ---------------------------------------------------------------------------
static void testResponseManagerGuards(const fs::path& base) {
    auto allowlist  = std::make_shared<Allowlist>(
        (base / "rm_allow.jsonl").string());
    auto quarantine = std::make_shared<Quarantine>(
        (base / "rm_q").string(), (base / "rm_q_md.jsonl").string());
    auto log        = std::make_shared<ActionLog>(
        (base / "rm_log.jsonl").string());

    ResponseManager mgr(allowlist, quarantine, log,
                        makeDefaultProcessControl(),
                        makeNoopUiBridge(),
                        ResponseConfig{/*responseActionsEnabled*/ true,
                                       /*quarantineEnabled*/      true,
                                       /*processKillEnabled*/     true,
                                       /*allowlistEnabled*/       true});

    // Build a fake process target.
    ActionRequest killReq;
    killReq.action = ActionType::KillProcess;
    killReq.target.kind = TargetKind::Process;
    killReq.target.pid  = 99999999;            // bogus
    killReq.target.processName = "definitely_not_real";
    killReq.userConfirmed = false;

    auto res = mgr.execute(killReq);
    CHECK(!res.success && !res.errorMessage.empty(),
          "kill without userConfirmed is rejected");

    // Now confirm AND target a critical-process name. Must still fail.
    killReq.userConfirmed = true;
    killReq.target.processName = "/sbin/launchd";
    res = mgr.execute(killReq);
    CHECK(!res.success && res.errorMessage.find("critical") != std::string::npos,
          "critical-process blocklist denies launchd");

    // Allowlist add via manager.
    ActionRequest allowReq;
    allowReq.action        = ActionType::AddToAllowlist;
    allowReq.userConfirmed = true;
    allowReq.target.kind   = TargetKind::File;
    allowReq.target.sha256 = "abc123def456";
    res = mgr.execute(allowReq);
    CHECK(res.success, "allowlist add via manager succeeds");
    CHECK(allowlist->contains(AllowlistEntry::Kind::FileSha256, "abc123def456"),
          "allowlist actually mutated");

    // Audit log should have at least three records by now.
    auto records = log->readAll();
    CHECK(records.size() >= 3, "audit log captured all actions");
}

// ---------------------------------------------------------------------------
// Test 5: critical-process blocklist matching is case-insensitive and works
// with absolute paths.
// ---------------------------------------------------------------------------
static void testCriticalProcessMatching() {
    CHECK(ResponseManager::isCriticalProcessName("launchd"),       "launchd");
    CHECK(ResponseManager::isCriticalProcessName("LaunchD"),       "case-insensitive");
    CHECK(ResponseManager::isCriticalProcessName("/sbin/launchd"), "abs path");
    CHECK(ResponseManager::isCriticalProcessName("WindowServer"),  "WindowServer");
    CHECK(!ResponseManager::isCriticalProcessName("bash"),         "bash is not critical");
    CHECK(!ResponseManager::isCriticalProcessName(""),             "empty is not critical");
}

// ---------------------------------------------------------------------------
// main.
// ---------------------------------------------------------------------------
int main() {
    fs::path tmp = makeTempDir();
    std::cout << "[i] using temp dir: " << tmp << "\n";

    testQuarantineRoundTrip(tmp);
    testRestoreConflictAskUser(tmp);
    testAllowlist(tmp);
    testResponseManagerGuards(tmp);
    testCriticalProcessMatching();

    std::cout << "\n[summary] " << g_pass << " passed, " << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}
