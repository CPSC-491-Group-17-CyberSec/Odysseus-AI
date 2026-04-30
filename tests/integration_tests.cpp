// =============================================================================
// Odysseus-AI  -  Phase 5 Integration Tests
// File: tests/integration_tests.cpp
//
// Regression tests for the Phase 5 Response & Control Layer integration.
// Validates the contract used by ResultsPage's Quarantine / Ignore buttons
// and by the scanner's Allowlist suppression path.
//
// These tests are independent of Qt — they construct the response objects
// directly (same default ResponseManager() behavior the global singleton
// uses) and exercise the same calls the production code makes.
//
// Build (from repo root):
//
//   g++ -std=c++17 -Iinclude
//       src/response/ResponseTypes.cpp
//       src/response/Allowlist.cpp
//       src/response/Quarantine.cpp
//       src/response/ActionLog.cpp
//       src/response/ResponseManager.cpp
//       src/response/ResponseManagerSingleton.cpp
//       tests/integration_tests.cpp
//       -o build/integration_tests -lpthread
//
//   ./build/integration_tests
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
// Tiny test harness — same shape as response_tests.cpp.
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

static fs::path makeTempDir(const char* leaf) {
    fs::path base = fs::temp_directory_path() /
                    (std::string("odysseus_integration_tests_") + leaf);
    fs::remove_all(base);
    fs::create_directories(base);
    return base;
}

// ---------------------------------------------------------------------------
// Build a ResponseManager whose Allowlist / Quarantine / ActionLog are
// rooted under a per-test tmp dir, so we don't pollute the user's app-data
// directory and so each test gets a clean slate.
// ---------------------------------------------------------------------------
static ResponseManager makeTestManager(const fs::path& base) {
    auto allowlist = std::make_shared<Allowlist>(
        (base / "allowlist.jsonl").string());
    auto quarantine = std::make_shared<Quarantine>(
        (base / "quarantine").string(),
        (base / "quarantine_metadata.jsonl").string());
    auto actionLog = std::make_shared<ActionLog>(
        (base / "action_log.jsonl").string());
    return ResponseManager(allowlist, quarantine, actionLog,
                           makeDefaultProcessControl(),
                           makeNoopUiBridge(),
                           ResponseConfig{});  // defaults: quarantine on,
                                                //           kill off
}

// ---------------------------------------------------------------------------
// Test 1: ResponseManager quarantine action works.
// Mirrors the call ResultsPage::onQuarantineClicked() makes.
// ---------------------------------------------------------------------------
static void testQuarantineActionViaManager(const fs::path& base) {
    std::cout << "\n[test] testQuarantineActionViaManager\n";
    fs::path src = base / "fake_threat.bin";
    {
        std::ofstream out(src);
        out << "fake malicious bytes for the integration test";
    }
    CHECK(fs::exists(src), "fixture file created");

    ResponseManager mgr = makeTestManager(base);

    ActionRequest req;
    req.action          = ActionType::QuarantineFile;
    req.userConfirmed   = true;          // ResultsPage's QMessageBox sets this
    req.target.kind     = TargetKind::File;
    req.target.path     = src.string();
    req.target.sha256   = "fakehash_for_testing";
    req.target.label    = src.filename().string();
    req.target.sourceId = src.string();
    req.reason          = "integration-test quarantine";

    ActionResult res = mgr.execute(req);

    CHECK(res.success,
          std::string("execute() succeeded: ") + res.errorMessage);
    CHECK(!res.newPath.empty(), "newPath populated with quarantine location");
    CHECK(fs::exists(res.newPath), "quarantined file exists at newPath");
    CHECK(!fs::exists(src), "original file no longer at original path");

    // The quarantine list must show exactly one entry.
    auto entries = mgr.quarantine().list();
    CHECK(entries.size() == 1, "quarantine has one entry");
    if (!entries.empty()) {
        CHECK(entries[0].sha256 == "fakehash_for_testing",
              "metadata sha256 preserved");
    }
}

// ---------------------------------------------------------------------------
// Test 2: Quarantine refuses without userConfirmed.
// Confirms the safety guard ResultsPage relies on.
// ---------------------------------------------------------------------------
static void testQuarantineRefusesWithoutConfirmation(const fs::path& base) {
    std::cout << "\n[test] testQuarantineRefusesWithoutConfirmation\n";
    fs::path src = base / "no_confirm.txt";
    {
        std::ofstream out(src);
        out << "should remain in place";
    }

    ResponseManager mgr = makeTestManager(base);

    ActionRequest req;
    req.action          = ActionType::QuarantineFile;
    req.userConfirmed   = false;              // <— deliberately omitted
    req.target.kind     = TargetKind::File;
    req.target.path     = src.string();
    req.target.sourceId = src.string();

    ActionResult res = mgr.execute(req);

    CHECK(!res.success, "execute() correctly refused without confirmation");
    CHECK(fs::exists(src), "file is untouched");
    CHECK(res.errorMessage.find("Confirmation") != std::string::npos,
          "error message mentions confirmation");
}

// ---------------------------------------------------------------------------
// Test 3: Allowlisted SHA-256 suppresses a finding (Allowlist::isFileIgnored).
// This is the contract the scanner detector path relies on.
// ---------------------------------------------------------------------------
static void testAllowlistSha256Suppression(const fs::path& base) {
    std::cout << "\n[test] testAllowlistSha256Suppression\n";

    Allowlist a((base / "allowlist.jsonl").string());

    const std::string knownGoodHash =
        "deadbeef00000000000000000000000000000000000000000000000000000000";
    const std::string filePath = "/Users/example/legit_dev_tool";

    // Initially nothing is suppressed.
    CHECK(!a.isFileIgnored(filePath, knownGoodHash),
          "fresh allowlist suppresses nothing");
    CHECK(!a.isFileIgnored(filePath, {}),
          "fresh allowlist suppresses nothing (path-only)");

    // Add a SHA-256 entry — preferred form per the integration spec.
    AllowlistEntry e;
    e.kind  = AllowlistEntry::Kind::FileSha256;
    e.value = knownGoodHash;
    e.note  = "User-added during integration test";
    CHECK(a.add(std::move(e)), "added SHA-256 entry");

    // The same path with the matching SHA-256 must now be suppressed.
    CHECK(a.isFileIgnored(filePath, knownGoodHash),
          "isFileIgnored matches by SHA-256");

    // A different path with the same SHA-256 must also be suppressed
    // (hash is the strong identifier — file location is irrelevant).
    CHECK(a.isFileIgnored("/other/location/copy.bin", knownGoodHash),
          "SHA-256 match suppresses regardless of path");

    // The same path with a different SHA-256 must NOT be suppressed
    // (this is what makes hash-based allowlisting safe).
    CHECK(!a.isFileIgnored(
              filePath,
              "0000000000000000000000000000000000000000000000000000000000000000"),
          "different SHA-256 is not suppressed");
}

// ---------------------------------------------------------------------------
// Test 4: Allowlist add via ResponseManager (mirrors ResultsPage Ignore button).
// ---------------------------------------------------------------------------
static void testIgnoreActionViaManager(const fs::path& base) {
    std::cout << "\n[test] testIgnoreActionViaManager\n";

    ResponseManager mgr = makeTestManager(base);

    ActionRequest req;
    req.action          = ActionType::AddToAllowlist;
    req.userConfirmed   = true;
    req.target.kind     = TargetKind::File;
    req.target.path     = "/some/legit/file.exe";
    req.target.sha256   = "abc123def456";  // ResponseManager prefers SHA-256
    req.target.label    = "file.exe";
    req.reason          = "integration-test ignore";

    ActionResult res = mgr.execute(req);
    CHECK(res.success, "AddToAllowlist via manager succeeds");
    CHECK(mgr.allowlist().contains(AllowlistEntry::Kind::FileSha256,
                                    "abc123def456"),
          "allowlist contains the SHA-256 entry");

    // The detector path's check should now suppress this file.
    CHECK(mgr.allowlist().isFileIgnored("/some/legit/file.exe",
                                          "abc123def456"),
          "isFileIgnored returns true for the freshly-added entry");
}

// ---------------------------------------------------------------------------
// Test 5: Every action — success or failure — writes one ActionLog record.
// ---------------------------------------------------------------------------
static void testActionLogRecordsEveryAction(const fs::path& base) {
    std::cout << "\n[test] testActionLogRecordsEveryAction\n";

    ResponseManager mgr = makeTestManager(base);
    const std::size_t initial = mgr.actionLog().readAll().size();

    // (a) Successful action: add to allowlist.
    {
        ActionRequest r;
        r.action          = ActionType::AddToAllowlist;
        r.userConfirmed   = true;
        r.target.kind     = TargetKind::File;
        r.target.sha256   = "logtest_hash_1";
        r.reason          = "log-write check (success)";
        mgr.execute(r);
    }

    // (b) Failed action: quarantine without confirmation must STILL log.
    {
        ActionRequest r;
        r.action          = ActionType::QuarantineFile;
        r.userConfirmed   = false;          // forces a refusal
        r.target.kind     = TargetKind::File;
        r.target.path     = (base / "nonexistent.bin").string();
        r.reason          = "log-write check (failure)";
        mgr.execute(r);
    }

    auto records = mgr.actionLog().readAll();
    CHECK(records.size() == initial + 2,
          "two new audit records (one success, one failure)");

    if (records.size() >= initial + 2) {
        const auto& first  = records[initial];
        const auto& second = records[initial + 1];
        CHECK(first.action == ActionType::AddToAllowlist,
              "first record is AddToAllowlist");
        CHECK(first.success, "first record marked successful");
        CHECK(second.action == ActionType::QuarantineFile,
              "second record is QuarantineFile");
        CHECK(!second.success, "second record marked failed");
        CHECK(!second.errorMessage.empty(),
              "second record carries the error message");
    }
}

// ---------------------------------------------------------------------------
// Test 6: Quarantine action writes an ActionLog record on success.
// (Spec calls this out explicitly as a priority test.)
// ---------------------------------------------------------------------------
static void testQuarantineWritesActionLog(const fs::path& base) {
    std::cout << "\n[test] testQuarantineWritesActionLog\n";

    fs::path src = base / "audit_subject.txt";
    {
        std::ofstream out(src);
        out << "content";
    }

    ResponseManager mgr = makeTestManager(base);
    const std::size_t initial = mgr.actionLog().readAll().size();

    ActionRequest req;
    req.action          = ActionType::QuarantineFile;
    req.userConfirmed   = true;
    req.target.kind     = TargetKind::File;
    req.target.path     = src.string();
    req.target.sourceId = src.string();
    req.reason          = "audit-trail check";

    ActionResult res = mgr.execute(req);
    CHECK(res.success, "quarantine succeeded");

    auto records = mgr.actionLog().readAll();
    CHECK(records.size() == initial + 1,
          "exactly one new audit record");
    if (!records.empty()) {
        const auto& last = records.back();
        CHECK(last.action == ActionType::QuarantineFile,
              "audit record is for QuarantineFile");
        CHECK(last.success, "audit record marks success");
        CHECK(last.userConfirmed, "audit record records userConfirmed=true");
        CHECK(last.targetSummary.find(src.filename().string())
                  != std::string::npos,
              "audit record summary mentions the file");
    }
}

// ---------------------------------------------------------------------------
// main.
// ---------------------------------------------------------------------------
int main() {
    fs::path base = makeTempDir("phase5_integration");
    std::cout << "[i] using temp dir: " << base << "\n";

    // Each test gets its own subdirectory so they don't interfere.
    testQuarantineActionViaManager(makeTempDir("quarantine_action"));
    testQuarantineRefusesWithoutConfirmation(makeTempDir("quarantine_noconfirm"));
    testAllowlistSha256Suppression(makeTempDir("allowlist_sha"));
    testIgnoreActionViaManager(makeTempDir("ignore_action"));
    testActionLogRecordsEveryAction(makeTempDir("audit_records"));
    testQuarantineWritesActionLog(makeTempDir("audit_quarantine"));

    std::cout << "\n[summary] " << g_pass << " passed, "
              << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}
