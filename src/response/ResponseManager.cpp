// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: src/response/ResponseManager.cpp
// =============================================================================

#include "response/ResponseManager.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#if defined(__APPLE__) || defined(__linux__)
    #include <sys/types.h>
    #include <signal.h>
    #include <unistd.h>
    #if defined(__linux__)
        #include <fstream>
    #endif
#endif

namespace odysseus::response {

namespace {

std::string lowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return s;
}

// Strip directory portion if path-like, leaving just the executable basename.
std::string basenameOnly(const std::string& s) {
    auto pos = s.find_last_of("/\\");
    return (pos == std::string::npos) ? s : s.substr(pos + 1);
}

}  // namespace

// ---------------------------------------------------------------------------
// Default process control bridge — POSIX kill(2). No-ops gracefully if a
// platform doesn't expose these (Windows would be a future port).
// ---------------------------------------------------------------------------
ProcessControl makeDefaultProcessControl() {
    ProcessControl pc;

#if defined(__APPLE__) || defined(__linux__)
    pc.kill = [](int64_t pid, int sig) -> int {
        if (pid <= 1) return EINVAL;  // never touch init/launchd
        if (::kill(static_cast<pid_t>(pid), sig) == 0) return 0;
        return errno;
    };
    pc.isAlive = [](int64_t pid) -> bool {
        if (pid <= 1) return false;
        // Signal 0: existence check, no signal delivered.
        if (::kill(static_cast<pid_t>(pid), 0) == 0) return true;
        return errno != ESRCH;  // permission errors mean it exists
    };
    pc.nameForPid = [](int64_t pid) -> std::string {
        if (pid <= 0) return "";
    #if defined(__linux__)
        std::ifstream in("/proc/" + std::to_string(pid) + "/comm");
        std::string name;
        if (in) std::getline(in, name);
        return name;
    #else
        // macOS: a richer impl would use proc_pidpath via libproc. For Phase
        // 5 we rely on the caller passing target.processName from the alert.
        return "";
    #endif
    };
#else
    pc.kill       = [](int64_t, int) { return ENOSYS; };
    pc.isAlive    = [](int64_t)       { return false; };
    pc.nameForPid = [](int64_t)       { return std::string(); };
#endif

    return pc;
}

UiBridge makeNoopUiBridge() {
    UiBridge ui;
    ui.writeClipboard = [](const std::string&) { return true; };
    ui.openLocation   = [](const std::string&) { return true; };
    return ui;
}

// ---------------------------------------------------------------------------
// Critical-process blocklist. Matches the spec exactly. Comparison is
// case-insensitive against the basename of the process executable path.
// ---------------------------------------------------------------------------
const std::vector<std::string>& ResponseManager::criticalProcessBlocklist() {
    static const std::vector<std::string> kList = {
        "launchd",
        "kernel_task",
        "WindowServer",
        "Finder",
        "loginwindow",
        "systemd",
        "init",
        "dbus-daemon",
        "NetworkManager",
    };
    return kList;
}

bool ResponseManager::isCriticalProcessName(const std::string& processName) {
    if (processName.empty()) return false;
    const std::string base = lowerCopy(basenameOnly(processName));
    for (const auto& p : criticalProcessBlocklist()) {
        if (lowerCopy(p) == base) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------
ResponseManager::ResponseManager()
    : ResponseManager(std::make_shared<Allowlist>(Allowlist::defaultPath()),
                      std::make_shared<Quarantine>(),
                      std::make_shared<ActionLog>(),
                      makeDefaultProcessControl(),
                      makeNoopUiBridge(),
                      ResponseConfig{}) {}

ResponseManager::ResponseManager(std::shared_ptr<Allowlist> allowlist,
                                 std::shared_ptr<Quarantine> quarantine,
                                 std::shared_ptr<ActionLog> actionLog,
                                 ProcessControl processControl,
                                 UiBridge uiBridge,
                                 ResponseConfig config)
    : allowlist_(std::move(allowlist)),
      quarantine_(std::move(quarantine)),
      actionLog_(std::move(actionLog)),
      proc_(std::move(processControl)),
      ui_(std::move(uiBridge)),
      config_(config) {}

ResponseConfig ResponseManager::config() const { return config_; }
void ResponseManager::setConfig(const ResponseConfig& cfg) { config_ = cfg; }

Allowlist&  ResponseManager::allowlist()  { return *allowlist_; }
Quarantine& ResponseManager::quarantine() { return *quarantine_; }
ActionLog&  ResponseManager::actionLog()  { return *actionLog_; }

// ---------------------------------------------------------------------------
// Availability rules — used by the UI to enable/disable buttons.
// ---------------------------------------------------------------------------
bool ResponseManager::isActionAvailable(ActionType action,
                                        const ActionTarget& target,
                                        std::string* why) const {
    auto deny = [&](const char* msg) {
        if (why) *why = msg;
        return false;
    };

    if (!config_.responseActionsEnabled && isDestructive(action)) {
        return deny("Response actions are disabled in settings.");
    }

    switch (action) {
        case ActionType::OpenLocation:
            if (target.path.empty())
                return deny("No path on this target.");
            return true;

        case ActionType::CopyPath:
            return !target.path.empty() ||
                   deny("No path to copy.");

        case ActionType::CopyHash:
            return !target.sha256.empty() ||
                   deny("No SHA-256 available for this target.");

        case ActionType::CopyCommandLine:
            return !target.commandLine.empty() ||
                   deny("No command line captured.");

        case ActionType::CopyDetails:
        case ActionType::Investigate:
            return true;

        case ActionType::QuarantineFile:
            if (target.kind != TargetKind::File)
                return deny("Quarantine applies to file targets only.");
            if (!config_.quarantineEnabled)
                return deny("Quarantine is disabled in settings.");
            if (target.path.empty())
                return deny("No file path to quarantine.");
            return true;

        case ActionType::RestoreFromQuarantine:
            return !target.sourceId.empty() ||
                   deny("Restore needs a quarantine entry id (sourceId).");

        case ActionType::ViewProcessDetails:
            return target.kind == TargetKind::Process ||
                   deny("View Process Details applies to process targets.");

        case ActionType::KillProcess:
            if (target.kind != TargetKind::Process)
                return deny("Kill Process applies to process targets only.");
            if (!config_.processKillEnabled)
                return deny("Process kill is disabled in settings.");
            if (target.pid <= 1)
                return deny("Refusing to kill PID <= 1.");
            if (isCriticalProcessName(target.processName))
                return deny("This process is on the critical-process "
                            "blocklist.");
            return true;

        case ActionType::DisablePersistenceItem:
            return target.kind == TargetKind::Persistence ||
                   deny("Disable applies to persistence items only.");

        case ActionType::ViewBaseline:
        case ActionType::ResetIntegrityBaseline:
        case ActionType::MarkTrustedAfterReview:
            return target.kind == TargetKind::Integrity ||
                   deny("Action applies to integrity targets only.");

        case ActionType::AddToAllowlist:
        case ActionType::RemoveFromAllowlist:
            if (!config_.allowlistEnabled)
                return deny("Allowlist is disabled in settings.");
            return true;

        case ActionType::None:
            return deny("No action specified.");
    }
    return false;
}

// ---------------------------------------------------------------------------
// Main dispatcher.
// ---------------------------------------------------------------------------
ActionResult ResponseManager::execute(const ActionRequest& req) {
    ActionResult res;

    // 1. Master kill switch.
    if (!config_.responseActionsEnabled && isDestructive(req.action)) {
        res.errorMessage = "Response actions are disabled in settings.";
        recordAudit(req, res);
        return res;
    }

    // 2. Confirmation guard for destructive actions.
    if (requiresConfirmation(req.action) && !req.userConfirmed) {
        res.errorMessage =
            "Confirmation required: this action is destructive or sensitive.";
        recordAudit(req, res);
        return res;
    }

    // 3. Availability check (mirrors UI gating to defend against unsafe
    //    requests forged outside the UI).
    std::string why;
    if (!isActionAvailable(req.action, req.target, &why)) {
        res.errorMessage = why.empty() ? "Action not available." : why;
        recordAudit(req, res);
        return res;
    }

    // 4. Per-action handlers.
    switch (req.action) {
        case ActionType::OpenLocation:
            res = executeOpenLocation(req);
            break;

        case ActionType::CopyPath:
            res = executeCopyText(req, req.target.path);
            break;
        case ActionType::CopyHash:
            res = executeCopyText(req, req.target.sha256);
            break;
        case ActionType::CopyCommandLine:
            res = executeCopyText(req, req.target.commandLine);
            break;
        case ActionType::CopyDetails: {
            std::string detail = summarizeTarget(req.target);
            if (!req.target.commandLine.empty())
                detail += "\nCmd: " + req.target.commandLine;
            res = executeCopyText(req, detail);
            break;
        }

        case ActionType::QuarantineFile:
            res = executeQuarantine(req);
            break;
        case ActionType::RestoreFromQuarantine:
            res = executeRestore(req);
            break;

        case ActionType::KillProcess:
            res = executeKillProcess(req);
            break;

        case ActionType::AddToAllowlist:
            res = executeAddToAllowlist(req);
            break;
        case ActionType::RemoveFromAllowlist:
            res = executeRemoveFromAllowlist(req);
            break;

        // Read-only actions: surface the request to the audit log; the UI
        // presents the data itself.
        case ActionType::Investigate:
        case ActionType::ViewProcessDetails:
        case ActionType::ViewBaseline:
        case ActionType::DisablePersistenceItem:
        case ActionType::ResetIntegrityBaseline:
        case ActionType::MarkTrustedAfterReview:
            res = executeReadOnly(req);
            break;

        case ActionType::None:
            res.errorMessage = "No action specified.";
            break;
    }

    recordAudit(req, res);
    return res;
}

// ---------------------------------------------------------------------------
// Per-action handlers.
// ---------------------------------------------------------------------------
ActionResult ResponseManager::executeOpenLocation(const ActionRequest& req) {
    ActionResult res;
    if (!ui_.openLocation) {
        res.errorMessage = "No UI bridge for openLocation.";
        return res;
    }
    res.success = ui_.openLocation(req.target.path);
    res.message = res.success ? "Opened location" : "Failed to open location";
    if (!res.success) res.errorMessage = res.message;
    return res;
}

ActionResult ResponseManager::executeCopyText(const ActionRequest& /*req*/,
                                              const std::string& text) {
    ActionResult res;
    if (text.empty()) {
        res.errorMessage = "Nothing to copy.";
        return res;
    }
    if (!ui_.writeClipboard) {
        res.errorMessage = "No UI bridge for clipboard.";
        return res;
    }
    res.success = ui_.writeClipboard(text);
    res.message = res.success ? "Copied to clipboard."
                              : "Clipboard write failed.";
    if (!res.success) res.errorMessage = res.message;
    return res;
}

ActionResult ResponseManager::executeQuarantine(const ActionRequest& req) {
    ActionResult res;
    auto entry = quarantine_->quarantine(req.target.path,
                                         req.target.sha256,
                                         req.reason,
                                         req.target.sourceId);
    if (!entry) {
        res.errorMessage = "Quarantine failed: " + quarantine_->getLastError();
        return res;
    }
    res.success = true;
    res.message = "Quarantined to " + entry->quarantinePath;
    res.newPath = entry->quarantinePath;
    return res;
}

ActionResult ResponseManager::executeRestore(const ActionRequest& req) {
    ActionResult res = quarantine_->restore(req.target.sourceId,
                                            req.restorePolicy);
    if (!res.success && res.errorMessage.empty() && !res.needsUserChoice) {
        res.errorMessage = quarantine_->getLastError();
    }
    return res;
}

ActionResult ResponseManager::executeKillProcess(const ActionRequest& req) {
    ActionResult res;

    // Defensive checks duplicated from isActionAvailable in case execute()
    // is called without going through the UI.
    if (!config_.processKillEnabled) {
        res.errorMessage = "Process kill is disabled in settings.";
        return res;
    }
    if (req.target.pid <= 1) {
        res.errorMessage = "Refusing to kill PID <= 1.";
        return res;
    }
    std::string name = req.target.processName;
    if (name.empty() && proc_.nameForPid)
        name = proc_.nameForPid(req.target.pid);
    if (isCriticalProcessName(name)) {
        res.errorMessage = "Refusing to kill critical system process: " + name;
        return res;
    }
    if (!proc_.kill) {
        res.errorMessage = "Process control unavailable on this platform.";
        return res;
    }

    // SIGTERM first.
#if defined(__APPLE__) || defined(__linux__)
    int sigTerm = SIGTERM;
    int sigKill = SIGKILL;
#else
    int sigTerm = 15;
    int sigKill = 9;
#endif
    int rc = proc_.kill(req.target.pid, sigTerm);
    if (rc != 0) {
        res.errorMessage = "SIGTERM failed: errno=" + std::to_string(rc);
        return res;
    }

    // Brief pause, then check liveness.
    std::this_thread::sleep_for(std::chrono::milliseconds(750));
    bool stillAlive = proc_.isAlive ? proc_.isAlive(req.target.pid) : false;

    if (stillAlive && req.allowSigkillEscalation) {
        rc = proc_.kill(req.target.pid, sigKill);
        if (rc != 0) {
            res.errorMessage = "SIGTERM sent; SIGKILL escalation failed: errno="
                             + std::to_string(rc);
            return res;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        stillAlive = proc_.isAlive ? proc_.isAlive(req.target.pid) : false;
    }

    if (stillAlive) {
        res.message = "SIGTERM sent; process still running. Re-issue with "
                      "SIGKILL escalation enabled if needed.";
        // Not a hard failure — SIGTERM may take time. The caller decides.
        res.success = false;
        res.errorMessage = res.message;
    } else {
        res.success = true;
        res.message = "Process terminated.";
    }
    return res;
}

ActionResult ResponseManager::executeAddToAllowlist(const ActionRequest& req) {
    ActionResult res;
    if (!config_.allowlistEnabled) {
        res.errorMessage = "Allowlist is disabled in settings.";
        return res;
    }

    AllowlistEntry e;
    e.note = req.reason;

    // Pick the most-specific allowlist key the request supplies.
    if (!req.target.sha256.empty()) {
        e.kind  = AllowlistEntry::Kind::FileSha256;
        e.value = req.target.sha256;
    } else if (req.target.kind == TargetKind::File && !req.target.path.empty()) {
        e.kind  = AllowlistEntry::Kind::FilePath;
        e.value = req.target.path;
    } else if (req.target.kind == TargetKind::Process &&
               !req.target.path.empty()) {
        e.kind  = AllowlistEntry::Kind::ProcessPath;
        e.value = req.target.path;
    } else if (req.target.kind == TargetKind::Persistence) {
        if (!req.target.label.empty()) {
            e.kind  = AllowlistEntry::Kind::PersistenceLabel;
            e.value = req.target.label;
        } else if (!req.target.path.empty()) {
            e.kind  = AllowlistEntry::Kind::PersistencePath;
            e.value = req.target.path;
        } else if (!req.target.signatureKey.empty()) {
            e.kind  = AllowlistEntry::Kind::AlertSignatureKey;
            e.value = req.target.signatureKey;
        } else {
            res.errorMessage = "No identifier available to allowlist.";
            return res;
        }
    } else if (!req.target.signatureKey.empty()) {
        e.kind  = AllowlistEntry::Kind::AlertSignatureKey;
        e.value = req.target.signatureKey;
    } else {
        res.errorMessage = "No identifier available to allowlist.";
        return res;
    }

    if (!allowlist_->add(e)) {
        res.errorMessage = "Allowlist add failed: " + allowlist_->getLastError();
        return res;
    }
    res.success = true;
    res.message = std::string("Allowlisted by ") + toString(e.kind) + ".";
    return res;
}

ActionResult ResponseManager::executeRemoveFromAllowlist(
    const ActionRequest& req) {
    ActionResult res;
    if (!config_.allowlistEnabled) {
        res.errorMessage = "Allowlist is disabled in settings.";
        return res;
    }

    // Try the most specific key the request supplies, then fall back. This
    // mirrors the priority used in executeAddToAllowlist.
    auto tryRemove = [&](AllowlistEntry::Kind k, const std::string& v) {
        if (v.empty()) return false;
        return allowlist_->remove(k, v);
    };

    bool removed =
        tryRemove(AllowlistEntry::Kind::FileSha256,        req.target.sha256) ||
        tryRemove(AllowlistEntry::Kind::FilePath,          req.target.path)   ||
        tryRemove(AllowlistEntry::Kind::ProcessPath,       req.target.path)   ||
        tryRemove(AllowlistEntry::Kind::PersistenceLabel,  req.target.label)  ||
        tryRemove(AllowlistEntry::Kind::PersistencePath,   req.target.path)   ||
        tryRemove(AllowlistEntry::Kind::AlertSignatureKey, req.target.signatureKey);

    if (!removed) {
        res.errorMessage = "No matching allowlist entry to remove.";
        return res;
    }
    res.success = true;
    res.message = "Removed from allowlist.";
    return res;
}

ActionResult ResponseManager::executeReadOnly(const ActionRequest& req) {
    // Read-only actions just pass through; the UI does the actual rendering.
    // We still call the audit log so reports show that the user looked at a
    // particular item.
    ActionResult res;
    res.success = true;
    res.message = std::string("Opened ") + toString(req.action);
    return res;
}

// ---------------------------------------------------------------------------
// Audit logging.
// ---------------------------------------------------------------------------
void ResponseManager::recordAudit(const ActionRequest& req,
                                  const ActionResult& res) {
    if (!actionLog_) return;
    ActionLogRecord r;
    r.action         = req.action;
    r.targetKind     = req.target.kind;
    r.targetSummary  = summarizeTarget(req.target);
    r.userConfirmed  = req.userConfirmed;
    r.success        = res.success;
    r.message        = res.message;
    r.errorMessage   = res.errorMessage;
    actionLog_->append(std::move(r));
}

// ---------------------------------------------------------------------------
// Bulk.
// ---------------------------------------------------------------------------
std::vector<ActionResult> ResponseManager::executeBatch(
    const std::vector<ActionRequest>& reqs, bool continueOnError) {
    std::vector<ActionResult> out;
    out.reserve(reqs.size());
    for (const auto& r : reqs) {
        out.push_back(execute(r));
        if (!out.back().success && !continueOnError) break;
    }
    return out;
}

}  // namespace odysseus::response
