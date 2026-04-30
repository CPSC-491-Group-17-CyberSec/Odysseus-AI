// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/response/ResponseManager.h
//
// Single entry-point for all response actions. The UI never talks to
// Quarantine / Allowlist / ActionLog directly — it builds an ActionRequest
// and calls ResponseManager::execute().
//
// Safety guardrails enforced here:
//   * Hard-blocked actions (e.g. file deletion) are simply not in ActionType.
//   * Destructive actions require ActionRequest::userConfirmed == true.
//   * Process kill requires:
//       - config.processKillEnabled == true
//       - target name not in critical-process blocklist
//       - userConfirmed == true
//   * Allowlisted items may still be acted on if the user explicitly asks
//     (e.g. quarantining anyway), but they will never raise a NEW alert —
//     that suppression happens in the detector layer via Allowlist::is*.
//   * Every action — successful or not — is appended to ActionLog.
// =============================================================================

#ifndef ODYSSEUS_RESPONSE_MANAGER_H
#define ODYSSEUS_RESPONSE_MANAGER_H

#include "response/ActionLog.h"
#include "response/Allowlist.h"
#include "response/Quarantine.h"
#include "response/ResponseTypes.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace odysseus::response {

// ---------------------------------------------------------------------------
// Bridge to whatever process-kill the host platform supplies. Default impl
// uses kill(2) (POSIX). Tests can inject a fake.
// ---------------------------------------------------------------------------
struct ProcessControl {
    // Returns 0 on success, errno on failure.
    std::function<int(int64_t pid, int signal)> kill;
    // Returns true if the process is alive (best-effort).
    std::function<bool(int64_t pid)> isAlive;
    // Returns the executable name for a pid (best-effort, may be empty).
    std::function<std::string(int64_t pid)> nameForPid;
};
ProcessControl makeDefaultProcessControl();

// ---------------------------------------------------------------------------
// UI bridge for clipboard and "open location". Defaults are no-op stubs that
// just record the request — wire concrete implementations from the UI layer
// when integrating.
// ---------------------------------------------------------------------------
struct UiBridge {
    std::function<bool(const std::string& text)> writeClipboard;
    std::function<bool(const std::string& path)> openLocation;
};
UiBridge makeNoopUiBridge();

// ---------------------------------------------------------------------------
// ResponseManager.
// ---------------------------------------------------------------------------
class ResponseManager {
public:
    // Default-construct: uses default app-data paths and POSIX process control.
    ResponseManager();

    // Test/integration constructor: inject everything.
    ResponseManager(std::shared_ptr<Allowlist> allowlist,
                    std::shared_ptr<Quarantine> quarantine,
                    std::shared_ptr<ActionLog> actionLog,
                    ProcessControl processControl,
                    UiBridge uiBridge,
                    ResponseConfig config = {});

    // Execute one action. Returns a populated ActionResult; ALWAYS writes one
    // ActionLogRecord, regardless of success/failure (errors are auditable).
    ActionResult execute(const ActionRequest& req);

    // Helpers exposed so the UI can decide whether to enable a button BEFORE
    // the user clicks it.
    bool isActionAvailable(ActionType action,
                           const ActionTarget& target,
                           std::string* whyDisabled = nullptr) const;

    // Bulk: run several actions sequentially. Stops on first hard failure
    // unless continueOnError is true.
    std::vector<ActionResult> executeBatch(
        const std::vector<ActionRequest>& reqs,
        bool continueOnError = false);

    // Config.
    ResponseConfig config() const;
    void setConfig(const ResponseConfig& cfg);

    // Critical-process blocklist (immutable). Matched case-insensitively
    // against the process name (basename of the executable path).
    static const std::vector<std::string>& criticalProcessBlocklist();

    // True if the process name is on the critical-process blocklist.
    static bool isCriticalProcessName(const std::string& processName);

    // Accessors so the Settings UI can list/edit allowlist and quarantine.
    Allowlist&  allowlist();
    Quarantine& quarantine();
    ActionLog&  actionLog();

private:
    ActionResult executeOpenLocation(const ActionRequest&);
    ActionResult executeCopyText(const ActionRequest&, const std::string&);
    ActionResult executeQuarantine(const ActionRequest&);
    ActionResult executeRestore(const ActionRequest&);
    ActionResult executeKillProcess(const ActionRequest&);
    ActionResult executeAddToAllowlist(const ActionRequest&);
    ActionResult executeRemoveFromAllowlist(const ActionRequest&);
    ActionResult executeReadOnly(const ActionRequest&);

    // Always called; never throws.
    void recordAudit(const ActionRequest& req, const ActionResult& res);

    std::shared_ptr<Allowlist>  allowlist_;
    std::shared_ptr<Quarantine> quarantine_;
    std::shared_ptr<ActionLog>  actionLog_;
    ProcessControl              proc_;
    UiBridge                    ui_;
    ResponseConfig              config_;
};

}  // namespace odysseus::response

#endif  // ODYSSEUS_RESPONSE_MANAGER_H
