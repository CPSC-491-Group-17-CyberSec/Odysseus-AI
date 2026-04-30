// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/response/ResponseTypes.h
//
// Common types, enums, and POD records used by the response subsystem.
// Header-only. C++17.
//
// Safety design notes (enforced by ResponseManager):
//   * No automatic destructive actions. Every destructive action requires
//     explicit user confirmation passed through ActionRequest::userConfirmed.
//   * Delete is intentionally NOT in ActionType. Quarantine is reversible.
//   * Process kill is gated by a critical-process blocklist and an off-by-
//     default config flag (processKillEnabled).
// =============================================================================

#ifndef ODYSSEUS_RESPONSE_TYPES_H
#define ODYSSEUS_RESPONSE_TYPES_H

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

namespace odysseus::response {

// ----------------------------------------------------------------------------
// Target kinds — which subsystem produced the alert/result the action targets.
// ----------------------------------------------------------------------------
enum class TargetKind {
    Unknown = 0,
    File,
    Process,
    Persistence,
    Integrity,
    KernelExtension
};

// ----------------------------------------------------------------------------
// Action types. Grouped by target kind in comments for clarity.
// "Delete" is deliberately omitted — Phase 5 prefers reversible actions.
// ----------------------------------------------------------------------------
enum class ActionType {
    None = 0,

    // Generic / informational (safe, no confirmation required)
    OpenLocation,        // open the containing folder of a file or persistence item
    CopyPath,            // copy file/process/persistence path to clipboard
    CopyHash,            // copy SHA-256 to clipboard
    CopyDetails,         // copy a formatted detail block to clipboard
    CopyCommandLine,     // copy a process command line to clipboard
    Investigate,         // open the in-app investigation/details view

    // File actions
    QuarantineFile,      // move file to quarantine (reversible)
    RestoreFromQuarantine,

    // Process actions
    ViewProcessDetails,
    KillProcess,         // SIGTERM, optional SIGKILL escalation; requires confirmation

    // Persistence actions
    DisablePersistenceItem,  // mark disabled in app DB; does NOT actually unload

    // Integrity actions
    ViewBaseline,
    ResetIntegrityBaseline,
    MarkTrustedAfterReview,

    // Allowlist
    AddToAllowlist,         // i.e. "Ignore"
    RemoveFromAllowlist
};

// ----------------------------------------------------------------------------
// Conflict resolution policy for restore-from-quarantine when the original
// path already has a file at it.
// ----------------------------------------------------------------------------
enum class RestoreConflictPolicy {
    AskUser = 0,    // default — UI must call back with a concrete choice
    Overwrite,
    RestoreWithNewName,
    Cancel
};

// ----------------------------------------------------------------------------
// Fully-described target of an action. Fields are populated only if relevant
// to the TargetKind — the rest stay empty.
// ----------------------------------------------------------------------------
struct ActionTarget {
    TargetKind kind = TargetKind::Unknown;

    // File / persistence item
    std::string path;            // absolute filesystem path
    std::string sha256;          // optional, lower-case hex
    std::string label;           // human-friendly name (persistence item label, etc.)

    // Process
    int64_t pid = -1;
    std::string processName;
    std::string commandLine;

    // Cross-cutting
    std::string sourceId;        // alert id / scan result id that produced the target
    std::string signatureKey;    // stable key for "ignore future alerts of this kind"
};

// ----------------------------------------------------------------------------
// Request and result records.
// ----------------------------------------------------------------------------
struct ActionRequest {
    ActionType action = ActionType::None;
    ActionTarget target;

    // The UI must set this to true ONLY after the user confirmed in the
    // chat/dialog. Destructive actions refuse to run unless this is true.
    bool userConfirmed = false;

    // Used only by KillProcess to ask the manager to escalate to SIGKILL after
    // SIGTERM fails. Still requires userConfirmed = true.
    bool allowSigkillEscalation = false;

    // Used only by RestoreFromQuarantine. AskUser bubbles up as
    // ActionResult::needsUserChoice.
    RestoreConflictPolicy restorePolicy = RestoreConflictPolicy::AskUser;

    // Free-form reason captured for the audit log.
    std::string reason;
};

struct ActionResult {
    bool success = false;

    // True when the manager could not finish because it needs the UI to
    // collect another decision from the user (e.g. restore conflict).
    bool needsUserChoice = false;

    std::string message;        // human-readable summary
    std::string errorMessage;   // empty on success
    std::string newPath;        // populated by quarantine/restore where useful

    // Echoes the audit-log id assigned to this action, if any.
    std::string actionLogId;
};

// ----------------------------------------------------------------------------
// Persisted records.
// ----------------------------------------------------------------------------
struct QuarantineEntry {
    std::string id;              // uuid-ish
    std::string originalPath;
    std::string quarantinePath;
    std::string sha256;
    std::int64_t timestampEpoch = 0;
    std::string reason;
    std::string sourceId;        // alert/scan id
};

struct AllowlistEntry {
    enum class Kind {
        FileSha256 = 0,
        FilePath,
        ProcessPath,
        PersistenceLabel,
        PersistencePath,
        AlertSignatureKey
    };
    Kind kind = Kind::FileSha256;
    std::string value;
    std::int64_t addedEpoch = 0;
    std::string note;
};

struct ActionLogRecord {
    std::string id;
    std::int64_t timestampEpoch = 0;
    ActionType action = ActionType::None;
    TargetKind targetKind = TargetKind::Unknown;
    std::string targetSummary;   // short human-readable description of target
    bool userConfirmed = false;
    bool success = false;
    std::string message;
    std::string errorMessage;
};

// ----------------------------------------------------------------------------
// Configuration. Persisted at config/response_config.json.
// ----------------------------------------------------------------------------
struct ResponseConfig {
    bool responseActionsEnabled = true;
    bool quarantineEnabled      = true;
    bool processKillEnabled     = false;   // off by default — riskier
    bool allowlistEnabled       = true;
};

// ----------------------------------------------------------------------------
// Helpers — string forms for logging, JSON, and tooltips.
// ----------------------------------------------------------------------------
const char* toString(ActionType a);
const char* toString(TargetKind k);
const char* toString(AllowlistEntry::Kind k);

// True if the action is destructive / non-reversible-without-restore and so
// must have userConfirmed == true on the request.
bool requiresConfirmation(ActionType a);

// True if the action mutates the filesystem or process state at all. Used by
// ResponseManager as a final guardrail when responseActionsEnabled is false.
bool isDestructive(ActionType a);

}  // namespace odysseus::response

#endif  // ODYSSEUS_RESPONSE_TYPES_H
