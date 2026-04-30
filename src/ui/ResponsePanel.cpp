// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: src/ui/ResponsePanel.cpp
//
// Framework-agnostic helpers for building action panels in the Alerts /
// Results / System Status detail views. Pure C++; no widget dependencies.
// =============================================================================

#include "ui/ResponsePanel.h"

namespace odysseus::ui {

using response::ActionType;
using response::ActionTarget;
using response::ResponseManager;
using response::TargetKind;

namespace {

// Build one ActionButton, querying the manager for availability + reason.
ActionButton make(const ResponseManager& mgr,
                  const ActionTarget& t,
                  ActionType action,
                  const char* label,
                  const char* tooltipWhenEnabled,
                  bool destructive) {
    ActionButton b;
    b.action      = action;
    b.label       = label;
    b.destructive = destructive;
    std::string why;
    b.enabled     = mgr.isActionAvailable(action, t, &why);
    b.tooltip     = b.enabled ? tooltipWhenEnabled : why;
    return b;
}

}  // namespace

// ---------------------------------------------------------------------------
// Alert detail panel.
// ---------------------------------------------------------------------------
std::vector<ActionButton> buildAlertActions(const ResponseManager& mgr,
                                            const ActionTarget& t) {
    std::vector<ActionButton> out;

    out.push_back(make(mgr, t, ActionType::Investigate,
                       "Investigate",
                       "Open the alert in the investigation view.",
                       /*destructive*/ false));

    if (t.kind == TargetKind::File ||
        t.kind == TargetKind::Persistence) {
        out.push_back(make(mgr, t, ActionType::OpenLocation,
                           "Open Location",
                           "Reveal the file in the system file manager.",
                           false));
    }

    out.push_back(make(mgr, t, ActionType::CopyDetails,
                       "Copy Details",
                       "Copy a formatted summary to the clipboard.",
                       false));

    if (t.kind == TargetKind::File) {
        out.push_back(make(mgr, t, ActionType::QuarantineFile,
                           "Quarantine",
                           "Move the file to the app quarantine folder. "
                           "Reversible.",
                           /*destructive*/ true));
    }

    if (t.kind == TargetKind::Process) {
        out.push_back(make(mgr, t, ActionType::KillProcess,
                           "Kill Process",
                           "Terminate the process. Sends SIGTERM first.",
                           true));
    }

    if (t.kind == TargetKind::Integrity) {
        out.push_back(make(mgr, t, ActionType::ResetIntegrityBaseline,
                           "Reset Baseline",
                           "Replace the stored integrity baseline with the "
                           "current state.",
                           true));
    }

    out.push_back(make(mgr, t, ActionType::AddToAllowlist,
                       "Ignore",
                       "Allowlist this item — it will not raise future alerts.",
                       true));

    return out;
}

// ---------------------------------------------------------------------------
// Result detail panel (file-scan / hash result).
// ---------------------------------------------------------------------------
std::vector<ActionButton> buildResultActions(const ResponseManager& mgr,
                                             const ActionTarget& t) {
    std::vector<ActionButton> out;
    out.push_back(make(mgr, t, ActionType::OpenLocation,
                       "Open Location",
                       "Reveal the file in the system file manager.",
                       false));
    out.push_back(make(mgr, t, ActionType::CopyPath,
                       "Copy Path",
                       "Copy the absolute file path.",
                       false));
    out.push_back(make(mgr, t, ActionType::CopyHash,
                       "Copy SHA-256",
                       "Copy the SHA-256 hash.",
                       false));
    out.push_back(make(mgr, t, ActionType::QuarantineFile,
                       "Quarantine",
                       "Move the file to the app quarantine folder. "
                       "Reversible.",
                       true));
    out.push_back(make(mgr, t, ActionType::AddToAllowlist,
                       "Ignore",
                       "Allowlist this file — it will not raise future alerts.",
                       true));
    return out;
}

// ---------------------------------------------------------------------------
// System status detail panel (process / persistence / kext).
// ---------------------------------------------------------------------------
std::vector<ActionButton> buildSystemStatusActions(const ResponseManager& mgr,
                                                   const ActionTarget& t) {
    std::vector<ActionButton> out;

    if (t.kind == TargetKind::Process) {
        out.push_back(make(mgr, t, ActionType::ViewProcessDetails,
                           "View Details",
                           "Open the process detail view.",
                           false));
        out.push_back(make(mgr, t, ActionType::CopyCommandLine,
                           "Copy Cmd Line",
                           "Copy the captured command line.",
                           false));
        out.push_back(make(mgr, t, ActionType::KillProcess,
                           "Kill Process",
                           "Terminate the process. Sends SIGTERM first.",
                           true));
    } else if (t.kind == TargetKind::Persistence) {
        out.push_back(make(mgr, t, ActionType::OpenLocation,
                           "Open Location",
                           "Reveal the persistence item in the file manager.",
                           false));
        out.push_back(make(mgr, t, ActionType::DisablePersistenceItem,
                           "Disable",
                           "Mark this persistence item as disabled in the app "
                           "DB. Does NOT alter the system loader directly.",
                           true));
    } else if (t.kind == TargetKind::Integrity) {
        out.push_back(make(mgr, t, ActionType::ViewBaseline,
                           "View Baseline",
                           "Show the stored integrity baseline.",
                           false));
        out.push_back(make(mgr, t, ActionType::ResetIntegrityBaseline,
                           "Reset Baseline",
                           "Replace the stored baseline with the current "
                           "state.",
                           true));
        out.push_back(make(mgr, t, ActionType::MarkTrustedAfterReview,
                           "Mark Trusted",
                           "Record that you reviewed this finding and consider "
                           "it trustworthy.",
                           true));
    } else if (t.kind == TargetKind::KernelExtension) {
        out.push_back(make(mgr, t, ActionType::Investigate,
                           "Investigate",
                           "Open the kext in the investigation view.",
                           false));
        // No destructive options for kexts in Phase 5 — explicit out-of-scope.
    }

    out.push_back(make(mgr, t, ActionType::AddToAllowlist,
                       "Ignore",
                       "Allowlist this item — it will not raise future alerts.",
                       true));
    return out;
}

// ---------------------------------------------------------------------------
// Confirmation prompts. Wording stays in one place so it can be reviewed by
// design / legal once and used everywhere.
// ---------------------------------------------------------------------------
ConfirmPrompt confirmPromptFor(ActionType action, const ActionTarget& t) {
    ConfirmPrompt p;
    p.confirmLabel = "Continue";
    p.cancelLabel  = "Cancel";

    switch (action) {
        case ActionType::QuarantineFile:
            p.title = "Quarantine file?";
            p.body  = "Odysseus will move this file to the app quarantine "
                      "folder. This action is reversible from the Quarantine "
                      "view.\n\nFile: " + t.path;
            break;

        case ActionType::RestoreFromQuarantine:
            p.title = "Restore file from quarantine?";
            p.body  = "Odysseus will move this file back to its original "
                      "location.";
            break;

        case ActionType::KillProcess:
            p.title = "Kill process?";
            p.body  = "Killing a process can cause data loss or system "
                      "instability. Continue?\n\nProcess: " + t.processName +
                      "\nPID: " + std::to_string(t.pid);
            p.confirmLabel = "Kill";
            break;

        case ActionType::DisablePersistenceItem:
            p.title = "Disable persistence item?";
            p.body  = "Odysseus will mark this item as disabled in its "
                      "database. The system loader is not modified directly. "
                      "You may need to remove the underlying file manually.";
            break;

        case ActionType::ResetIntegrityBaseline:
            p.title = "Reset integrity baseline?";
            p.body  = "The stored baseline will be replaced with the current "
                      "state. Future drift will be measured from this new "
                      "snapshot.";
            break;

        case ActionType::MarkTrustedAfterReview:
            p.title = "Mark this finding as trusted?";
            p.body  = "Confirm that you reviewed the finding and accept it as "
                      "trustworthy.";
            break;

        case ActionType::AddToAllowlist:
            p.title = "Allowlist this item?";
            p.body  = "Odysseus will not raise future alerts for this item.";
            break;

        case ActionType::RemoveFromAllowlist:
            p.title = "Remove from allowlist?";
            p.body  = "Future alerts for this item will resume.";
            break;

        default:
            p.title = "Confirm action";
            p.body  = "Continue with this action?";
            break;
    }
    return p;
}

}  // namespace odysseus::ui
