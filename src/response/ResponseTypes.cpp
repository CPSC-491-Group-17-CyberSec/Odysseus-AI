// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: src/response/ResponseTypes.cpp
//
// Out-of-line helpers for ResponseTypes.h. Kept tiny; everything else stays
// in the header so callers can build with just the public API.
// =============================================================================

#include "response/ResponseTypes.h"

namespace odysseus::response {

const char* toString(ActionType a) {
    switch (a) {
        case ActionType::None:                    return "None";
        case ActionType::OpenLocation:            return "OpenLocation";
        case ActionType::CopyPath:                return "CopyPath";
        case ActionType::CopyHash:                return "CopyHash";
        case ActionType::CopyDetails:             return "CopyDetails";
        case ActionType::CopyCommandLine:         return "CopyCommandLine";
        case ActionType::Investigate:             return "Investigate";
        case ActionType::QuarantineFile:          return "QuarantineFile";
        case ActionType::RestoreFromQuarantine:   return "RestoreFromQuarantine";
        case ActionType::ViewProcessDetails:      return "ViewProcessDetails";
        case ActionType::KillProcess:             return "KillProcess";
        case ActionType::DisablePersistenceItem:  return "DisablePersistenceItem";
        case ActionType::ViewBaseline:            return "ViewBaseline";
        case ActionType::ResetIntegrityBaseline:  return "ResetIntegrityBaseline";
        case ActionType::MarkTrustedAfterReview:  return "MarkTrustedAfterReview";
        case ActionType::AddToAllowlist:          return "AddToAllowlist";
        case ActionType::RemoveFromAllowlist:     return "RemoveFromAllowlist";
    }
    return "Unknown";
}

const char* toString(TargetKind k) {
    switch (k) {
        case TargetKind::Unknown:         return "Unknown";
        case TargetKind::File:            return "File";
        case TargetKind::Process:         return "Process";
        case TargetKind::Persistence:     return "Persistence";
        case TargetKind::Integrity:       return "Integrity";
        case TargetKind::KernelExtension: return "KernelExtension";
    }
    return "Unknown";
}

const char* toString(AllowlistEntry::Kind k) {
    switch (k) {
        case AllowlistEntry::Kind::FileSha256:        return "FileSha256";
        case AllowlistEntry::Kind::FilePath:          return "FilePath";
        case AllowlistEntry::Kind::ProcessPath:       return "ProcessPath";
        case AllowlistEntry::Kind::PersistenceLabel:  return "PersistenceLabel";
        case AllowlistEntry::Kind::PersistencePath:   return "PersistencePath";
        case AllowlistEntry::Kind::AlertSignatureKey: return "AlertSignatureKey";
    }
    return "Unknown";
}

bool requiresConfirmation(ActionType a) {
    switch (a) {
        case ActionType::QuarantineFile:
        case ActionType::RestoreFromQuarantine:
        case ActionType::KillProcess:
        case ActionType::DisablePersistenceItem:
        case ActionType::ResetIntegrityBaseline:
        case ActionType::MarkTrustedAfterReview:
        case ActionType::AddToAllowlist:
        case ActionType::RemoveFromAllowlist:
            return true;
        default:
            return false;
    }
}

bool isDestructive(ActionType a) {
    switch (a) {
        case ActionType::QuarantineFile:
        case ActionType::RestoreFromQuarantine:
        case ActionType::KillProcess:
        case ActionType::DisablePersistenceItem:
        case ActionType::ResetIntegrityBaseline:
            return true;
        default:
            return false;
    }
}

}  // namespace odysseus::response
