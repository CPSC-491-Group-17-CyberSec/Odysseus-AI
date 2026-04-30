// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/response/Quarantine.h
//
// File quarantine. Reversible — quarantined files are NEVER deleted by the
// response subsystem. Restore returns the file to its original location, with
// a user-supplied collision policy.
//
// Storage layout:
//   macOS : ~/Library/Application Support/Odysseus-AI/quarantine/<id>.quarantine
//   Linux : ~/.local/share/Odysseus-AI/quarantine/<id>.quarantine
//
// Metadata is appended to <appdata>/quarantine_metadata.jsonl. The original
// filename is encoded in the renamed quarantine file as
//   <orig_basename>.<id>.quarantine
// so a human can identify a file even if metadata is missing.
//
// Concurrency: thread-safe via internal mutex. All operations are synchronous.
// =============================================================================

#ifndef ODYSSEUS_RESPONSE_QUARANTINE_H
#define ODYSSEUS_RESPONSE_QUARANTINE_H

#include "response/ResponseTypes.h"

#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace odysseus::response {

class Quarantine {
public:
    // Uses platform default directories.
    Quarantine();

    // Custom directory + metadata path. Useful for tests.
    Quarantine(std::string quarantineDir, std::string metadataPath);

    // Move file at originalPath into the quarantine directory. The file is
    // renamed (NOT deleted) and a metadata record is written. On success
    // returns the populated entry.
    //
    // sha256 is optional — if empty, the entry's sha256 stays empty too.
    // sourceId is the producing alert/scan id (used by the audit log).
    std::optional<QuarantineEntry> quarantine(const std::string& originalPath,
                                              const std::string& sha256,
                                              const std::string& reason,
                                              const std::string& sourceId);

    // Restore a quarantined file by its id. The collision policy controls
    // what happens when a file already exists at the original path.
    //
    // RestoreConflictPolicy::AskUser causes the function to return a result
    // with .needsUserChoice = true and not move anything — the UI must call
    // back with a concrete choice.
    ActionResult restore(const std::string& entryId,
                         RestoreConflictPolicy policy);

    // Read-only views.
    std::vector<QuarantineEntry> list() const;
    std::optional<QuarantineEntry> findById(const std::string& id) const;
    std::optional<QuarantineEntry> findByOriginalPath(
        const std::string& originalPath) const;

    // Diagnostics.
    std::string getLastError() const;
    const std::string& quarantineDir() const { return quarantineDir_; }
    const std::string& metadataPath() const  { return metadataPath_; }

private:
    bool loadLocked();
    bool flushLocked() const;
    static std::string makeId();

    std::string quarantineDir_;
    std::string metadataPath_;
    mutable std::mutex mutex_;
    mutable std::string lastError_;
    std::vector<QuarantineEntry> entries_;
};

}  // namespace odysseus::response

#endif  // ODYSSEUS_RESPONSE_QUARANTINE_H
