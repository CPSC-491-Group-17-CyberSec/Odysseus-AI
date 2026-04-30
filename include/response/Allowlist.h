// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/response/Allowlist.h
//
// Local allowlist of items the user has explicitly chosen to ignore. Backed
// by a JSONL file in the app data directory:
//   macOS : ~/Library/Application Support/Odysseus-AI/odysseus_allowlist.jsonl
//   Linux : ~/.local/share/Odysseus-AI/odysseus_allowlist.jsonl
//
// Thread-safe (internal mutex). All file I/O is synchronous and best-effort;
// failures bubble up via bool returns and getLastError().
//
// Behavior contract:
//   * Allowlisted items must NOT generate new alerts. Detection layers should
//     call Allowlist::isIgnored(...) before emitting an alert and short-circuit
//     when it returns true.
//   * The Settings UI lists entries from list() and removes via remove(...).
// =============================================================================

#ifndef ODYSSEUS_RESPONSE_ALLOWLIST_H
#define ODYSSEUS_RESPONSE_ALLOWLIST_H

#include "response/ResponseTypes.h"

#include <mutex>
#include <string>
#include <vector>

namespace odysseus::response {

class Allowlist {
public:
    // Loads the file at construction. If the file is missing, an empty list
    // is used and the file is created on first add().
    explicit Allowlist(std::string filePath);

    // Default-constructed: uses platform app-data directory + standard name.
    static std::string defaultPath();

    // Add or remove. Returns true on success.
    bool add(AllowlistEntry entry);
    bool remove(AllowlistEntry::Kind kind, const std::string& value);

    // True if the entry exists.
    bool contains(AllowlistEntry::Kind kind, const std::string& value) const;

    // Convenience: ignore-checks used by detectors before raising an alert.
    // Each method returns true if ANY matching allowlist entry exists.
    bool isFileIgnored(const std::string& path,
                       const std::string& sha256) const;
    bool isProcessIgnored(const std::string& processPath) const;
    bool isPersistenceIgnored(const std::string& label,
                              const std::string& path) const;
    bool isAlertSignatureIgnored(const std::string& signatureKey) const;

    // Read-only snapshot. Cheap because the in-memory store is small.
    std::vector<AllowlistEntry> list() const;

    // Last error string (mainly for surfacing in the UI).
    std::string getLastError() const;

    // Force reload from disk (used by Settings UI after manual edits).
    bool reload();

    // Force flush to disk. add()/remove() already flush automatically.
    bool flush() const;

private:
    bool loadLocked();
    bool flushLocked() const;

    std::string filePath_;
    mutable std::mutex mutex_;
    mutable std::string lastError_;
    std::vector<AllowlistEntry> entries_;
};

}  // namespace odysseus::response

#endif  // ODYSSEUS_RESPONSE_ALLOWLIST_H
