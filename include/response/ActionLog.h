// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/response/ActionLog.h
//
// Append-only audit log of every response action. One JSON object per line
// (.jsonl). Used by the future Reports page.
//
// File location:
//   macOS : ~/Library/Application Support/Odysseus-AI/odysseus_action_log.jsonl
//   Linux : ~/.local/share/Odysseus-AI/odysseus_action_log.jsonl
//
// Thread-safe via internal mutex. Append is fsync-best-effort (ofstream flush);
// each action call writes one line and immediately closes the stream so a
// crash mid-action loses at most that one record.
// =============================================================================

#ifndef ODYSSEUS_RESPONSE_ACTION_LOG_H
#define ODYSSEUS_RESPONSE_ACTION_LOG_H

#include <mutex>
#include <string>
#include <vector>

#include "response/ResponseTypes.h"

namespace odysseus::response {

class ActionLog {
 public:
  // Default path uses platform app-data dir.
  ActionLog();

  // Custom path — useful for tests.
  explicit ActionLog(std::string filePath);

  // Append a record. Fills in id and timestamp if missing. Returns the
  // assigned id on success, empty on failure (and sets getLastError()).
  std::string append(ActionLogRecord record);

  // Read the entire log. Cheap for typical sizes (action log is tiny).
  std::vector<ActionLogRecord> readAll() const;

  // Diagnostics.
  std::string getLastError() const;
  const std::string& filePath() const { return filePath_; }

 private:
  std::string filePath_;
  mutable std::mutex mutex_;
  mutable std::string lastError_;
};

// ---------------------------------------------------------------------------
// Helpers used by ResponseManager when constructing log records — they live
// here so other subsystems can produce summaries without pulling in the full
// ResponseManager.
// ---------------------------------------------------------------------------
std::string summarizeTarget(const ActionTarget& t);

}  // namespace odysseus::response

#endif  // ODYSSEUS_RESPONSE_ACTION_LOG_H
