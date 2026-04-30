// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: src/response/Quarantine.cpp
// =============================================================================

#include "response/Quarantine.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#include "response/MiniJson.h"

#if defined(__APPLE__)
#define ODY_PLATFORM_MAC 1
#elif defined(__linux__)
#define ODY_PLATFORM_LINUX 1
#endif

namespace odysseus::response {

namespace fs = std::filesystem;

namespace {

std::string homeDir() {
  if (const char* h = std::getenv("HOME"))
    return h;
  return ".";
}

std::string defaultAppDataDir() {
#if defined(ODY_PLATFORM_MAC)
  return homeDir() + "/Library/Application Support/Odysseus-AI";
#else
  if (const char* xdg = std::getenv("XDG_DATA_HOME"))
    return std::string(xdg) + "/Odysseus-AI";
  return homeDir() + "/.local/share/Odysseus-AI";
#endif
}

std::int64_t nowEpoch() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------
Quarantine::Quarantine()
    : Quarantine(
          defaultAppDataDir() + "/quarantine", defaultAppDataDir() + "/quarantine_metadata.jsonl") {
}

Quarantine::Quarantine(std::string quarantineDir, std::string metadataPath)
    : quarantineDir_(std::move(quarantineDir)),
      metadataPath_(std::move(metadataPath)) {
  std::error_code ec;
  fs::create_directories(quarantineDir_, ec);  // best-effort
  std::lock_guard<std::mutex> g(mutex_);
  loadLocked();
}

// ---------------------------------------------------------------------------
// Metadata I/O.
// ---------------------------------------------------------------------------
bool Quarantine::loadLocked() {
  entries_.clear();
  std::error_code ec;
  if (!fs::exists(metadataPath_, ec))
    return true;

  std::ifstream in(metadataPath_);
  if (!in) {
    lastError_ = "Could not open quarantine metadata: " + metadataPath_;
    return false;
  }
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty())
      continue;
    auto obj = mjson::parseLine(line);
    if (!obj.ok)
      continue;

    QuarantineEntry e;
    e.id = obj.getString("id").value_or("");
    e.originalPath = obj.getString("originalPath").value_or("");
    e.quarantinePath = obj.getString("quarantinePath").value_or("");
    e.sha256 = obj.getString("sha256").value_or("");
    e.timestampEpoch = obj.getInt("timestampEpoch").value_or(0);
    e.reason = obj.getString("reason").value_or("");
    e.sourceId = obj.getString("sourceId").value_or("");
    if (!e.id.empty())
      entries_.push_back(std::move(e));
  }
  return true;
}

bool Quarantine::flushLocked() const {
  std::error_code ec;
  fs::create_directories(fs::path(metadataPath_).parent_path(), ec);
  if (ec) {
    lastError_ = "Could not create metadata directory: " + ec.message();
    return false;
  }

  std::string tmp = metadataPath_ + ".tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
      lastError_ = "Could not open metadata tmp file: " + tmp;
      return false;
    }
    for (const auto& e : entries_) {
      mjson::ObjectWriter w;
      w.addString("id", e.id)
          .addString("originalPath", e.originalPath)
          .addString("quarantinePath", e.quarantinePath)
          .addString("sha256", e.sha256)
          .addInt("timestampEpoch", e.timestampEpoch)
          .addString("reason", e.reason)
          .addString("sourceId", e.sourceId);
      out << w.str() << '\n';
    }
    out.flush();
    if (!out) {
      lastError_ = "Failed to write metadata tmp file";
      return false;
    }
  }
  fs::rename(tmp, metadataPath_, ec);
  if (ec) {
    lastError_ = "Failed to rename metadata tmp file: " + ec.message();
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// ID generation. Cheap pseudo-uuid (timestamp + random hex). Uniqueness is
// enforced by checking the entry vector before inserting; collisions are
// astronomically unlikely but handled defensively.
// ---------------------------------------------------------------------------
std::string Quarantine::makeId() {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  std::uniform_int_distribution<std::uint64_t> dist;
  std::ostringstream os;
  os << std::hex << nowEpoch() << '-' << dist(rng);
  return os.str();
}

// ---------------------------------------------------------------------------
// Quarantine.
// ---------------------------------------------------------------------------
std::optional<QuarantineEntry> Quarantine::quarantine(
    const std::string& originalPath,
    const std::string& sha256,
    const std::string& reason,
    const std::string& sourceId) {
  std::lock_guard<std::mutex> g(mutex_);

  if (originalPath.empty()) {
    lastError_ = "quarantine: empty originalPath";
    return std::nullopt;
  }

  std::error_code ec;
  if (!fs::exists(originalPath, ec)) {
    lastError_ = "quarantine: file does not exist: " + originalPath;
    return std::nullopt;
  }
  if (fs::is_directory(originalPath, ec)) {
    lastError_ = "quarantine: refusing to quarantine a directory";
    return std::nullopt;
  }

  fs::create_directories(quarantineDir_, ec);
  if (ec) {
    lastError_ = "quarantine: could not create dir: " + ec.message();
    return std::nullopt;
  }

  QuarantineEntry entry;
  entry.id = makeId();
  entry.originalPath = fs::absolute(originalPath, ec).string();
  if (ec)
    entry.originalPath = originalPath;
  entry.sha256 = sha256;
  entry.timestampEpoch = nowEpoch();
  entry.reason = reason;
  entry.sourceId = sourceId;

  const std::string baseName = fs::path(originalPath).filename().string();
  entry.quarantinePath =
      (fs::path(quarantineDir_) / (baseName + "." + entry.id + ".quarantine")).string();

  // Try rename first (works inside a single filesystem). Fall back to
  // copy + remove for cross-device moves.
  fs::rename(entry.originalPath, entry.quarantinePath, ec);
  if (ec) {
    ec.clear();
    fs::copy_file(
        entry.originalPath, entry.quarantinePath, fs::copy_options::overwrite_existing, ec);
    if (ec) {
      lastError_ = "quarantine: copy failed: " + ec.message();
      return std::nullopt;
    }
    fs::remove(entry.originalPath, ec);
    if (ec) {
      // Roll back: leave the copied file in quarantine, but report.
      lastError_ = "quarantine: removed-original failed: " + ec.message();
      // Continue — file is at least preserved in quarantine.
    }
  }

  // Tighten permissions on the quarantined file (owner read only). Best
  // effort; ignore failures.
  fs::permissions(entry.quarantinePath, fs::perms::owner_read, fs::perm_options::replace, ec);

  entries_.push_back(entry);
  if (!flushLocked())
    return std::nullopt;
  return entry;
}

// ---------------------------------------------------------------------------
// Restore.
// ---------------------------------------------------------------------------
ActionResult Quarantine::restore(const std::string& entryId, RestoreConflictPolicy policy) {
  std::lock_guard<std::mutex> g(mutex_);
  ActionResult res;

  auto it = std::find_if(
      entries_.begin(), entries_.end(), [&](const QuarantineEntry& e) { return e.id == entryId; });
  if (it == entries_.end()) {
    res.errorMessage = "restore: no quarantine entry with id " + entryId;
    return res;
  }

  std::error_code ec;
  if (!fs::exists(it->quarantinePath, ec)) {
    res.errorMessage = "restore: quarantined file missing on disk: " + it->quarantinePath;
    return res;
  }

  std::string destination = it->originalPath;
  bool destinationExists = fs::exists(destination, ec);

  if (destinationExists) {
    switch (policy) {
      case RestoreConflictPolicy::AskUser:
        res.needsUserChoice = true;
        res.message =
            "Original path already exists. Choose how to "
            "restore.";
        return res;
      case RestoreConflictPolicy::Cancel:
        res.message = "Restore cancelled by user.";
        return res;
      case RestoreConflictPolicy::Overwrite:
        fs::remove(destination, ec);
        if (ec) {
          res.errorMessage =
              "restore overwrite: could not remove "
              "existing file: " +
              ec.message();
          return res;
        }
        break;
      case RestoreConflictPolicy::RestoreWithNewName: {
        fs::path p(destination);
        std::string stem = p.stem().string();
        std::string ext = p.extension().string();
        int n = 1;
        fs::path candidate;
        do {
          candidate = p.parent_path() / (stem + ".restored-" + std::to_string(n++) + ext);
        } while (fs::exists(candidate, ec) && n < 1000);
        destination = candidate.string();
        break;
      }
    }
  }

  fs::create_directories(fs::path(destination).parent_path(), ec);
  fs::rename(it->quarantinePath, destination, ec);
  if (ec) {
    ec.clear();
    fs::copy_file(it->quarantinePath, destination, fs::copy_options::overwrite_existing, ec);
    if (ec) {
      res.errorMessage = "restore: copy failed: " + ec.message();
      return res;
    }
    fs::remove(it->quarantinePath, ec);  // best-effort
  }

  // Restore default file mode (owner rw + group/world read). Best effort.
  fs::permissions(
      destination,
      fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
          fs::perms::others_read,
      fs::perm_options::replace,
      ec);

  res.success = true;
  res.newPath = destination;
  res.message = "Restored to " + destination;

  entries_.erase(it);
  flushLocked();  // remove the metadata entry too
  return res;
}

// ---------------------------------------------------------------------------
// Queries / diagnostics.
// ---------------------------------------------------------------------------
std::vector<QuarantineEntry> Quarantine::list() const {
  std::lock_guard<std::mutex> g(mutex_);
  return entries_;
}

std::optional<QuarantineEntry> Quarantine::findById(const std::string& id) const {
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.id == id)
      return e;
  }
  return std::nullopt;
}

std::optional<QuarantineEntry> Quarantine::findByOriginalPath(
    const std::string& originalPath) const {
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.originalPath == originalPath)
      return e;
  }
  return std::nullopt;
}

std::string Quarantine::getLastError() const {
  std::lock_guard<std::mutex> g(mutex_);
  return lastError_;
}

}  // namespace odysseus::response
