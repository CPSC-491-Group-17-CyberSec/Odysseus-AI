// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: src/response/Allowlist.cpp
// =============================================================================

#include "response/Allowlist.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "response/MiniJson.h"

#if defined(__APPLE__)
#define ODY_PLATFORM_MAC 1
#elif defined(__linux__)
#define ODY_PLATFORM_LINUX 1
#endif

namespace odysseus::response {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Platform helpers — kept inline here (Allowlist is the first subsystem to
// use them; later files share their own copies via internal linkage to keep
// each translation unit self-contained for the test scaffolding).
// ---------------------------------------------------------------------------
namespace {

std::string homeDir() {
  if (const char* h = std::getenv("HOME"))
    return h;
  return ".";
}

std::string appDataDir() {
#if defined(ODY_PLATFORM_MAC)
  return homeDir() + "/Library/Application Support/Odysseus-AI";
#else
  if (const char* xdg = std::getenv("XDG_DATA_HOME")) {
    return std::string(xdg) + "/Odysseus-AI";
  }
  return homeDir() + "/.local/share/Odysseus-AI";
#endif
}

std::int64_t nowEpoch() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

const char* kindToString(AllowlistEntry::Kind k) {
  return toString(k);
}

std::optional<AllowlistEntry::Kind> parseKind(const std::string& s) {
  if (s == "FileSha256")
    return AllowlistEntry::Kind::FileSha256;
  if (s == "FilePath")
    return AllowlistEntry::Kind::FilePath;
  if (s == "ProcessPath")
    return AllowlistEntry::Kind::ProcessPath;
  if (s == "PersistenceLabel")
    return AllowlistEntry::Kind::PersistenceLabel;
  if (s == "PersistencePath")
    return AllowlistEntry::Kind::PersistencePath;
  if (s == "AlertSignatureKey")
    return AllowlistEntry::Kind::AlertSignatureKey;
  return std::nullopt;
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------
std::string Allowlist::defaultPath() {
  return appDataDir() + "/odysseus_allowlist.jsonl";
}

Allowlist::Allowlist(std::string filePath)
    : filePath_(std::move(filePath)) {
  std::lock_guard<std::mutex> g(mutex_);
  loadLocked();
}

// ---------------------------------------------------------------------------
// Load / flush.
// ---------------------------------------------------------------------------
bool Allowlist::loadLocked() {
  entries_.clear();
  std::error_code ec;
  if (!fs::exists(filePath_, ec)) {
    // First run — nothing to do.
    return true;
  }

  std::ifstream in(filePath_);
  if (!in) {
    lastError_ = "Could not open allowlist file: " + filePath_;
    return false;
  }
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty())
      continue;
    auto obj = mjson::parseLine(line);
    if (!obj.ok)
      continue;  // skip malformed lines defensively

    auto kindStr = obj.getString("kind");
    auto value = obj.getString("value");
    if (!kindStr || !value)
      continue;
    auto kind = parseKind(*kindStr);
    if (!kind)
      continue;

    AllowlistEntry e;
    e.kind = *kind;
    e.value = *value;
    e.addedEpoch = obj.getInt("addedEpoch").value_or(0);
    e.note = obj.getString("note").value_or("");
    entries_.push_back(std::move(e));
  }
  return true;
}

bool Allowlist::flushLocked() const {
  std::error_code ec;
  fs::create_directories(fs::path(filePath_).parent_path(), ec);
  if (ec) {
    lastError_ = "Could not create allowlist directory: " + ec.message();
    return false;
  }

  // Write to a tmp file then rename — atomic-ish on POSIX.
  std::string tmp = filePath_ + ".tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
      lastError_ = "Could not open allowlist tmp file: " + tmp;
      return false;
    }
    for (const auto& e : entries_) {
      mjson::ObjectWriter w;
      w.addString("kind", kindToString(e.kind))
          .addString("value", e.value)
          .addInt("addedEpoch", e.addedEpoch)
          .addString("note", e.note);
      out << w.str() << '\n';
    }
    out.flush();
    if (!out) {
      lastError_ = "Failed to write allowlist tmp file";
      return false;
    }
  }
  fs::rename(tmp, filePath_, ec);
  if (ec) {
    lastError_ = "Failed to rename allowlist tmp file: " + ec.message();
    return false;
  }
  return true;
}

bool Allowlist::reload() {
  std::lock_guard<std::mutex> g(mutex_);
  return loadLocked();
}

bool Allowlist::flush() const {
  std::lock_guard<std::mutex> g(mutex_);
  return flushLocked();
}

// ---------------------------------------------------------------------------
// Mutators.
// ---------------------------------------------------------------------------
bool Allowlist::add(AllowlistEntry entry) {
  std::lock_guard<std::mutex> g(mutex_);
  if (entry.value.empty()) {
    lastError_ = "Refusing to add empty allowlist value";
    return false;
  }
  // Dedupe — exact (kind, value) pair must be unique.
  for (const auto& e : entries_) {
    if (e.kind == entry.kind && e.value == entry.value) {
      return true;  // already present is success
    }
  }
  if (entry.addedEpoch == 0)
    entry.addedEpoch = nowEpoch();
  entries_.push_back(std::move(entry));
  return flushLocked();
}

bool Allowlist::remove(AllowlistEntry::Kind kind, const std::string& value) {
  std::lock_guard<std::mutex> g(mutex_);
  auto before = entries_.size();
  entries_.erase(
      std::remove_if(
          entries_.begin(),
          entries_.end(),
          [&](const AllowlistEntry& e) { return e.kind == kind && e.value == value; }),
      entries_.end());
  if (entries_.size() == before)
    return false;
  return flushLocked();
}

// ---------------------------------------------------------------------------
// Queries.
// ---------------------------------------------------------------------------
bool Allowlist::contains(AllowlistEntry::Kind kind, const std::string& value) const {
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.kind == kind && e.value == value)
      return true;
  }
  return false;
}

bool Allowlist::isFileIgnored(const std::string& path, const std::string& sha256) const {
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.kind == AllowlistEntry::Kind::FilePath && !path.empty() && e.value == path)
      return true;
    if (e.kind == AllowlistEntry::Kind::FileSha256 && !sha256.empty() && e.value == sha256)
      return true;
  }
  return false;
}

bool Allowlist::isProcessIgnored(const std::string& processPath) const {
  if (processPath.empty())
    return false;
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.kind == AllowlistEntry::Kind::ProcessPath && e.value == processPath)
      return true;
  }
  return false;
}

bool Allowlist::isPersistenceIgnored(const std::string& label, const std::string& path) const {
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.kind == AllowlistEntry::Kind::PersistenceLabel && !label.empty() && e.value == label)
      return true;
    if (e.kind == AllowlistEntry::Kind::PersistencePath && !path.empty() && e.value == path)
      return true;
  }
  return false;
}

bool Allowlist::isAlertSignatureIgnored(const std::string& signatureKey) const {
  if (signatureKey.empty())
    return false;
  std::lock_guard<std::mutex> g(mutex_);
  for (const auto& e : entries_) {
    if (e.kind == AllowlistEntry::Kind::AlertSignatureKey && e.value == signatureKey)
      return true;
  }
  return false;
}

std::vector<AllowlistEntry> Allowlist::list() const {
  std::lock_guard<std::mutex> g(mutex_);
  return entries_;
}

std::string Allowlist::getLastError() const {
  std::lock_guard<std::mutex> g(mutex_);
  return lastError_;
}

}  // namespace odysseus::response
