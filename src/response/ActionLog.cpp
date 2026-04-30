// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: src/response/ActionLog.cpp
// =============================================================================

#include "response/ActionLog.h"
#include "response/MiniJson.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#if defined(__APPLE__)
    #define ODY_PLATFORM_MAC 1
#elif defined(__linux__)
    #define ODY_PLATFORM_LINUX 1
#endif

namespace odysseus::response {

namespace fs = std::filesystem;

namespace {

std::string homeDir() {
    if (const char* h = std::getenv("HOME")) return h;
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

std::string makeId() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    std::ostringstream os;
    os << "act-" << std::hex << nowEpoch() << '-' << dist(rng);
    return os.str();
}

std::optional<ActionType> parseActionType(const std::string& s) {
    // Lookup table avoids a long if/else chain. Matches the strings emitted
    // by toString(ActionType).
    static const std::pair<const char*, ActionType> kTable[] = {
        {"None",                   ActionType::None},
        {"OpenLocation",           ActionType::OpenLocation},
        {"CopyPath",               ActionType::CopyPath},
        {"CopyHash",               ActionType::CopyHash},
        {"CopyDetails",            ActionType::CopyDetails},
        {"CopyCommandLine",        ActionType::CopyCommandLine},
        {"Investigate",            ActionType::Investigate},
        {"QuarantineFile",         ActionType::QuarantineFile},
        {"RestoreFromQuarantine",  ActionType::RestoreFromQuarantine},
        {"ViewProcessDetails",     ActionType::ViewProcessDetails},
        {"KillProcess",            ActionType::KillProcess},
        {"DisablePersistenceItem", ActionType::DisablePersistenceItem},
        {"ViewBaseline",           ActionType::ViewBaseline},
        {"ResetIntegrityBaseline", ActionType::ResetIntegrityBaseline},
        {"MarkTrustedAfterReview", ActionType::MarkTrustedAfterReview},
        {"AddToAllowlist",         ActionType::AddToAllowlist},
        {"RemoveFromAllowlist",    ActionType::RemoveFromAllowlist},
    };
    for (const auto& [name, value] : kTable) {
        if (s == name) return value;
    }
    return std::nullopt;
}

std::optional<TargetKind> parseTargetKind(const std::string& s) {
    if (s == "File")            return TargetKind::File;
    if (s == "Process")         return TargetKind::Process;
    if (s == "Persistence")     return TargetKind::Persistence;
    if (s == "Integrity")       return TargetKind::Integrity;
    if (s == "KernelExtension") return TargetKind::KernelExtension;
    if (s == "Unknown")         return TargetKind::Unknown;
    return std::nullopt;
}

}  // namespace

// ---------------------------------------------------------------------------
// summarizeTarget — short human-readable form used in audit-log records and
// in UI tooltips.
// ---------------------------------------------------------------------------
std::string summarizeTarget(const ActionTarget& t) {
    std::ostringstream os;
    switch (t.kind) {
        case TargetKind::File:
            os << "file: " << (t.path.empty() ? "<unknown>" : t.path);
            if (!t.sha256.empty()) os << " sha256=" << t.sha256.substr(0, 12);
            break;
        case TargetKind::Process:
            os << "process: ";
            if (!t.processName.empty()) os << t.processName << ' ';
            if (t.pid >= 0) os << "pid=" << t.pid;
            break;
        case TargetKind::Persistence:
            os << "persistence: "
               << (t.label.empty() ? t.path : t.label);
            break;
        case TargetKind::Integrity:
            os << "integrity: "
               << (t.path.empty() ? t.sourceId : t.path);
            break;
        case TargetKind::KernelExtension:
            os << "kext: " << (t.label.empty() ? t.path : t.label);
            break;
        case TargetKind::Unknown:
        default:
            os << "<unknown target>";
    }
    return os.str();
}

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------
ActionLog::ActionLog()
    : ActionLog(defaultAppDataDir() + "/odysseus_action_log.jsonl") {}

ActionLog::ActionLog(std::string filePath) : filePath_(std::move(filePath)) {}

// ---------------------------------------------------------------------------
// Append.
// ---------------------------------------------------------------------------
std::string ActionLog::append(ActionLogRecord record) {
    std::lock_guard<std::mutex> g(mutex_);
    if (record.id.empty())              record.id = makeId();
    if (record.timestampEpoch == 0)     record.timestampEpoch = nowEpoch();

    std::error_code ec;
    fs::create_directories(fs::path(filePath_).parent_path(), ec);
    if (ec) {
        lastError_ = "Could not create action-log directory: " + ec.message();
        return "";
    }

    std::ofstream out(filePath_, std::ios::app);
    if (!out) {
        lastError_ = "Could not open action-log: " + filePath_;
        return "";
    }
    mjson::ObjectWriter w;
    w.addString("id",             record.id)
     .addInt   ("timestampEpoch", record.timestampEpoch)
     .addString("action",         toString(record.action))
     .addString("targetKind",     toString(record.targetKind))
     .addString("targetSummary",  record.targetSummary)
     .addBool  ("userConfirmed",  record.userConfirmed)
     .addBool  ("success",        record.success)
     .addString("message",        record.message)
     .addString("errorMessage",   record.errorMessage);
    out << w.str() << '\n';
    out.flush();
    if (!out) {
        lastError_ = "Failed to write action-log line";
        return "";
    }
    return record.id;
}

// ---------------------------------------------------------------------------
// Read.
// ---------------------------------------------------------------------------
std::vector<ActionLogRecord> ActionLog::readAll() const {
    std::lock_guard<std::mutex> g(mutex_);
    std::vector<ActionLogRecord> out;
    std::error_code ec;
    if (!fs::exists(filePath_, ec)) return out;

    std::ifstream in(filePath_);
    if (!in) {
        lastError_ = "Could not open action-log for read: " + filePath_;
        return out;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto obj = mjson::parseLine(line);
        if (!obj.ok) continue;
        ActionLogRecord r;
        r.id              = obj.getString("id").value_or("");
        r.timestampEpoch  = obj.getInt("timestampEpoch").value_or(0);
        r.action          = parseActionType(
                                 obj.getString("action").value_or("None"))
                                 .value_or(ActionType::None);
        r.targetKind      = parseTargetKind(
                                 obj.getString("targetKind").value_or("Unknown"))
                                 .value_or(TargetKind::Unknown);
        r.targetSummary   = obj.getString("targetSummary").value_or("");
        r.userConfirmed   = obj.getBool("userConfirmed").value_or(false);
        r.success         = obj.getBool("success").value_or(false);
        r.message         = obj.getString("message").value_or("");
        r.errorMessage    = obj.getString("errorMessage").value_or("");
        out.push_back(std::move(r));
    }
    return out;
}

std::string ActionLog::getLastError() const {
    std::lock_guard<std::mutex> g(mutex_);
    return lastError_;
}

}  // namespace odysseus::response
