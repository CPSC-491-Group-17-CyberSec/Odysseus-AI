// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/response/MiniJson.h
//
// A deliberately tiny JSON helper used only by the response subsystem.
// It is NOT a general-purpose JSON library. It supports just enough to
// serialize and parse our flat records (string/int64/bool fields) in a
// line-oriented (JSONL) format.
//
// Why we ship this instead of pulling nlohmann/json: the response subsystem
// must be self-contained for Phase 5 so it can compile on macOS and Linux
// with no third-party dependency drop. When Odysseus-AI later adopts a
// project-wide JSON library, the calls in this module can be swapped over
// with a small refactor (search for `mjson::`).
//
// Header-only. C++17. No exceptions thrown — failures return std::nullopt /
// false, which keeps the response subsystem in defensive-style code.
// =============================================================================

#ifndef ODYSSEUS_RESPONSE_MINIJSON_H
#define ODYSSEUS_RESPONSE_MINIJSON_H

#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <string>

namespace odysseus::response::mjson {

// ----------------------------------------------------------------------------
// Writer — builds one JSON object as a single line. Always emits valid JSON
// for the limited grammar we need.
// ----------------------------------------------------------------------------
class ObjectWriter {
 public:
  ObjectWriter() { os_ << '{'; }

  ObjectWriter& addString(const std::string& key, const std::string& value) {
    sep();
    emitKey(key);
    emitString(value);
    return *this;
  }
  ObjectWriter& addInt(const std::string& key, std::int64_t value) {
    sep();
    emitKey(key);
    os_ << value;
    return *this;
  }
  ObjectWriter& addBool(const std::string& key, bool value) {
    sep();
    emitKey(key);
    os_ << (value ? "true" : "false");
    return *this;
  }

  std::string str() {
    std::string out = os_.str();
    out.push_back('}');
    return out;
  }

 private:
  void sep() {
    if (!first_)
      os_ << ',';
    first_ = false;
  }
  void emitKey(const std::string& k) {
    emitString(k);
    os_ << ':';
  }
  void emitString(const std::string& s) {
    os_ << '"';
    for (char c : s) {
      switch (c) {
        case '"':
          os_ << "\\\"";
          break;
        case '\\':
          os_ << "\\\\";
          break;
        case '\n':
          os_ << "\\n";
          break;
        case '\r':
          os_ << "\\r";
          break;
        case '\t':
          os_ << "\\t";
          break;
        default:
          if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c) & 0xff);
            os_ << buf;
          } else {
            os_ << c;
          }
      }
    }
    os_ << '"';
  }

  std::ostringstream os_;
  bool first_ = true;
};

// ----------------------------------------------------------------------------
// Parser — parses one flat JSON object (keys -> string/number/bool) into
// std::map. Handles backslash escapes inside strings. Anything more exotic
// (nested objects, arrays) is rejected.
// ----------------------------------------------------------------------------
struct ParsedObject {
  std::map<std::string, std::string> values;  // raw stringified values
  bool ok = false;

  std::optional<std::string> getString(const std::string& key) const {
    auto it = values.find(key);
    if (it == values.end())
      return std::nullopt;
    return it->second;
  }
  std::optional<std::int64_t> getInt(const std::string& key) const {
    auto it = values.find(key);
    if (it == values.end())
      return std::nullopt;
    try {
      return static_cast<std::int64_t>(std::stoll(it->second));
    } catch (...) {
      return std::nullopt;
    }
  }
  std::optional<bool> getBool(const std::string& key) const {
    auto it = values.find(key);
    if (it == values.end())
      return std::nullopt;
    if (it->second == "true")
      return true;
    if (it->second == "false")
      return false;
    return std::nullopt;
  }
};

inline ParsedObject parseLine(const std::string& line) {
  ParsedObject out;
  std::size_t i = 0;
  auto skipWs = [&]() {
    while (i < line.size() &&
           (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n'))
      ++i;
  };
  auto parseString = [&](std::string& dst) -> bool {
    if (i >= line.size() || line[i] != '"')
      return false;
    ++i;
    while (i < line.size() && line[i] != '"') {
      if (line[i] == '\\' && i + 1 < line.size()) {
        char n = line[i + 1];
        switch (n) {
          case '"':
            dst.push_back('"');
            break;
          case '\\':
            dst.push_back('\\');
            break;
          case '/':
            dst.push_back('/');
            break;
          case 'n':
            dst.push_back('\n');
            break;
          case 'r':
            dst.push_back('\r');
            break;
          case 't':
            dst.push_back('\t');
            break;
          case 'b':
            dst.push_back('\b');
            break;
          case 'f':
            dst.push_back('\f');
            break;
          case 'u': {
            if (i + 5 >= line.size())
              return false;
            // Limited \uXXXX support: ASCII range only — adequate
            // for our generated payloads. Higher code points are
            // emitted as raw UTF-8 by the writer above.
            unsigned code = 0;
            for (int k = 0; k < 4; ++k) {
              char hc = line[i + 2 + k];
              code <<= 4;
              if (hc >= '0' && hc <= '9')
                code |= (hc - '0');
              else if (hc >= 'a' && hc <= 'f')
                code |= (hc - 'a' + 10);
              else if (hc >= 'A' && hc <= 'F')
                code |= (hc - 'A' + 10);
              else
                return false;
            }
            if (code < 0x80)
              dst.push_back(static_cast<char>(code));
            else
              dst.push_back('?');
            i += 4;
            break;
          }
          default:
            return false;
        }
        i += 2;
      } else {
        dst.push_back(line[i++]);
      }
    }
    if (i >= line.size() || line[i] != '"')
      return false;
    ++i;
    return true;
  };

  skipWs();
  if (i >= line.size() || line[i] != '{')
    return out;
  ++i;
  skipWs();

  if (i < line.size() && line[i] == '}') {
    out.ok = true;
    return out;
  }

  while (i < line.size()) {
    skipWs();
    std::string key;
    if (!parseString(key))
      return out;
    skipWs();
    if (i >= line.size() || line[i] != ':')
      return out;
    ++i;
    skipWs();

    std::string raw;
    if (i < line.size() && line[i] == '"') {
      if (!parseString(raw))
        return out;
    } else {
      // number, true, false, null — read until comma or close-brace
      while (i < line.size() && line[i] != ',' && line[i] != '}') {
        if (line[i] != ' ' && line[i] != '\t')
          raw.push_back(line[i]);
        ++i;
      }
    }
    out.values.emplace(std::move(key), std::move(raw));

    skipWs();
    if (i < line.size() && line[i] == ',') {
      ++i;
      continue;
    }
    if (i < line.size() && line[i] == '}') {
      ++i;
      out.ok = true;
      return out;
    }
    return out;  // malformed
  }
  return out;
}

}  // namespace odysseus::response::mjson

#endif  // ODYSSEUS_RESPONSE_MINIJSON_H
