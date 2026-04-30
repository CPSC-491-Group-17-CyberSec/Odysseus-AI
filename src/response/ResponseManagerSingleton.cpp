// =============================================================================
// Odysseus-AI  -  Phase 5 integration
// File: src/response/ResponseManagerSingleton.cpp
// =============================================================================

#include "response/ResponseManagerSingleton.h"

namespace odysseus::response {

ResponseManager& globalResponseManager() {
    // Meyer's singleton — initialization is thread-safe under C++17.
    // Default construction wires the standard app-data paths:
    //   macOS  : ~/Library/Application Support/Odysseus-AI/
    //   Linux  : ~/.local/share/Odysseus-AI/
    static ResponseManager mgr;
    return mgr;
}

Allowlist* globalAllowlist() {
    return &globalResponseManager().allowlist();
}

}  // namespace odysseus::response
