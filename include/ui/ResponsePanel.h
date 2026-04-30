// =============================================================================
// Odysseus-AI  -  Phase 5: Response & Control Layer
// File: include/ui/ResponsePanel.h
//
// Framework-agnostic UI integration scaffold. The Phase 5 spec calls for
// action buttons on three views — Alert detail, Result detail, System Status
// detail — but Odysseus-AI's UI layer hasn't yet picked a single framework.
// This header defines the contract any UI implementation must satisfy:
//
//   * Build the action panel for a given target (which buttons to show).
//   * Decide which buttons are enabled, with tooltips explaining why.
//   * Drive the user-confirmation flow for destructive actions.
//   * Hand the chosen action off to ResponseManager.
//
// Wire it up in src/ui/ResponsePanel.cpp once the host UI framework (Qt
// widgets, ImGui, web-view etc.) is selected. The functions below have
// concrete C++ implementations that any UI can call directly — they don't
// depend on widget libraries.
// =============================================================================

#ifndef ODYSSEUS_UI_RESPONSE_PANEL_H
#define ODYSSEUS_UI_RESPONSE_PANEL_H

#include <string>
#include <vector>

#include "response/ResponseManager.h"
#include "response/ResponseTypes.h"

namespace odysseus::ui {

using response::ActionTarget;
using response::ActionType;

// Per-button descriptor returned to the UI to render an action panel.
struct ActionButton {
  ActionType action;
  std::string label;    // user-visible text
  std::string tooltip;  // shown on hover; explains "why disabled" too
  bool enabled;
  bool destructive;     // UI should style differently and ask to confirm
};

// Builds the canonical button list for an alert detail panel. The order is
// stable across calls so the UI can render them positionally.
std::vector<ActionButton> buildAlertActions(
    const response::ResponseManager& mgr, const ActionTarget& t);

// Same shape, for scan-result detail panels and system-status detail panels.
std::vector<ActionButton> buildResultActions(
    const response::ResponseManager& mgr, const ActionTarget& t);
std::vector<ActionButton> buildSystemStatusActions(
    const response::ResponseManager& mgr, const ActionTarget& t);

// User-facing confirmation prompts. Use these strings in the modal dialogs;
// they're written once here so wording stays consistent across the app.
struct ConfirmPrompt {
  std::string title;
  std::string body;
  std::string confirmLabel;
  std::string cancelLabel;
};
ConfirmPrompt confirmPromptFor(ActionType action, const ActionTarget& t);

}  // namespace odysseus::ui

#endif  // ODYSSEUS_UI_RESPONSE_PANEL_H
