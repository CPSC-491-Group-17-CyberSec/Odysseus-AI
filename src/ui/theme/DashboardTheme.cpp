// ============================================================================
// DashboardTheme.cpp
//
// Implementation strategy:
//   • install() sets a QPalette so native (un-stylesheeted) widgets pick up
//     the dark colors automatically (menus, tooltips, scroll bars, etc.).
//   • Then it applies a global QSS sheet for any widget that we DO style.
//   • Older widgets that have inline setStyleSheet() calls keep their look
//     until Step 5 strips/replaces them.
// ============================================================================

#include "DashboardTheme.h"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QString>

namespace Theme {

void install(QApplication* app) {
  if (!app)
    return;

  QPalette p = app->palette();

  auto col = [](const char* hex) { return QColor(hex); };

  p.setColor(QPalette::Window, col(Color::bgPrimary));
  p.setColor(QPalette::WindowText, col(Color::textPrimary));
  p.setColor(QPalette::Base, col(Color::bgSecondary));
  p.setColor(QPalette::AlternateBase, col(Color::bgCard));
  p.setColor(QPalette::ToolTipBase, col(Color::bgCard));
  p.setColor(QPalette::ToolTipText, col(Color::textPrimary));
  p.setColor(QPalette::Text, col(Color::textPrimary));
  p.setColor(QPalette::Button, col(Color::bgCard));
  p.setColor(QPalette::ButtonText, col(Color::textPrimary));
  p.setColor(QPalette::BrightText, col("#FF3030"));
  p.setColor(QPalette::Link, col(Color::accentBlue));
  p.setColor(QPalette::Highlight, col(Color::accentBlue));
  p.setColor(QPalette::HighlightedText, col("#FFFFFF"));
  p.setColor(QPalette::PlaceholderText, col(Color::textMuted));

  // Disabled state — slightly muted versions
  p.setColor(QPalette::Disabled, QPalette::WindowText, col(Color::textMuted));
  p.setColor(QPalette::Disabled, QPalette::Text, col(Color::textMuted));
  p.setColor(QPalette::Disabled, QPalette::ButtonText, col(Color::textMuted));

  app->setPalette(p);
  app->setStyleSheet(globalStyleSheet());
}

QString globalStyleSheet() {
  // Note: keep this lean. Heavy styling lives on individual widget classes
  // so it's easy to override per-component without leaking selectors.
  return QString(
             "QMainWindow, QWidget#OdyShell {"
             "  background-color: %1;"
             "}"
             "QToolTip {"
             "  background-color: %2;"
             "  color: %3;"
             "  border: 1px solid %4;"
             "  padding: 4px 8px;"
             "  border-radius: 6px;"
             "}"
             "QScrollBar:vertical {"
             "  background: transparent;"
             "  width: 10px;"
             "  margin: 4px 2px 4px 0;"
             "}"
             "QScrollBar::handle:vertical {"
             "  background: %4;"
             "  border-radius: 4px;"
             "  min-height: 20px;"
             "}"
             "QScrollBar::handle:vertical:hover {"
             "  background: %5;"
             "}"
             "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
             "  height: 0; background: transparent;"
             "}"
             "QScrollBar:horizontal { background: transparent; height: 10px; }"
             "QScrollBar::handle:horizontal {"
             "  background: %4; border-radius: 4px; min-width: 20px;"
             "}"
             "QScrollBar::handle:horizontal:hover { background: %5; }"
             "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {"
             "  width: 0; background: transparent;"
             "}")
      .arg(Color::bgPrimary)        // %1
      .arg(Color::bgCard)           // %2
      .arg(Color::textPrimary)      // %3
      .arg(Color::borderSubtle)     // %4
      .arg(Color::accentBlueSoft);  // %5
}

const char* severityHex(const QString& sev) {
  const QString s = sev.toLower();
  if (s == "critical")
    return Color::severityCritical;
  if (s == "high")
    return Color::severityHigh;
  if (s == "medium")
    return Color::severityMedium;
  if (s == "low")
    return Color::severityLow;
  if (s == "safe" || s == "ok" || s == "clean")
    return Color::severitySafe;
  return Color::severityInfo;
}

}  // namespace Theme
