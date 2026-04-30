#pragma once
// ============================================================================
// DetailSection.h  –  one section of the Results-page right detail panel.
//
// Visual: thin colored accent bar on the left, section title, body content.
// Body can be either a plain rich-text label or a bullet list (one entry
// per QStringList item). Designed for repeated use in the detail panel:
//   "Why was this flagged?", "AI Summary", "Indicators", "Recommended Actions".
// ============================================================================

#include <QFrame>
#include <QString>
#include <QStringList>

class QLabel;
class QVBoxLayout;

class DetailSection : public QFrame {
  Q_OBJECT
 public:
  /// `accentHex` controls the left-border color (severity / accent blue).
  /// Defaults to accent blue; pass severity color when relevant.
  explicit DetailSection(
      const QString& title, const QString& accentHex = QString(), QWidget* parent = nullptr);

  /// Replace body content with a single paragraph. Call clear() first
  /// or use setBullets() to switch modes.
  void setBody(const QString& bodyText);

  /// Replace body content with a bullet list. Each item is rendered on
  /// its own line with a leading "• ".
  void setBullets(const QStringList& bullets);

  /// Drop all current body widgets.
  void clear();

 private:
  QString m_accentHex;
  QLabel* m_titleLabel = nullptr;
  QVBoxLayout* m_body = nullptr;
};
