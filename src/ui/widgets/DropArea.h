#pragma once
// ============================================================================
// DropArea.h  –  drop-target QFrame for the Scan page.
//
// Visual: dashed border + accent-blue folder glyph + two lines of help text.
// Behavior: accepts dropped files / folders; emits filesDropped() with the
// list of local file paths. Hover state lifts the border + tint (handled
// via stylesheet swap on the m_hovered flag).
// ============================================================================

#include <QFrame>
#include <QStringList>

class QLabel;

class DropArea : public QFrame {
  Q_OBJECT
 public:
  explicit DropArea(QWidget* parent = nullptr);

 signals:
  void filesDropped(const QStringList& paths);

 protected:
  void dragEnterEvent(QDragEnterEvent* e) override;
  void dragLeaveEvent(QDragLeaveEvent* e) override;
  void dropEvent(QDropEvent* e) override;

 private:
  void applyStyle();

  QLabel* m_iconLabel = nullptr;
  QLabel* m_titleLabel = nullptr;
  QLabel* m_subLabel = nullptr;
  bool m_hovered = false;
};
