#pragma once
// ============================================================================
// Sidebar.h  –  fixed-width left navigation column
//
// Self-contained: knows nothing about pages, only emits a signal saying
// "the user clicked the i-th button". MainWindow wires that to its
// QStackedWidget.
//
// The buttons themselves are plain QPushButtons styled via stylesheet to
// look like sidebar nav items. Avoiding a custom QAbstractButton subclass
// keeps the moc surface small and the UI inspector-friendly.
// ============================================================================

#include <QString>
#include <QVector>
#include <QWidget>

class QPushButton;
class QButtonGroup;
class QVBoxLayout;
class QLabel;

class Sidebar : public QWidget {
  Q_OBJECT
 public:
  explicit Sidebar(QWidget* parent = nullptr);

  /// Add a navigation item. Index returned matches the order of additions.
  /// `glyph` is a short text/unicode glyph rendered before the label.
  int addItem(const QString& label, const QString& glyph);

  /// Programmatically select an item (no signal emitted).
  void setActive(int index);

  /// Set the small footer text below the nav (e.g. version).
  void setFooterText(const QString& text);

 signals:
  /// Emitted when the user clicks an item.
  void pageRequested(int index);

 private slots:
  void onButtonClicked();

 private:
  QVBoxLayout* m_buttonsLayout = nullptr;
  QButtonGroup* m_group = nullptr;
  QVector<QPushButton*> m_buttons;
  QLabel* m_footer = nullptr;
};
