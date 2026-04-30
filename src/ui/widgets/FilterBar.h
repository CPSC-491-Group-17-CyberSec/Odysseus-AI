#pragma once
// ============================================================================
// FilterBar.h  –  Alerts page filter controls.
//
// Layout:
//   [chip All] [chip Critical] [chip High] [chip Medium] [chip Low]
//                                            [Category ▾]  [Search …]
//
// Severity chip selection is mutually exclusive (radio-style). Category
// dropdown maps to EDR::Category constants (or "All"). Search filters by
// title / source-path / category text.
//
// State changes emit `filtersChanged()` — caller re-runs its row-build pass.
// ============================================================================

#include <QString>
#include <QVector>
#include <QWidget>

#include "../../../include/edr/AlertTypes.h"

class QPushButton;
class QLineEdit;
class QComboBox;
class QHBoxLayout;

class FilterBar : public QWidget {
  Q_OBJECT
 public:
  explicit FilterBar(QWidget* parent = nullptr);

  /// "All" or one of EDR::Severity (cast as int + 1; returns -1 for All).
  int selectedSeverity() const;
  QString selectedCategory() const;  // "" means All
  QString searchText() const;

 signals:
  void filtersChanged();

 private slots:
  void onChipClicked();

 private:
  QPushButton* makeChip(const QString& label, int severityValue);

  QVector<QPushButton*> m_chips;  // [All, Critical, High, Medium, Low]
  int m_activeChip = 0;           // index — All by default
  QComboBox* m_categoryCombo = nullptr;
  QLineEdit* m_search = nullptr;
};
