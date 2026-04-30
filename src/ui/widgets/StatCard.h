#pragma once
// ============================================================================
// StatCard.h  –  KPI tile used along the top of the Dashboard page.
//
// Tones drive the accent color (left border + tinted background) so the
// card communicates state at a glance:
//   • Safe     → green (System Status: Protected)
//   • Critical → red    (Critical Threats)
//   • Warning  → yellow (Suspicious Files)
//   • Info     → blue   (Files Scanned)
//
// API:
//   setTitle("Critical Threats"), setValue("1"),
//   setSubtitle("Requires immediate attention"), setIcon("⚠"),
//   setTone(StatCard::Critical)
// ============================================================================

#include <QFrame>
#include <QString>

class QLabel;

class StatCard : public QFrame {
  Q_OBJECT
 public:
  enum Tone { Safe, Critical, Warning, Info };

  explicit StatCard(QWidget* parent = nullptr);

  void setTone(Tone tone);
  void setTitle(const QString& title);
  void setValue(const QString& value);
  void setSubtitle(const QString& subtitle);
  void setIcon(const QString& glyph);

 private:
  void applyTone();

  QLabel* m_titleLabel = nullptr;
  QLabel* m_valueLabel = nullptr;
  QLabel* m_subtitleLabel = nullptr;
  QLabel* m_iconLabel = nullptr;
  QFrame* m_pulseBar = nullptr;
  Tone m_tone = Info;
};
