// ============================================================================
// SecurityScoreCard.cpp
//
// ScoreGauge: a custom QWidget painted as a 180° semicircle gauge.
//   - Outer arc: thin red→yellow→green sweep (the full possible range)
//   - Inner arc: thicker fill at the actual score, in the score's color
//   - We compute the score color by piecewise-linear ramp 0→50→100.
// ============================================================================

#include "SecurityScoreCard.h"

#include <QConicalGradient>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QVBoxLayout>
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>

#include "../theme/DashboardTheme.h"

// ---------------------------------------------------------------------------
// ScoreGauge — custom-painted semicircle
//
// Polish pass: draws the score number INSIDE the arc (matches the mockup
// where the user sees "92" centered in the gauge). Below the number we
// draw a small "/100" caption so there's no ambiguity about the scale.
// The companion SecurityScoreCard removes the duplicate score label
// underneath.
// ---------------------------------------------------------------------------
class ScoreGauge : public QWidget {
  Q_OBJECT
 public:
  explicit ScoreGauge(QWidget* parent = nullptr)
      : QWidget(parent) {
    setMinimumHeight(170);
    setMinimumWidth(240);
  }
  void setScore(int s) {
    m_score = qBound(0, s, 100);
    update();
  }

 protected:
  void paintEvent(QPaintEvent*) override {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    // Use the bottom half of a centered square as the gauge area.
    const int margin = 8;
    const int side = qMin(width() - 2 * margin, (height() - margin) * 2);
    QRectF rect(width() / 2.0 - side / 2.0, margin, side, side);

    const int penWidth = qMax(10, side / 16);

    // ── Background arc (range red → yellow → green, 3 segments) ────
    p.setPen(QPen(QColor(Theme::Color::severityCritical), penWidth, Qt::SolidLine, Qt::FlatCap));
    p.drawArc(rect, 180 * 16, -60 * 16);
    p.setPen(QPen(QColor(Theme::Color::severityMedium), penWidth, Qt::SolidLine, Qt::FlatCap));
    p.drawArc(rect, 120 * 16, -60 * 16);
    p.setPen(QPen(QColor(Theme::Color::severitySafe), penWidth, Qt::SolidLine, Qt::FlatCap));
    p.drawArc(rect, 60 * 16, -60 * 16);

    // ── Score-fill arc (in score color, drawn on top) ──────────────
    const double t = m_score / 100.0;
    const int sweep = static_cast<int>(180 * 16 * t);
    QPen scorePen{QColor(scoreColor(m_score))};
    scorePen.setWidth(penWidth + 2);
    scorePen.setCapStyle(Qt::RoundCap);
    p.setPen(scorePen);
    p.drawArc(rect, 180 * 16, -sweep);

    // ── Needle dot at the current score angle ───────────────────────
    const double angleDeg = 180.0 - 180.0 * t;
    const double angleRad = angleDeg * M_PI / 180.0;
    const QPointF center = rect.center();
    const double radius = rect.width() / 2.0 - penWidth / 2.0;
    const QPointF dot(
        center.x() + std::cos(angleRad) * radius, center.y() - std::sin(angleRad) * radius);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(Theme::Color::textPrimary));
    p.drawEllipse(dot, penWidth * 0.55, penWidth * 0.55);

    // ── Score number + "/100" inside the gauge bowl ─────────────────
    // The semicircle's "bowl" is the upper portion — text goes there,
    // vertically centered at ~70% of the rect height.
    const QRectF textRect(
        rect.left(), rect.top() + rect.height() * 0.30, rect.width(), rect.height() * 0.42);

    QFont scoreFont = p.font();
    scoreFont.setPixelSize(static_cast<int>(rect.height() * 0.30));
    scoreFont.setWeight(QFont::Black);
    p.setFont(scoreFont);
    p.setPen(QColor(Theme::Color::textPrimary));
    p.drawText(textRect, Qt::AlignHCenter | Qt::AlignTop, QString::number(m_score));

    QFont scaleFont = p.font();
    scaleFont.setPixelSize(static_cast<int>(rect.height() * 0.09));
    scaleFont.setWeight(QFont::Medium);
    p.setFont(scaleFont);
    p.setPen(QColor(Theme::Color::textSecondary));
    const QRectF scaleRect(
        rect.left(), rect.top() + rect.height() * 0.62, rect.width(), rect.height() * 0.12);
    p.drawText(scaleRect, Qt::AlignHCenter | Qt::AlignTop, "/ 100");
  }

 private:
  static QColor scoreColor(int score) {
    // Three-tier ramp aligned with the SecurityScoreCard label colors:
    //   ≥ 80 → green   (Safe)
    //   50–79 → yellow (Moderate)
    //   < 50  → red    (Critical)
    if (score >= 80)
      return QColor(Theme::Color::severitySafe);
    if (score >= 50)
      return QColor(Theme::Color::severityMedium);
    return QColor(Theme::Color::severityCritical);
  }

  int m_score = 0;
};

// ---------------------------------------------------------------------------
// SecurityScoreCard
// ---------------------------------------------------------------------------
SecurityScoreCard::SecurityScoreCard(QWidget* parent)
    : QFrame(parent) {
  setObjectName("OdySecurityScore");
  setAttribute(Qt::WA_StyledBackground, true);
  setStyleSheet(QString("QFrame#OdySecurityScore {"
                        "  background-color: %1;"
                        "  border: 1px solid %2;"
                        "  border-radius: %3px;"
                        "}")
                    .arg(Theme::Color::bgCard, Theme::Color::borderSubtle)
                    .arg(Theme::Size::cardRadius));

  auto* v = new QVBoxLayout(this);
  v->setContentsMargins(20, 16, 20, 16);
  v->setSpacing(8);

  // The score is computed from active EDR-Lite alerts only (see
  // SecurityScoreEngine::scoreActiveAlerts). It does NOT factor in
  // file-scan findings. Naming it "System Security Score" was
  // misleading — it could read 100 / Secure while the dashboard's
  // STATUS card simultaneously said "At Risk" because of recent scan
  // findings. The renamed title makes the runtime-vs-scan distinction
  // explicit, and the italic subtitle below repeats it for users who
  // skim past the title.
  auto* title = new QLabel("Real-Time Protection Score (EDR-Lite)", this);
  title->setStyleSheet(
      QString("color: %1; font-size: 16px; font-weight: 700;").arg(Theme::Color::textPrimary));
  v->addWidget(title);

  auto* scope = new QLabel(
      "Reflects live system monitoring only — does not include file scan results.",
      this);
  scope->setWordWrap(true);
  scope->setStyleSheet(
      QString("color: %1; font-size: 11px; font-style: italic;")
          .arg(Theme::Color::textSecondary));
  v->addWidget(scope);

  // ── Gauge (the score number is now drawn inside the arc) ───────────
  m_gauge = new ScoreGauge(this);
  v->addWidget(m_gauge, 0, Qt::AlignHCenter);

  // m_scoreText kept for API compatibility — hidden because the gauge
  // already shows the number. Removing the field would mean touching
  // every refresh path that references it.
  m_scoreText = new QLabel("", this);
  m_scoreText->setVisible(false);

  m_label = new QLabel("—", this);
  m_label->setAlignment(Qt::AlignHCenter);
  m_label->setStyleSheet(
      QString("color: %1; font-size: 14px; font-weight: 600;").arg(Theme::Color::severitySafe));
  v->addWidget(m_label);

  m_subtitle = new QLabel("", this);
  m_subtitle->setAlignment(Qt::AlignHCenter);
  m_subtitle->setWordWrap(true);
  m_subtitle->setStyleSheet(
      QString("color: %1; font-size: 11px;").arg(Theme::Color::textSecondary));
  v->addWidget(m_subtitle);

  // ── Why-this-score breakdown ────────────────────────────────────────
  auto* breakdownTitle = new QLabel("Why this score", this);
  breakdownTitle->setStyleSheet(QString("color: %1; font-size: 11px; font-weight: 600;"
                                        " text-transform: uppercase; letter-spacing: 0.5px;"
                                        " padding-top: 4px;")
                                    .arg(Theme::Color::textSecondary));
  v->addWidget(breakdownTitle);

  m_breakdownBox = new QVBoxLayout();
  m_breakdownBox->setContentsMargins(0, 0, 0, 0);
  m_breakdownBox->setSpacing(2);
  v->addLayout(m_breakdownBox);

  m_breakdownEmpty = new QLabel("No active findings.", this);
  m_breakdownEmpty->setStyleSheet(
      QString("color: %1; font-size: 12px; font-style: italic;").arg(Theme::Color::textMuted));
  m_breakdownBox->addWidget(m_breakdownEmpty);

  // ── 7-day trend chart ───────────────────────────────────────────────
  m_chart = new QChart();
  m_chart->setBackgroundBrush(Qt::transparent);
  m_chart->setBackgroundPen(Qt::NoPen);
  m_chart->setMargins({0, 0, 0, 0});
  m_chart->legend()->hide();
  m_chart->setBackgroundRoundness(0);

  m_series = new QLineSeries(m_chart);
  // Brace initialization — avoids the "most vexing parse" where
  //   QPen pen(QColor(...));
  // would be interpreted as a function declaration named `pen`.
  QPen pen{QColor(Theme::Color::severitySafe)};
  pen.setWidthF(2.5);
  m_series->setPen(pen);
  m_chart->addSeries(m_series);

  auto* axisX = new QValueAxis();
  auto* axisY = new QValueAxis();
  axisX->setRange(0, 6);
  axisY->setRange(0, 100);
  axisX->setVisible(false);
  axisY->setVisible(false);
  m_chart->addAxis(axisX, Qt::AlignBottom);
  m_chart->addAxis(axisY, Qt::AlignLeft);
  m_series->attachAxis(axisX);
  m_series->attachAxis(axisY);

  m_chartView = new QChartView(m_chart, this);
  m_chartView->setRenderHint(QPainter::Antialiasing, true);
  m_chartView->setStyleSheet("background: transparent;");
  m_chartView->setFrameShape(QFrame::NoFrame);
  m_chartView->setFixedHeight(60);
  v->addWidget(m_chartView);

  // ── ISSUE 1 FIX ── default to 100 (Secure) instead of 0 (Critical).
  // Before: if EDR-Lite was disabled or hadn't ticked yet, the gauge
  // showed 0 / Critical even though there were no active alerts. Now
  // the resting state matches "no findings → Secure", and any later
  // setReport() / setScore() call updates it from there.
  setScore(100);
}

void SecurityScoreCard::setScore(int score) {
  score = qBound(0, score, 100);
  if (m_gauge)
    m_gauge->setScore(score);
  m_scoreText->setText(QString::number(score));

  // Stabilization C — three-tier color scale per the spec:
  //   ≥ 80 → Green (Safe)
  //   50–79 → Yellow (Moderate)
  //   < 50 → Red (Critical)
  QString label, color, subtitle;
  if (score >= 90) {
    label = "Excellent";
    color = Theme::Color::severitySafe;
    subtitle = "Your system is well protected.\nKeep up the good work!";
  } else if (score >= 80) {
    label = "Good";
    color = Theme::Color::severitySafe;
    subtitle = "System is secure — a few items worth reviewing.";
  } else if (score >= 50) {
    label = "Moderate";
    color = Theme::Color::severityMedium;
    subtitle = "Some findings need attention.";
  } else {
    label = "Critical";
    color = Theme::Color::severityCritical;
    subtitle = "Immediate action recommended.";
  }
  m_label->setText(label);
  m_label->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: 600;").arg(color));
  m_subtitle->setText(subtitle);
}

void SecurityScoreCard::setTrend(const QVector<int>& trend) {
  rebuildTrend(trend);
}

void SecurityScoreCard::rebuildTrend(const QVector<int>& trend) {
  m_series->clear();
  QVector<int> t = trend;
  while (t.size() < 7)
    t.append(t.isEmpty() ? 0 : t.last());
  if (t.size() > 7)
    t = t.mid(t.size() - 7);
  for (int i = 0; i < t.size(); ++i)
    m_series->append(i, t[i]);
}

// ============================================================================
//  Risk-based report path (Score.B)
// ============================================================================
void SecurityScoreCard::setReport(const EDR::ScoreReport& report) {
  // Apply the score number + gauge color via the existing path.
  setScore(report.score);

  // Override the label using the engine's three-tier classification
  // (Secure / Moderate / High Risk) — matches the spec exactly.
  const QString labelText = EDR::scoreLabelToText(report.label);
  const QString labelHex = EDR::scoreLabelHex(report.label);
  m_label->setText(labelText);
  m_label->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: 600;").arg(labelHex));

  // Subtitle summary — short and informative
  QString sub;
  if (report.activeAlerts == 0) {
    sub = "No active EDR-Lite findings.";
  } else {
    sub = QString(
              "%1 active alert%2 — %3 critical, %4 high, "
              "%5 medium, %6 low.")
              .arg(report.activeAlerts)
              .arg(report.activeAlerts == 1 ? "" : "s")
              .arg(report.criticalCount)
              .arg(report.highCount)
              .arg(report.mediumCount)
              .arg(report.lowCount);
  }
  m_subtitle->setText(sub);

  rebuildBreakdown(report.breakdown);
}

void SecurityScoreCard::rebuildBreakdown(const QVector<EDR::ScoreLine>& lines) {
  if (!m_breakdownBox)
    return;

  // Tear down previously-rendered breakdown labels (keep
  // m_breakdownEmpty for reuse).
  for (int i = m_breakdownBox->count() - 1; i >= 0; --i) {
    QLayoutItem* it = m_breakdownBox->itemAt(i);
    if (!it)
      continue;
    QWidget* w = it->widget();
    if (w && w != m_breakdownEmpty) {
      m_breakdownBox->removeWidget(w);
      w->deleteLater();
    }
  }

  if (lines.isEmpty() || (lines.size() == 1 && lines.first().delta == 0)) {
    m_breakdownEmpty->setText(
        lines.isEmpty() ? QStringLiteral("No active findings.") : lines.first().reason);
    m_breakdownEmpty->setVisible(true);
    return;
  }

  m_breakdownEmpty->setVisible(false);

  for (const EDR::ScoreLine& line : lines) {
    auto* row = new QLabel(this);
    row->setWordWrap(true);
    const QString prefix = (line.delta < 0) ? QString::number(line.delta) : QString("±0");
    row->setText(QString("%1 · %2").arg(prefix, line.reason));
    // Negative deltas in red-orange; informational lines in muted.
    const QString color = (line.delta < 0) ? QString(Theme::Color::severityCritical)
                                           : QString(Theme::Color::textSecondary);
    row->setStyleSheet(QString("color: %1; font-size: 12px; font-family: monospace;").arg(color));
    m_breakdownBox->addWidget(row);
  }
}

#include "SecurityScoreCard.moc"
