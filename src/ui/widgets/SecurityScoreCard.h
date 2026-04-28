#pragma once
// ============================================================================
// SecurityScoreCard.h  –  semicircle gauge + 7-day score trend
//
// Two visual elements stacked:
//   1. ScoreGauge: custom QPainter widget. 180° arc with red→yellow→green
//      gradient, center text shows current score + label ("Excellent" /
//      "Good" / "At Risk").
//   2. QLineSeries trend: QtCharts line chart over the past 7 days.
// ============================================================================

#include <QFrame>
#include <QString>
#include <QVector>

class QChart;
class QChartView;
class QLineSeries;
class QLabel;
class ScoreGauge;

class SecurityScoreCard : public QFrame
{
    Q_OBJECT
public:
    explicit SecurityScoreCard(QWidget* parent = nullptr);

    /// Set the current score (0–100) and the optional last-7-days history.
    /// `trend` should have exactly 7 entries (oldest → newest); shorter
    /// vectors render with a flat-line tail.
    void setScore(int score);
    void setTrend(const QVector<int>& trend);

private:
    ScoreGauge*   m_gauge      = nullptr;
    QLabel*       m_scoreText  = nullptr;
    QLabel*       m_label      = nullptr;
    QLabel*       m_subtitle   = nullptr;
    QChart*       m_chart      = nullptr;
    QChartView*   m_chartView  = nullptr;
    QLineSeries*  m_series     = nullptr;

    void rebuildTrend(const QVector<int>& trend);
};
