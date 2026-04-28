#pragma once
// ============================================================================
// DonutChart.h  –  thin QtCharts wrapper for the Threat Overview card.
//
// Renders a hollow pie chart with center text ("5 / Total Threats" in the
// mockup). Slice colors come from DashboardTheme severity palette.
//
// Public API:
//   setSlices({ {"Critical", 1, color}, {"Suspicious", 3, color}, ... })
//   setCenterValue("5"), setCenterLabel("Total Threats")
//
// Use a QChartView with antialiasing on for smooth edges. The legend is
// rendered separately by the page (so we can match the mockup's right-side
// label layout); chart's built-in legend is hidden.
// ============================================================================

#include <QWidget>
#include <QString>
#include <QColor>
#include <QVector>

QT_BEGIN_NAMESPACE
namespace QtCharts { /* Qt6 puts QChart in global namespace */ }
QT_END_NAMESPACE

class QChartView;
class QChart;
class QPieSeries;
class QLabel;

class DonutChart : public QWidget
{
    Q_OBJECT
public:
    struct Slice {
        QString label;
        int     value = 0;
        QColor  color;
    };

    explicit DonutChart(QWidget* parent = nullptr);

    void setSlices(const QVector<Slice>& slices);
    void setCenterValue(const QString& v);
    void setCenterLabel(const QString& l);

private:
    void rebuild();

    QChartView*  m_view       = nullptr;
    QChart*      m_chart      = nullptr;
    QPieSeries*  m_series     = nullptr;
    QLabel*      m_centerVal  = nullptr;
    QLabel*      m_centerLab  = nullptr;
    QVector<Slice> m_slices;
};
