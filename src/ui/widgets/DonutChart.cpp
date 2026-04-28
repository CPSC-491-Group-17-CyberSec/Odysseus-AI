// ============================================================================
// DonutChart.cpp
//
// Centering strategy: place the QChartView and a center-label widget at the
// SAME cell of a QGridLayout. The center label widget has WA_TransparentForMouseEvents
// and a transparent background so it overlays the donut hole cleanly without
// needing manual geometry math.
// ============================================================================

#include "DonutChart.h"
#include "../theme/DashboardTheme.h"

#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QLabel>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QPainter>

DonutChart::DonutChart(QWidget* parent)
    : QWidget(parent)
{
    setAttribute(Qt::WA_TranslucentBackground);

    auto* grid = new QGridLayout(this);
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setSpacing(0);

    // ── Chart ──────────────────────────────────────────────────────────
    m_chart = new QChart();
    m_chart->setBackgroundRoundness(0);
    m_chart->setBackgroundBrush(Qt::transparent);
    m_chart->setBackgroundPen(Qt::NoPen);
    m_chart->setMargins({0, 0, 0, 0});
    m_chart->legend()->hide();

    m_series = new QPieSeries(m_chart);
    m_series->setHoleSize(0.65);    // makes it a donut
    m_series->setPieSize(0.92);
    m_chart->addSeries(m_series);

    m_view = new QChartView(m_chart, this);
    m_view->setRenderHint(QPainter::Antialiasing, true);
    m_view->setBackgroundBrush(Qt::transparent);
    m_view->setStyleSheet("background: transparent;");
    m_view->setFrameShape(QFrame::NoFrame);
    grid->addWidget(m_view, 0, 0);

    // ── Center labels (overlaid in same grid cell, centered) ───────────
    auto* center = new QWidget(this);
    center->setAttribute(Qt::WA_TransparentForMouseEvents);
    center->setStyleSheet("background: transparent;");
    auto* cv = new QVBoxLayout(center);
    cv->setContentsMargins(0, 0, 0, 0);
    cv->setSpacing(0);
    cv->setAlignment(Qt::AlignCenter);

    m_centerVal = new QLabel("0", center);
    m_centerVal->setAlignment(Qt::AlignCenter);
    m_centerVal->setStyleSheet(QString(
        "color: %1; font-size: 32px; font-weight: 700; background: transparent;")
            .arg(Theme::Color::textPrimary));
    cv->addWidget(m_centerVal);

    m_centerLab = new QLabel("Total Threats", center);
    m_centerLab->setAlignment(Qt::AlignCenter);
    m_centerLab->setStyleSheet(QString(
        "color: %1; font-size: 11px; background: transparent;")
            .arg(Theme::Color::textSecondary));
    cv->addWidget(m_centerLab);

    grid->addWidget(center, 0, 0, Qt::AlignCenter);

    rebuild();
}

void DonutChart::setSlices(const QVector<Slice>& slices)
{
    m_slices = slices;
    rebuild();
}

void DonutChart::setCenterValue(const QString& v) { m_centerVal->setText(v); }
void DonutChart::setCenterLabel(const QString& l) { m_centerLab->setText(l); }

void DonutChart::rebuild()
{
    m_series->clear();
    int total = 0;
    for (const auto& s : m_slices) total += s.value;

    if (total <= 0) {
        auto* slice = m_series->append("No data", 1);
        slice->setBrush(QColor(Theme::Color::borderSubtle));
        slice->setBorderColor(QColor(Theme::Color::bgCard));
        slice->setBorderWidth(2);
        return;
    }

    for (const auto& s : m_slices) {
        if (s.value <= 0) continue;
        auto* slice = m_series->append(s.label, s.value);
        slice->setBrush(s.color);
        slice->setBorderColor(QColor(Theme::Color::bgCard));
        slice->setBorderWidth(2);
        slice->setLabelVisible(false);
    }
}
