// ============================================================================
// FilterBar.cpp
// ============================================================================

#include "FilterBar.h"
#include "../theme/DashboardTheme.h"

#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QHBoxLayout>

namespace {

QString chipQss(bool active)
{
    if (active) {
        return QString(
            "QPushButton { background-color: %1; color: white; border: none;"
            " border-radius: 14px; padding: 6px 14px; %2 }"
        ).arg(Theme::Color::accentBlue)
         .arg(Theme::Type::qss(Theme::Type::Caption,
                                 Theme::Type::WeightSemi));
    }
    return QString(
        "QPushButton { background-color: %1; color: %2; border: 1px solid %3;"
        " border-radius: 14px; padding: 5px 14px; %4 }"
        "QPushButton:hover { background-color: %5; color: white; }"
    ).arg(Theme::Color::bgCard, Theme::Color::textSecondary,
          Theme::Color::borderSubtle)
     .arg(Theme::Type::qss(Theme::Type::Caption,
                              Theme::Type::WeightSemi))
     .arg(Theme::Color::bgCardHover);
}

}  // anonymous

// ============================================================================
//  Construction
// ============================================================================
FilterBar::FilterBar(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("background: transparent;");

    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(8);

    // ── Chip group ─────────────────────────────────────────────────────
    // severityValue: -1 = All, otherwise int(EDR::Severity) + 1
    m_chips.append(makeChip("All",        -1));
    m_chips.append(makeChip("Critical",   static_cast<int>(EDR::Severity::Critical)));
    m_chips.append(makeChip("High",       static_cast<int>(EDR::Severity::High)));
    m_chips.append(makeChip("Medium",     static_cast<int>(EDR::Severity::Medium)));
    m_chips.append(makeChip("Low / Info", static_cast<int>(EDR::Severity::Low)));
    for (QPushButton* chip : m_chips) h->addWidget(chip);

    // First chip is active.
    m_chips.first()->setStyleSheet(chipQss(true));

    h->addSpacing(8);
    h->addStretch(1);

    // ── Category dropdown ─────────────────────────────────────────────
    m_categoryCombo = new QComboBox(this);
    m_categoryCombo->setMinimumWidth(160);
    m_categoryCombo->setStyleSheet(QString(
        "QComboBox {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 8px;"
        "  padding: 6px 12px; %4"
        "}"
        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox QAbstractItemView {"
        "  background-color: %1; color: %2;"
        "  selection-background-color: %5; border: 1px solid %3;"
        "}"
    ).arg(Theme::Color::bgCard, Theme::Color::textPrimary,
          Theme::Color::borderSubtle)
     .arg(Theme::Type::qss(Theme::Type::Caption))
     .arg(Theme::Color::accentBlueSoft));
    m_categoryCombo->addItem("All Categories", QString(""));
    m_categoryCombo->addItem("Process",        QString(EDR::Category::Process));
    m_categoryCombo->addItem("Persistence",    QString(EDR::Category::Persistence));
    m_categoryCombo->addItem("Cross-View",     QString(EDR::Category::CrossView));
    m_categoryCombo->addItem("Integrity",      QString(EDR::Category::Integrity));
    m_categoryCombo->addItem("Kernel Ext.",    QString(EDR::Category::KernelExt));
    connect(m_categoryCombo, &QComboBox::currentIndexChanged,
            this, &FilterBar::filtersChanged);
    h->addWidget(m_categoryCombo);

    // ── Search input ───────────────────────────────────────────────────
    m_search = new QLineEdit(this);
    m_search->setPlaceholderText("Search by file or process…");
    m_search->setMinimumWidth(220);
    m_search->setStyleSheet(QString(
        "QLineEdit {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 8px;"
        "  padding: 6px 12px; %4"
        "}"
        "QLineEdit:focus { border-color: %5; }"
    ).arg(Theme::Color::bgCard, Theme::Color::textPrimary,
          Theme::Color::borderSubtle)
     .arg(Theme::Type::qss(Theme::Type::Caption))
     .arg(Theme::Color::accentBlue));
    connect(m_search, &QLineEdit::textChanged,
            this, &FilterBar::filtersChanged);
    h->addWidget(m_search);
}

QPushButton* FilterBar::makeChip(const QString& label, int severityValue)
{
    auto* b = new QPushButton(label, this);
    b->setCursor(Qt::PointingHandCursor);
    b->setProperty("__severityValue", severityValue);
    b->setStyleSheet(chipQss(false));
    connect(b, &QPushButton::clicked,
            this, &FilterBar::onChipClicked);
    return b;
}

void FilterBar::onChipClicked()
{
    auto* clicked = qobject_cast<QPushButton*>(sender());
    if (!clicked) return;

    for (int i = 0; i < m_chips.size(); ++i) {
        const bool active = (m_chips[i] == clicked);
        m_chips[i]->setStyleSheet(chipQss(active));
        if (active) m_activeChip = i;
    }
    emit filtersChanged();
}

int FilterBar::selectedSeverity() const
{
    if (m_activeChip < 0 || m_activeChip >= m_chips.size()) return -1;
    return m_chips[m_activeChip]->property("__severityValue").toInt();
}

QString FilterBar::selectedCategory() const
{
    return m_categoryCombo ? m_categoryCombo->currentData().toString()
                              : QString();
}

QString FilterBar::searchText() const
{
    return m_search ? m_search->text().trimmed() : QString();
}
