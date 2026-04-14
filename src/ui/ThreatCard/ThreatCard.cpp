#include "ThreatCard.h"

#include <QLabel>
#include <QProgressBar>
#include <QPlainTextEdit>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QFont>

ThreatCard::ThreatCard(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Threat Details");
    resize(520, 480);
    setStyleSheet(
        "QDialog { background-color: #1A1A2E; }"
        "QLabel { color: #E0E0E0; }"
        "QPlainTextEdit { background-color: #16213E; color: #D4D4D4;"
        "  border: 1px solid #2A2A4A; border-radius: 6px;"
        "  padding: 8px; font-family: 'SF Mono', Menlo, monospace; font-size: 12px; }"
    );

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 16, 20, 20);
    mainLayout->setSpacing(12);

    // ── Title + Severity Badge ──────────────────────────────────────────
    auto* headerLayout = new QHBoxLayout();

    titleLabel = new QLabel("Threat Detected", this);
    titleLabel->setStyleSheet(
        "font-size: 18px; font-weight: bold; color: #FFFFFF;"
    );

    severityLabel = new QLabel("UNKNOWN", this);
    severityLabel->setStyleSheet(
        "font-size: 12px; font-weight: bold; color: #FFFFFF;"
        " background-color: #555; border-radius: 10px;"
        " padding: 3px 12px;"
    );
    severityLabel->setAlignment(Qt::AlignCenter);

    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(severityLabel);
    mainLayout->addLayout(headerLayout);

    // ── File Name ───────────────────────────────────────────────────────
    fileNameLabel = new QLabel("", this);
    fileNameLabel->setStyleSheet(
        "font-size: 13px; color: #8888AA; padding-bottom: 4px;"
    );
    mainLayout->addWidget(fileNameLabel);

    // ── Score Bar ───────────────────────────────────────────────────────
    auto* scoreLayout = new QHBoxLayout();
    auto* scoreLabel = new QLabel("Anomaly Score:", this);
    scoreLabel->setStyleSheet("font-size: 12px; color: #8888AA;");

    scoreBar = new QProgressBar(this);
    scoreBar->setRange(0, 1000);
    scoreBar->setTextVisible(false);
    scoreBar->setFixedHeight(14);
    scoreBar->setStyleSheet(
        "QProgressBar { background-color: #2A2A4A; border-radius: 7px; }"
        "QProgressBar::chunk { background-color: #FF6B6B; border-radius: 7px; }"
    );

    scoreTextLabel = new QLabel("0.000 / 1.000", this);
    scoreTextLabel->setStyleSheet("font-size: 12px; color: #CCCCCC; font-family: monospace;");

    scoreLayout->addWidget(scoreLabel);
    scoreLayout->addWidget(scoreBar, 1);
    scoreLayout->addWidget(scoreTextLabel);
    mainLayout->addLayout(scoreLayout);

    // ── Separator ───────────────────────────────────────────────────────
    auto* sep = new QFrame(this);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color: #2A2A4A;");
    mainLayout->addWidget(sep);

    // ── Sections via QFormLayout ────────────────────────────────────────
    auto* formLayout = new QFormLayout();
    formLayout->setLabelAlignment(Qt::AlignTop | Qt::AlignLeft);
    formLayout->setSpacing(10);

    // Key Indicators
    auto* indLabel = new QLabel("Key Indicators:", this);
    indLabel->setStyleSheet("font-size: 12px; font-weight: bold; color: #FF9F43;");
    indicatorsBox = new QPlainTextEdit(this);
    indicatorsBox->setReadOnly(true);
    indicatorsBox->setMaximumHeight(90);
    formLayout->addRow(indLabel, indicatorsBox);

    // AI Summary
    auto* sumLabel = new QLabel("AI Summary:", this);
    sumLabel->setStyleSheet("font-size: 12px; font-weight: bold; color: #54A0FF;");
    summaryBox = new QPlainTextEdit(this);
    summaryBox->setReadOnly(true);
    summaryBox->setMaximumHeight(80);
    formLayout->addRow(sumLabel, summaryBox);

    // Recommended Actions
    auto* actLabel = new QLabel("Actions:", this);
    actLabel->setStyleSheet("font-size: 12px; font-weight: bold; color: #2ED573;");
    remediationBox = new QPlainTextEdit(this);
    remediationBox->setReadOnly(true);
    remediationBox->setMaximumHeight(90);
    formLayout->addRow(actLabel, remediationBox);

    mainLayout->addLayout(formLayout);
    mainLayout->addStretch();

    // Legacy compat: severityBar points to scoreBar
    severityBar = scoreBar;

    setLayout(mainLayout);
}

// ── Legacy setters ──────────────────────────────────────────────────────

void ThreatCard::setSummary(const QString& summary)
{
    summaryBox->setPlainText(summary);
}

void ThreatCard::setSeverity(int severity)
{
    scoreBar->setValue(severity * 10);  // legacy used 0-100, new uses 0-1000
}

void ThreatCard::setRemediation(const QString& remediation)
{
    remediationBox->setPlainText(remediation);
}

// ── New structured setters ──────────────────────────────────────────────

void ThreatCard::setSeverityLevel(const QString& level)
{
    severityLabel->setText(level.toUpper());
    updateSeverityStyle(level);
}

void ThreatCard::setAnomalyScore(float score, float threshold)
{
    int barValue = static_cast<int>(score * 1000);
    scoreBar->setValue(barValue);
    scoreTextLabel->setText(
        QString("%1 / 1.000  (threshold: %2)")
            .arg(score, 0, 'f', 3)
            .arg(threshold, 0, 'f', 3)
    );

    // Color the bar based on severity
    QString color;
    if (score >= 0.90f)      color = "#FF4757";  // Critical red
    else if (score >= 0.75f) color = "#FF6348";  // High orange-red
    else if (score >= 0.60f) color = "#FFA502";  // Medium orange
    else                     color = "#FECA57";  // Low yellow

    scoreBar->setStyleSheet(
        QString("QProgressBar { background-color: #2A2A4A; border-radius: 7px; }"
                "QProgressBar::chunk { background-color: %1; border-radius: 7px; }")
            .arg(color)
    );
}

void ThreatCard::setFileName(const QString& name)
{
    fileNameLabel->setText(name);
}

void ThreatCard::setKeyIndicators(const QStringList& indicators)
{
    QString text;
    for (const QString& ind : indicators) {
        text += QString::fromUtf8("\u2022 ") + ind + "\n";
    }
    indicatorsBox->setPlainText(text.trimmed());
}

void ThreatCard::setRecommendedActions(const QStringList& actions)
{
    QString text;
    for (int i = 0; i < actions.size(); ++i) {
        text += QString("%1. %2\n").arg(i + 1).arg(actions[i]);
    }
    remediationBox->setPlainText(text.trimmed());
}

void ThreatCard::updateSeverityStyle(const QString& level)
{
    QString bg;
    QString upper = level.toUpper();
    if (upper == "CRITICAL")     bg = "#FF4757";
    else if (upper == "HIGH")    bg = "#FF6348";
    else if (upper == "MEDIUM")  bg = "#FFA502";
    else if (upper == "LOW")     bg = "#FECA57";
    else                         bg = "#555555";

    severityLabel->setStyleSheet(
        QString("font-size: 12px; font-weight: bold; color: #FFFFFF;"
                " background-color: %1; border-radius: 10px;"
                " padding: 3px 12px;").arg(bg)
    );
}
