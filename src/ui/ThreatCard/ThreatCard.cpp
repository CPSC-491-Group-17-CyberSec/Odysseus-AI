#include "ThreatCard.h"

#include <QLabel>
#include <QProgressBar>
#include <QPlainTextEdit>
#include <QFormLayout>
#include <QVBoxLayout>

ThreatCard::ThreatCard(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Threat Details");
    resize(450, 350);

    titleLabel = new QLabel("Malicious File Detected", this);

    severityBar = new QProgressBar(this);
    severityBar->setRange(0, 100);

    summaryBox = new QPlainTextEdit(this);
    summaryBox->setReadOnly(true);

    remediationBox = new QPlainTextEdit(this);
    remediationBox->setReadOnly(true);

    auto *formLayout = new QFormLayout;
    formLayout->addRow("Severity:", severityBar);
    formLayout->addRow("AI Summary:", summaryBox);
    formLayout->addRow("Remediation:", remediationBox);

    auto *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(titleLabel);
    mainLayout->addLayout(formLayout);

    setLayout(mainLayout);
}

void ThreatCard::setSummary(const QString& summary)
{
    summaryBox->setPlainText(summary);
}

void ThreatCard::setSeverity(int severity)
{
    severityBar->setValue(severity);
}

void ThreatCard::setRemediation(const QString& remediation)
{
    remediationBox->setPlainText(remediation);
}
