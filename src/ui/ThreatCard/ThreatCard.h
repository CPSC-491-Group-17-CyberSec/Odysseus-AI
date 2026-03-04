#pragma once

#include <QDialog>

class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QFormLayout;

class ThreatCard : public QDialog
{
    Q_OBJECT

public:
    explicit ThreatCard(QWidget *parent = nullptr);

    void setSummary(const QString& summary);
    void setSeverity(int severity);
    void setRemediation(const QString& remediation);

private:
    QLabel* titleLabel;
    QProgressBar* severityBar;
    QPlainTextEdit* summaryBox;
    QPlainTextEdit* remediationBox;
};
