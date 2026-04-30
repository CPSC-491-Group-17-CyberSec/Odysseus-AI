// ============================================================================
// QuarantinePage.cpp
// ============================================================================

#include "QuarantinePage.h"

#include "../theme/DashboardTheme.h"

// Phase 5 backend
#include <QDateTime>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

#include "response/Quarantine.h"
#include "response/ResponseManager.h"
#include "response/ResponseManagerSingleton.h"
#include "response/ResponseTypes.h"

namespace {

QString relTimeFromEpoch(std::int64_t epochSeconds) {
  if (epochSeconds <= 0)
    return QStringLiteral("—");
  const QDateTime when = QDateTime::fromSecsSinceEpoch(epochSeconds);
  if (!when.isValid())
    return QStringLiteral("—");
  const qint64 secs = when.secsTo(QDateTime::currentDateTime());
  if (secs < 60)
    return QString("%1s ago").arg(secs);
  else if (secs < 60 * 60)
    return QString("%1m ago").arg(secs / 60);
  else if (secs < 60 * 60 * 24)
    return QString("%1h ago").arg(secs / 3600);
  return when.toString("MMM d, hh:mm");
}

}  // namespace

// ============================================================================
//  Construction
// ============================================================================
QuarantinePage::QuarantinePage(QWidget* parent)
    : QWidget(parent) {
  setStyleSheet(QString("background-color: %1;").arg(Theme::Color::bgPrimary));
  buildUi();
  refresh();
}

void QuarantinePage::buildUi() {
  auto* outer = new QVBoxLayout(this);
  outer->setContentsMargins(0, 0, 0, 0);
  outer->setSpacing(0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setStyleSheet("background: transparent;");
  outer->addWidget(scroll);

  auto* content = new QWidget();
  content->setStyleSheet("background: transparent;");
  auto* main = new QVBoxLayout(content);
  main->setContentsMargins(32, 28, 32, 28);
  main->setSpacing(16);

  // ── Header ──────────────────────────────────────────────────────────
  auto* title = new QLabel("Quarantine", content);
  title->setStyleSheet(QString("color: %1; %2 background: transparent;")
                           .arg(Theme::Color::textPrimary)
                           .arg(Theme::Type::qss(Theme::Type::Display, Theme::Type::WeightBold)));
  main->addWidget(title);

  auto* sub = new QLabel(
      "Files moved to quarantine are read-only and never deleted. "
      "Use Restore to put a file back at its original path.",
      content);
  sub->setStyleSheet(QString("color: %1; %2 background: transparent;")
                         .arg(Theme::Color::textSecondary)
                         .arg(Theme::Type::qss(Theme::Type::Body)));
  sub->setWordWrap(true);
  main->addWidget(sub);

  // ── Action row (Refresh on left) ────────────────────────────────────
  auto* actionRow = new QHBoxLayout();
  actionRow->setSpacing(10);
  m_refreshBtn = new QPushButton("Refresh", content);
  m_refreshBtn->setCursor(Qt::PointingHandCursor);
  m_refreshBtn->setStyleSheet(QString("QPushButton { background: transparent; color: %1;"
                                      " border: 1px solid %2; border-radius: 8px;"
                                      " padding: 8px 14px; %3 }"
                                      "QPushButton:hover { background-color: %4; color: white; }")
                                  .arg(Theme::Color::textPrimary, Theme::Color::borderSubtle)
                                  .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
                                  .arg(Theme::Color::accentBlueSoft));
  connect(m_refreshBtn, &QPushButton::clicked, this, &QuarantinePage::onRefreshClicked);
  actionRow->addWidget(m_refreshBtn);
  actionRow->addStretch(1);
  main->addLayout(actionRow);

  // ── Two-column body: list (left), detail + restore (right) ──────────
  auto* body = new QHBoxLayout();
  body->setSpacing(16);

  // Left — list of quarantined entries.
  auto* leftCol = new QFrame(content);
  leftCol->setStyleSheet(QString("QFrame { background-color: %1; border: 1px solid %2;"
                                 " border-radius: 12px; }")
                             .arg(Theme::Color::bgCard, Theme::Color::borderSubtle));
  auto* leftV = new QVBoxLayout(leftCol);
  leftV->setContentsMargins(16, 14, 16, 14);
  leftV->setSpacing(8);

  auto* leftTitle = new QLabel("Quarantined files", leftCol);
  leftTitle->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent; }")
                               .arg(Theme::Color::textSecondary)
                               .arg(Theme::Type::qss(Theme::Type::H3, Theme::Type::WeightBold)));
  leftV->addWidget(leftTitle);

  m_list = new QListWidget(leftCol);
  m_list->setStyleSheet(
      QString("QListWidget { background-color: %1; color: %2;"
              " border: 1px solid %3; border-radius: 8px; padding: 4px; }"
              "QListWidget::item { padding: 8px; border-radius: 4px; }"
              "QListWidget::item:selected { background-color: %4; color: white; }")
          .arg(
              Theme::Color::bgSecondary,
              Theme::Color::textPrimary,
              Theme::Color::borderSubtle,
              Theme::Color::accentBlue));
  m_list->setMinimumHeight(360);
  connect(m_list, &QListWidget::itemSelectionChanged, this, &QuarantinePage::onSelectionChanged);
  leftV->addWidget(m_list, 1);

  m_emptyHint = new QLabel(
      "No quarantined files.\n"
      "When you click Quarantine on a finding, it will appear here.",
      leftCol);
  m_emptyHint->setAlignment(Qt::AlignCenter);
  m_emptyHint->setStyleSheet(
      QString("QLabel { color: %1; %2 padding: 24px; background: transparent; }")
          .arg(Theme::Color::textMuted)
          .arg(Theme::Type::qss(Theme::Type::Body)));
  leftV->addWidget(m_emptyHint);

  body->addWidget(leftCol, 2);

  // Right — detail pane + Restore button.
  auto* rightCol = new QFrame(content);
  rightCol->setStyleSheet(leftCol->styleSheet());
  auto* rightV = new QVBoxLayout(rightCol);
  rightV->setContentsMargins(16, 14, 16, 14);
  rightV->setSpacing(8);

  auto* rightTitle = new QLabel("Details", rightCol);
  rightTitle->setStyleSheet(leftTitle->styleSheet());
  rightV->addWidget(rightTitle);

  m_detail = new QLabel(rightCol);
  m_detail->setText("Select a file on the left to view details.");
  m_detail->setWordWrap(true);
  m_detail->setTextFormat(Qt::RichText);
  m_detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
  m_detail->setAlignment(Qt::AlignTop | Qt::AlignLeft);
  m_detail->setStyleSheet(QString("QLabel { color: %1; %2 background: transparent;"
                                  " padding: 6px 0; }")
                              .arg(Theme::Color::textPrimary)
                              .arg(Theme::Type::qss(Theme::Type::Body)));
  rightV->addWidget(m_detail, 1);

  m_status = new QLabel(rightCol);
  m_status->setWordWrap(true);
  m_status->setVisible(false);
  rightV->addWidget(m_status);

  m_restoreBtn = new QPushButton("Restore", rightCol);
  m_restoreBtn->setCursor(Qt::PointingHandCursor);
  m_restoreBtn->setEnabled(false);
  m_restoreBtn->setToolTip("Move the file back to its original path");
  m_restoreBtn->setStyleSheet(
      QString("QPushButton { background-color: %1; color: white; border: none;"
              " border-radius: 8px; padding: 10px 18px; %2 }"
              "QPushButton:hover { background-color: %3; }"
              "QPushButton:disabled { background-color: %4; color: %5; }")
          .arg(Theme::Color::accentBlue)
          .arg(Theme::Type::qss(Theme::Type::Body, Theme::Type::WeightSemi))
          .arg(Theme::Color::accentBlueHover)
          .arg(Theme::Color::bgSecondary)
          .arg(Theme::Color::textMuted));
  connect(m_restoreBtn, &QPushButton::clicked, this, &QuarantinePage::onRestoreClicked);
  rightV->addWidget(m_restoreBtn);

  body->addWidget(rightCol, 1);

  main->addLayout(body, 1);
  scroll->setWidget(content);
}

// ============================================================================
//  refresh — pull current state from Quarantine::list()
// ============================================================================
void QuarantinePage::refresh() {
  if (!m_list)
    return;
  m_list->clear();
  setStatus({}, false);

  namespace R = odysseus::response;
  auto entries = R::globalResponseManager().quarantine().list();

  for (const R::QuarantineEntry& e : entries) {
    const QFileInfo origInfo(QString::fromStdString(e.originalPath));
    const QString name =
        origInfo.fileName().isEmpty() ? QStringLiteral("(unnamed)") : origInfo.fileName();
    const QString rel = relTimeFromEpoch(e.timestampEpoch);

    auto* item = new QListWidgetItem(QString("%1   ·   %2").arg(name, rel), m_list);
    // Stash the entry id so onRestoreClicked can find it again.
    item->setData(Qt::UserRole, QString::fromStdString(e.id));
  }

  const bool empty = entries.empty();
  if (m_emptyHint)
    m_emptyHint->setVisible(empty);
  if (empty) {
    m_detail->setText("Select a file on the left to view details.");
    m_restoreBtn->setEnabled(false);
  } else if (m_list->count() > 0) {
    m_list->setCurrentRow(0);  // populate detail with the first entry
  }
}

// ============================================================================
//  Slots
// ============================================================================
void QuarantinePage::onRefreshClicked() {
  refresh();
}

void QuarantinePage::onSelectionChanged() {
  setStatus({}, false);
  auto* item = m_list->currentItem();
  if (!item) {
    m_detail->setText("Select a file on the left to view details.");
    m_restoreBtn->setEnabled(false);
    return;
  }

  const QString id = item->data(Qt::UserRole).toString();

  namespace R = odysseus::response;
  auto opt = R::globalResponseManager().quarantine().findById(id.toStdString());
  if (!opt) {
    m_detail->setText("(metadata unavailable)");
    m_restoreBtn->setEnabled(false);
    return;
  }
  const auto& e = *opt;

  const QString origPath = QString::fromStdString(e.originalPath).toHtmlEscaped();
  const QString quarPath = QString::fromStdString(e.quarantinePath).toHtmlEscaped();
  const QString sha256 =
      e.sha256.empty() ? QStringLiteral("(not recorded)") : QString::fromStdString(e.sha256);
  const QString reason = e.reason.empty() ? QStringLiteral("(none)")
                                          : QString::fromStdString(e.reason).toHtmlEscaped();
  const QString when =
      (e.timestampEpoch > 0)
          ? QDateTime::fromSecsSinceEpoch(e.timestampEpoch).toString("yyyy-MM-dd hh:mm:ss")
          : QStringLiteral("(unknown)");

  const QString html =
      QString(
          "<table cellspacing='0' cellpadding='3'>"
          "<tr><td><b>File</b></td><td>%1</td></tr>"
          "<tr><td><b>Original path</b></td><td>%2</td></tr>"
          "<tr><td><b>Quarantine path</b></td><td>%3</td></tr>"
          "<tr><td><b>SHA-256</b></td><td><code>%4</code></td></tr>"
          "<tr><td><b>Quarantined</b></td><td>%5</td></tr>"
          "<tr><td><b>Reason</b></td><td>%6</td></tr>"
          "</table>")
          .arg(
              QFileInfo(QString::fromStdString(e.originalPath)).fileName().toHtmlEscaped(),
              origPath,
              quarPath,
              sha256,
              when,
              reason);
  m_detail->setText(html);
  m_restoreBtn->setEnabled(true);
}

void QuarantinePage::onRestoreClicked() {
  auto* item = m_list->currentItem();
  if (!item)
    return;

  const QString id = item->data(Qt::UserRole).toString();

  namespace R = odysseus::response;
  auto opt = R::globalResponseManager().quarantine().findById(id.toStdString());
  if (!opt) {
    setStatus("Quarantine entry vanished — refresh the list.", true);
    return;
  }

  // Confirmation. Restore is reversible enough (it just moves the file
  // back), but a confirmation here matches the safety bar set elsewhere.
  QMessageBox box(this);
  box.setIcon(QMessageBox::Question);
  box.setWindowTitle("Restore file");
  box.setText("Restore this file to its original path?");
  box.setInformativeText(
      QString("<b>%1</b><br><br>"
              "Original path:<br><i>%2</i><br><br>"
              "If a file already exists at the original path, you'll be asked "
              "what to do (the safe default is to restore-with-new-name).")
          .arg(
              QFileInfo(QString::fromStdString(opt->originalPath)).fileName().toHtmlEscaped(),
              QString::fromStdString(opt->originalPath).toHtmlEscaped()));
  box.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
  box.setDefaultButton(QMessageBox::Cancel);
  if (box.exec() != QMessageBox::Yes)
    return;

  R::ActionRequest req;
  req.action = R::ActionType::RestoreFromQuarantine;
  req.userConfirmed = true;
  req.target.kind = R::TargetKind::File;
  req.target.sourceId = id.toStdString();  // entry id lookup key
  req.target.path = opt->originalPath;
  req.target.sha256 = opt->sha256;
  // Default policy = AskUser. If the destination exists, the manager
  // returns needsUserChoice and we surface a second dialog.
  req.restorePolicy = R::RestoreConflictPolicy::AskUser;

  R::ActionResult res = R::globalResponseManager().execute(req);

  if (res.needsUserChoice) {
    QMessageBox conflict(this);
    conflict.setIcon(QMessageBox::Warning);
    conflict.setWindowTitle("File already exists");
    conflict.setText(
        "A file already exists at the original path.\n"
        "How do you want to restore?");
    QPushButton* btnNew = conflict.addButton("Restore with new name", QMessageBox::AcceptRole);
    QPushButton* btnOver = conflict.addButton("Overwrite existing", QMessageBox::DestructiveRole);
    QPushButton* btnCancel = conflict.addButton("Cancel", QMessageBox::RejectRole);
    conflict.setDefaultButton(btnNew);
    conflict.exec();
    QAbstractButton* clicked = conflict.clickedButton();

    if (clicked == btnCancel || clicked == nullptr) {
      setStatus("Restore cancelled.", false);
      return;
    }
    req.restorePolicy = (clicked == btnOver) ? R::RestoreConflictPolicy::Overwrite
                                             : R::RestoreConflictPolicy::RestoreWithNewName;
    res = R::globalResponseManager().execute(req);
  }

  if (res.success) {
    QMessageBox::information(
        this, "Restore", QString("File restored to:\n%1").arg(QString::fromStdString(res.newPath)));
    setStatus(QString("Restored to %1").arg(QString::fromStdString(res.newPath)), false);
    refresh();
  } else {
    const std::string err = res.errorMessage.empty() ? res.message : res.errorMessage;
    QMessageBox::critical(
        this,
        "Restore failed",
        QString("Could not restore file.\n\n%1").arg(QString::fromStdString(err)));
    setStatus(QString("Restore failed: %1").arg(QString::fromStdString(err)), true);
  }
}

void QuarantinePage::setStatus(const QString& msg, bool isError) {
  if (!m_status)
    return;
  if (msg.isEmpty()) {
    m_status->setVisible(false);
    m_status->clear();
    return;
  }
  m_status->setVisible(true);
  m_status->setText(msg);
  m_status->setStyleSheet(
      QString("QLabel { color: %1; %2 background: transparent; }")
          .arg(isError ? Theme::Color::severityCritical : Theme::Color::severitySafe)
          .arg(Theme::Type::qss(Theme::Type::Caption, Theme::Type::WeightSemi)));
}
