#include "ScanTypeOverlay.h"

#include <QDir>
#include <QFileDialog>
#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QResizeEvent>
#include <QVBoxLayout>

// ============================================================================
// Helper: build one option column (title + description + action button)
// ============================================================================
static QFrame* makeOptionCard(
    const QString& title, const QString& description, const QString& buttonLabel, bool enabled) {
  auto* card = new QFrame();
  card->setStyleSheet(
      "QFrame {"
      "  background-color: #F0F4FF;"
      "  border-radius: 14px;"
      "  border: 1px solid #C8D4FF;"
      "}"
      "QLabel { background: transparent; border: none; }");

  auto* layout = new QVBoxLayout(card);
  layout->setContentsMargins(18, 18, 18, 18);
  layout->setSpacing(10);

  auto* titleLbl = new QLabel(title);
  titleLbl->setStyleSheet("font-size: 14px; font-weight: bold; color: #111111;");
  titleLbl->setWordWrap(true);

  auto* descLbl = new QLabel(description);
  descLbl->setStyleSheet("font-size: 11px; color: #555555; line-height: 140%;");
  descLbl->setWordWrap(true);
  descLbl->setAlignment(Qt::AlignTop | Qt::AlignLeft);

  auto* btn = new QPushButton(buttonLabel);
  if (enabled) {
    btn->setCursor(Qt::PointingHandCursor);
    btn->setStyleSheet(
        "QPushButton {"
        "  background-color: #1A1AEE;"
        "  color: white;"
        "  border-radius: 14px;"
        "  padding: 9px 0;"
        "  font-weight: bold;"
        "  font-size: 13px;"
        "  border: none;"
        "}"
        "QPushButton:hover { background-color: #0000CC; }"
        "QPushButton:pressed { background-color: #00009A; }");
  } else {
    btn->setCursor(Qt::ForbiddenCursor);
    btn->setEnabled(false);
    btn->setStyleSheet(
        "QPushButton {"
        "  background-color: #DDDDDD;"
        "  color: #999999;"
        "  border-radius: 14px;"
        "  padding: 9px 0;"
        "  font-size: 13px;"
        "  border: none;"
        "}");
  }

  layout->addWidget(titleLbl);
  layout->addWidget(descLbl, 1);
  layout->addWidget(btn);

  return card;
}

// ============================================================================
// ScanTypeOverlay
// ============================================================================
ScanTypeOverlay::ScanTypeOverlay(QWidget* parent)
    : QWidget(parent) {
  // Cover the parent widget fully; stays hidden until showOverlay() is called
  if (parent)
    setGeometry(parent->rect());
  hide();

  // ---- Outer card (the white popup panel) --------------------------------
  m_card = new QFrame(this);
  m_card->setObjectName("overlayCard");
  m_card->setStyleSheet(
      "QFrame#overlayCard {"
      "  background-color: #FFFFFF;"
      "  border-radius: 20px;"
      "}");
  m_card->setFixedSize(820, 360);

  auto* cardLayout = new QVBoxLayout(m_card);
  cardLayout->setContentsMargins(35, 30, 35, 30);
  cardLayout->setSpacing(22);

  // Title
  auto* titleLbl = new QLabel("Select Scan Type");
  titleLbl->setStyleSheet("font-size: 22px; font-weight: bold; color: #000000;");
  titleLbl->setAlignment(Qt::AlignCenter);
  cardLayout->addWidget(titleLbl);

  // Subtitle hint
  auto* hintLbl = new QLabel("Click outside this panel or press Escape to cancel.");
  hintLbl->setStyleSheet("font-size: 11px; color: #999999;");
  hintLbl->setAlignment(Qt::AlignCenter);
  cardLayout->addWidget(hintLbl);

  // ---- Three option columns -----------------------------------------------
  auto* optRow = new QHBoxLayout();
  optRow->setSpacing(18);

  QFrame* fullCard = makeOptionCard(
      "Full System Scan",
      "Entire scan of your disk drive, including all system files.",
      "Start Full Scan",
      true);

  QFrame* partialCard = makeOptionCard(
      "Partial Scan",
      "Scan based on your choosing — select which drives or directories "
      "you want scanned.",
      "Choose Directory",
      true);

  QFrame* lastCard = makeOptionCard(
      "Scan from Last Point",
      "Continue scanning from where the last scan left off. Previously "
      "scanned clean files are skipped automatically via the scan cache.",
      "Resume Scan",
      true);

  optRow->addWidget(fullCard);
  optRow->addWidget(partialCard);
  optRow->addWidget(lastCard);
  cardLayout->addLayout(optRow);

  // ---- Wire buttons -------------------------------------------------------
  QPushButton* fullBtn = fullCard->findChild<QPushButton*>();
  QPushButton* partialBtn = partialCard->findChild<QPushButton*>();
  QPushButton* lastBtn = lastCard->findChild<QPushButton*>();

  connect(fullBtn, &QPushButton::clicked, this, [this]() {
    hide();
    emit fullScanRequested();
  });

  connect(partialBtn, &QPushButton::clicked, this, [this]() {
    QString dir = QFileDialog::getExistingDirectory(
        this,
        "Select Directory to Scan",
        QDir::homePath(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!dir.isEmpty()) {
      hide();
      emit partialScanRequested(dir);
    }
  });

  connect(lastBtn, &QPushButton::clicked, this, [this]() {
    hide();
    emit resumeScanRequested();
  });

  repositionCard();
}

void ScanTypeOverlay::showOverlay() {
  if (parentWidget())
    setGeometry(parentWidget()->rect());
  repositionCard();
  raise();
  show();
  setFocus();
}

// ============================================================================
// Protected overrides
// ============================================================================
void ScanTypeOverlay::paintEvent(QPaintEvent*) {
  // Draw the dim background manually — this is required because Qt child
  // widgets don't compose alpha with their parents via stylesheets alone.
  QPainter p(this);
  p.fillRect(rect(), QColor(0, 0, 0, 170));
}

void ScanTypeOverlay::resizeEvent(QResizeEvent* e) {
  QWidget::resizeEvent(e);
  repositionCard();
}

void ScanTypeOverlay::mousePressEvent(QMouseEvent* e) {
  // Dismiss when clicking on the dim area outside the card
  if (m_card && !m_card->geometry().contains(e->pos()))
    hide();
  else
    QWidget::mousePressEvent(e);
}

void ScanTypeOverlay::keyPressEvent(QKeyEvent* e) {
  if (e->key() == Qt::Key_Escape)
    hide();
  else
    QWidget::keyPressEvent(e);
}

void ScanTypeOverlay::repositionCard() {
  if (m_card) {
    m_card->move((width() - m_card->width()) / 2, (height() - m_card->height()) / 2);
  }
}
