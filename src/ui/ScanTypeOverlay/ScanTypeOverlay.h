#pragma once

#include <QWidget>

class QFrame;

// ============================================================================
// ScanTypeOverlay
//
// Full-window dimming overlay that lets the user choose a scan type before
// the scan starts.  Shown by calling showOverlay(); dismissed by clicking
// outside the card, pressing Escape, or choosing an option.
// ============================================================================
class ScanTypeOverlay : public QWidget
{
    Q_OBJECT

public:
    explicit ScanTypeOverlay(QWidget* parent);

    // Call this to make the overlay visible (resizes to match parent first)
    void showOverlay();

signals:
    void fullScanRequested();
    void partialScanRequested(const QString& path);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private:
    QFrame* m_card = nullptr;
    void    repositionCard();
};
