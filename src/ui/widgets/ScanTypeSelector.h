#pragma once
// ============================================================================
// ScanTypeSelector.h  –  three Quick/Full/Custom cards plus a Start button
//
// Internal state: which card is selected. The Start button text and color
// update with the selection. Emits scanRequested(ScanType) when the button
// is clicked.
//
// Wiring:
//   MainWindow connects scanRequested to its existing scan slots:
//     Quick  → onRunScanClicked()       (pops the existing overlay)
//     Full   → onFullScanRequested()
//     Custom → onRunScanClicked()       (overlay → user picks Custom)
//
// We deliberately route Quick + Custom through the existing overlay so the
// user gets the same downstream UX. Step 5 may wire direct quick-scan.
// ============================================================================

#include <QFrame>
#include <QString>

class QPushButton;
class QLabel;

class ScanTypeSelector : public QFrame
{
    Q_OBJECT
public:
    enum ScanType { Quick = 0, Full = 1, Custom = 2 };

    explicit ScanTypeSelector(QWidget* parent = nullptr);

    void setSelected(ScanType type);
    ScanType selected() const { return m_selected; }

protected:
    /// Hooked up to each card-frame so a click selects that scan type
    /// without needing a custom QFrame subclass with a clicked() signal.
    bool eventFilter(QObject* watched, QEvent* event) override;

signals:
    void scanRequested(int scanType);

private slots:
    void onCardClicked();
    void onStartClicked();

private:
    struct Card {
        QFrame*  frame    = nullptr;
        QLabel*  glyph    = nullptr;
        QLabel*  title    = nullptr;
        QLabel*  subtitle = nullptr;
        QLabel*  estimate = nullptr;
        ScanType type     = Quick;
    };
    void styleCard(Card& c, bool selected);
    Card buildCard(ScanType type, const QString& glyph,
                    const QString& title, const QString& subtitle,
                    const QString& estimate);

    Card        m_cards[3];
    QPushButton* m_startBtn = nullptr;
    ScanType    m_selected = Quick;
};
