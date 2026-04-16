#include <QApplication>
#include <QLabel>
#include <QIcon>
#include <QPixmap>
#include "ui/ui.h"
#include "ui/MainWindow/MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // Set application icon from embedded PNG resource
    app.setWindowIcon(QIcon(QPixmap(":/icons/logo_icon.png")));

    MainWindow w;
    w.show();
    return app.exec();
}
