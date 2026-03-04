#include <QApplication>
#include <QLabel>
#include "ui/ui.h"
#include "ui/MainWindow/MainWindow.h"
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}
