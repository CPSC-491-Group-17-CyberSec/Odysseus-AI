#include <QApplication>
#include <QLabel>
#include <QIcon>
#include <QPixmap>
#include "ui/ui.h"
#include "ui/MainWindow/MainWindow.h"
#include "ui/theme/DashboardTheme.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // Apply the dark cybersecurity theme before any widgets are created so
    // every widget inherits the palette by default.
    Theme::install(&app);

    // Set application icon from embedded PNG resource
    app.setWindowIcon(QIcon(QPixmap(":/icons/logo_icon.png")));

    MainWindow w;
    w.show();
    return app.exec();
}
