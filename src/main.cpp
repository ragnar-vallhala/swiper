#include <QApplication>
#include "mainwindow.h"
#include "packetcapture.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    
    // Register PacketInfo for use in signals/slots
    qRegisterMetaType<PacketInfo>();
    
    MainWindow w;
    w.show();
    return a.exec();
}