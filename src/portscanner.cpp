#include "portscanner.h"
#include <QTcpSocket>
#include <QUdpSocket>
#include <QDebug>
#define MAX_PORT 65535
PortScanner::PortScanner(const QString& protocol, QObject *parent)
    : QThread(parent)
    , protocol(protocol)
    , running(true)
{
}

void PortScanner::stop()
{
    running = false;
}

void PortScanner::run()
{
    if(protocol == "TCP" || protocol == "All") {
        scanTCP();
    }
    if(protocol == "UDP" || protocol == "All") {
        scanUDP();
    }
}

void PortScanner::scanTCP()
{
    for(int port = 1; port < MAX_PORT && running; ++port) {
        QTcpSocket socket;
        socket.connectToHost("127.0.0.1", port);
        
        if(socket.waitForConnected(100)) {
            emit portFound(port, "TCP", "OPEN", 
                         QString::number(port));
        }
        socket.close();
    }
}

void PortScanner::scanUDP()
{
    for(int port = 1; port < MAX_PORT && running; ++port) {
        QUdpSocket socket;
        if(socket.bind(QHostAddress::LocalHost, port)) {
            socket.close();
        } else {
            emit portFound(port, "UDP", "OPEN", 
                         QString::number(port));
        }
    }
}