#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QVector>
#include <QLineEdit>
#include "portscanner.h"
#include "packetcapture.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void toggleCapture();
    void scanPorts();
    void protocolChanged(const QString& protocol);
    void addPort(int port, const QString& protocol, 
                const QString& state, const QString& service);
    void processPacket(const PacketInfo& packet);
    void onPacketSelected(int row, int column);
    void applyFilter();

private:
    void setupUi();
    void startCapture();
    void stopCapture();
    void refreshInterfaces();
    void updatePacketDetails(int index);

    Ui::MainWindow *ui;
    PortScanner* portScanner;
    PacketCapture* packetCapture;
    int packetCounter;
    bool isCapturing;
    QVector<PacketInfo> capturedPackets;
    QLineEdit *filterEdit;
};

#endif // MAINWINDOW_H