#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QThread>
#include <QObject>
#include <pcap.h>
#include <QMutex>
#include <atomic>

struct PacketInfo {
    Q_GADGET
public:
    PacketInfo() : length(0) {}
    
    QString timestamp;
    QString sourceIP;
    QString destIP;
    QString protocol;
    int length;
    QString details;
    QString hexDump;
};
Q_DECLARE_METATYPE(PacketInfo)

class PacketCapture : public QThread
{
    Q_OBJECT

public:
    explicit PacketCapture(const QString& interface, 
                          const QString& protocol,
                          const QString& filter,
                          QObject *parent = nullptr);
    ~PacketCapture();
    void stop();

signals:
    void packetCaptured(const PacketInfo& packet);

protected:
    void run() override;

private:
    void processPacket(const struct pcap_pkthdr *pkthdr, 
                      const u_char *packet);
    QString createHexDump(const u_char* data, int len);

    QString interface;
    QString protocol;
    QString filter;
    std::atomic<bool> running;
    pcap_t* handle;
    QMutex mutex;
};

#endif // PACKETCAPTURE_H