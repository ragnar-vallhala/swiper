#ifndef PORTSCANNER_H
#define PORTSCANNER_H

#include <QThread>
#include <QObject>

class PortScanner : public QThread
{
    Q_OBJECT

public:
    explicit PortScanner(const QString& protocol, QObject *parent = nullptr);
    void stop();

signals:
    void portFound(int port, const QString& protocol, 
                  const QString& state, const QString& service);

protected:
    void run() override;

private:
    QString protocol;
    bool running;
    void scanTCP();
    void scanUDP();
};

#endif // PORTSCANNER_H