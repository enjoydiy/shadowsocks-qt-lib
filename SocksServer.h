#ifndef SOCKSSERVER_H
#define SOCKSSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QPointer>
#include <QList>
#include <QHostAddress>
#include <QHostInfo>

#include "encrypt.h"

#include "SocksLib_global.h"
class SocksConnection;

class SOCKSLIBSHARED_EXPORT SocksServer : public QObject
{
    Q_OBJECT
public:
    explicit SocksServer(QHostAddress listenAddress = QHostAddress::Any,
                         quint16 listenPort = 1080,
                         qreal throttle = 500.0,
                         QObject *parent = 0);
    ~SocksServer();

    void start();

    bool isStarted() const;
    
signals:
    
public slots:

private slots:
    void handleNewIncomingConnection();
    void handleConnectionDestroyed();

private:
    QHostAddress _listenAddress;
    quint16 _listenPort;
    qreal _throttle;
    QPointer<QTcpServer> _serverSock;
    QList<QPointer<SocksConnection> > _connections;

protected:
    class encrypt *encrypt;
    QHostInfo remoteIp;
    quint16 remotePort;
    
};

#endif // SOCKSSERVER_H
