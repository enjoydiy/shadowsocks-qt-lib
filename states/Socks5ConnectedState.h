#ifndef SOCKS5CONNECTEDSTATE_H
#define SOCKS5CONNECTEDSTATE_H

#include "SocksState.h"
#include "protocol/Socks5RequestMessage.h"

#include <QTcpSocket>
#include <QPointer>
#include <QIODevice>
#include <QMutex>

#include "../base.h"

class Socks5ConnectedState : public SocksState
{
    Q_OBJECT
public:
    explicit Socks5ConnectedState(QIODevice * remoteSocket, QSharedPointer<Socks5RequestMessage> request, SocksConnection *parent = 0);

    //pure-virtual from SocksState
    virtual void handleIncomingBytes(QByteArray& bytes);

    //virtual from SocksState
    virtual void handleSetAsNewState();

private:
    QPointer<QIODevice> _socket;
    bool _shutdown;

    //For diy socks
    QByteArray header;
    int remote_connected;
    QSharedPointer<Socks5RequestMessage> _request;

    QMutex sendR;
    
signals:
    
public slots:

private slots:
    void handleRemoteReadyRead();
    void handleRemoteDisconnect();
    
};

#endif // SOCKS5CONNECTEDSTATE_H
