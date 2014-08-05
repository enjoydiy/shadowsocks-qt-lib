#include "Socks5ConnectedState.h"

#include <QPointer>

Socks5ConnectedState::Socks5ConnectedState(QIODevice *remoteSocket, QSharedPointer<Socks5RequestMessage> request, SocksConnection *parent) :
    SocksState(parent), _socket(remoteSocket), _request(request), remote_connected(0)
{
    if (_socket.isNull())
        return;

    _socket->setParent(this);

    stage = D_CONNECTED;

    //construct the diy socks header
    QDataStream stream(&header,QIODevice::WriteOnly);

    quint8 atyp;
    atyp = _request->addressType();
    stream << atyp;

    if(_request->addressType() == Socks5RequestMessage::IPv4)
    {
        quint32 ip = _request->address().toIPv4Address();
        stream << ip;
        quint16 port = _request->port();
        stream << port;
    }
    if(_request->addressType() == Socks5RequestMessage::IPv6)
    {
        quint8 * ipv6buf = new quint8[16];
        Q_IPV6ADDR addr = _request->address().toIPv6Address();

        for (int i = 0; i < 16; ++i) {
            ipv6buf[i] = addr[i];
        }

        int write = stream.writeRawData((char*)ipv6buf, 16);
        if(write != 16)
        {
            qWarning ("Failed to write IPv6 address bytes");
        }
        delete ipv6buf;

        quint16 port = _request->port();
        stream << port;
    }
    if(_request->addressType() == Socks5RequestMessage::DomainName)
    {
        QString domain = _request->domainName();
        quint8 len = domain.length();
        stream << len;
        stream.writeRawData(domain.toLatin1(), len);
        //stream << domain;

        quint16 port = _request->port();
        stream << port;
    }
    //END header

    connect(_socket.data(),
             SIGNAL(readyRead()),
             this,
             SLOT(handleRemoteReadyRead()));
    connect(_socket.data(),
             SIGNAL(aboutToClose()),
             this,
             SLOT(handleRemoteDisconnect()));
}

void Socks5ConnectedState::handleIncomingBytes(QByteArray &bytes)
{
    if(0 == remote_connected)
    {
        bytes.prepend(header);
    }
    else
    {
        qDebug() << "connected =1";
    }
    QByteArray *encode_bytes;
    QByteArray out;
    encode_bytes = _parent->encodeData(bytes, out);
    if(encode_bytes)
    {
        qint64 written = _socket->write(*encode_bytes);
        if (written < bytes.size())
            qWarning() << "Failed to write all" << bytes.size() << "desired bytes to remote connect. Wrote only" << written << "bytes";
        if(written > 0)
            remote_connected = 1;
        //Clear the bytes!
        bytes.clear();
        out.clear();
        qDebug() << "Send data:" << written << "bytes";
    }
    else
    {
        qDebug() << "encoder returns null";
        _parent->close();
    }



}

void Socks5ConnectedState::handleSetAsNewState()
{
    if (_socket.isNull())
    {
        qWarning() << this << "received null remote socket";
        _parent->close();
        return;
    }

    //Get any bytes from the remote socket that are waiting!
    this->handleRemoteReadyRead();
}

//private slot
void Socks5ConnectedState::handleRemoteReadyRead()
{
    int count = 0;
    const int max = 50;
    while (_socket->bytesAvailable() && ++count < max)
    {
        QByteArray bytes = _socket->readAll();
        //QByteArray bytes = _socket->read(BUF_SIZE);
        //wzj:decode the data and send to client
        _parent->decodeSend(bytes);
        qDebug() << "Recieve data:" << bytes.length() << "bytes";
        //_parent->sendData(bytes);
    }

    if (count == max)
        qDebug() << this << "looped too much";

    qDebug() << "can read data again";
    _parent->readSockdata(true);
}

//private slot
void Socks5ConnectedState::handleRemoteDisconnect()
{
    //Close the client connection too
    _parent->close();
    qDebug() << "remote disconnect and client dis too";
}
