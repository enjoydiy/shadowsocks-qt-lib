#include "SocksConnection.h"

#include <QtDebug>
#include <QHostAddress>

#include "states/InitialState.h"
#include "decorators/QIODeviceDecorator.h"
#include "decorators/ThrottlingDecorator.h"

SocksConnection::SocksConnection(QAbstractSocket *socket,class encrypt *_encrypt,
                                 QHostInfo *rip, quint16 port,QObject *parent) :
    QObject(parent), remotePort(port), remoteIp(rip), readData(true)
{
    //tackle encrypt data struct
    encrypt = _encrypt;
    encrypt->init_ctx(&d_ctx, false);
    encrypt->init_ctx(&e_ctx, true);

    _rawSocket = socket;
    if (_rawSocket.isNull())
    {
        qWarning() << this << "initialized with null socket";
        return;
    }

    _socket = new ThrottlingDecorator(_rawSocket,this);

    //When we have incoming bytes, we read them
    connect(_socket.data(),
            SIGNAL(readyRead()),
            this,
            SLOT(handleReadyRead()));

    //When our socket closes, we die
    connect(_socket.data(),
            SIGNAL(aboutToClose()),
            this,
            SLOT(handleSocketClosed()));


    //Set our state to the initial "someone just connected" state
    this->setState(new InitialState(this));

    //We don't yet know what version of SOCKS we're supposed to be speaking
    _socksVersionSet = false;
}

SocksConnection::~SocksConnection()
{
    if (!_socket.isNull())
    {
        _socket->close();
        _socket->deleteLater();
    }

    if (!_connectionState.isNull())
        delete _connectionState;
}

QPointer<SocksState> SocksConnection::connectionState()
{
    return _connectionState;
}

SocksProtocolMessage::SocksVersion SocksConnection::socksVersion() const
{
    return _socksVersion;
}

void SocksConnection::setSocksVersion(SocksProtocolMessage::SocksVersion nVer)
{
    if (_socksVersionSet)
        return;
    _socksVersionSet = true;
    _socksVersion = nVer;
}

bool SocksConnection::socksVersionSet() const
{
    return _socksVersionSet;
}

bool SocksConnection::sendMessage(QSharedPointer<SocksProtocolMessage> msg, QString *error)
{
    if (msg.isNull())
    {
        if (error)
            *error = "Cannot send null message";
        return false;
    }

    QByteArray toSend;
    QString serializeError;
    if (!msg->toBytes(&toSend,&serializeError))
    {
        if (error)
            *error = "Failed to send message. Error:" + serializeError;
        return false;
    }

    this->sendData(toSend);
    return true;
}

QHostAddress SocksConnection::myBoundAddress() const
{
    return _rawSocket->localAddress();
}

QHostAddress SocksConnection::peerAddress() const
{
    return _rawSocket->peerAddress();
}

void SocksConnection::decodeSend(QByteArray &in)
{
    QByteArray out;
    ssize_t len = in.length();
    QByteArray *f = encrypt->ss_decrypt(BUF_SIZE, &out, &in, &len, &d_ctx);
    if(f)
    {
        sendData(*f);
    }else{
        //TODO
        qDebug() << "can not decode the data from server";
    }

}

QByteArray *SocksConnection::encodeData(QByteArray &in, QByteArray &out)
{
    ssize_t len = in.length();
    return encrypt->ss_encrypt(BUF_SIZE, &out, &in, &len, &e_ctx);
}

void SocksConnection::readSockdata(bool canRead)
{
    if(canRead)
    {
        readData = true;
        handleReadyRead();
    }
    else
    {
        readData = false;
    }
}

//public slot
void SocksConnection::sendData(const QByteArray &toSend)
{
    if (_socket.isNull())
    {
        qWarning() << "Tried to send" << toSend.size() << "bytes but socket was null";
        return;
    }

    qint64 written = _socket->write(toSend);
    if (written != toSend.size())
        qWarning() << this << "wrote" << written << "bytes but should have written" << toSend.size() << "bytes";

    //qDebug() << "State" << _connectionState << "wrote" << toSend.toHex();
}

//public slot
void SocksConnection::setState(SocksState *nState)
{
    if (nState == 0)
        return;

    if (!_connectionState.isNull())
        delete _connectionState;

    _connectionState = nState;

    //Call the "you've just been set as the new state!" handler
    nState->handleSetAsNewState();

    //Force the new state to start off where the last one ended traffic-wise
    if (!_recvBuffer.isEmpty())
        this->handleIncomingBytes(_recvBuffer);
}

void SocksConnection::close()
{
        qDebug() << "Socks closed";
    if (_socket.isNull())
        return;
    _socket->close();
}

//protected slot
void SocksConnection::handleIncomingBytes(QByteArray &bytes)
{
    if (_connectionState.isNull())
    {
        qWarning() << this << "No state to do handleIncomingBytes";
        return;
    }

    if (bytes.size() == 0)
    {
        qWarning() << this << "got empty array in handleIncomingBytes";
        return;
    }

    //Pass the bytes to the state by reference. The state will eat the bytes it wants
    _connectionState->handleIncomingBytes(bytes);
}

//private slot
void SocksConnection::handleReadyRead()
{
    if (!readData)
    {
        qDebug() << "have data coming and refuse the data";
        return;
    }
    if (_socket.isNull())
        return;

    int count = 0;
    const int max = 50;
    while (_socket->bytesAvailable() > 0 && ++count < max)
        _recvBuffer.append(_socket->readAll());
    if (count == max)
        qDebug() << this << "looped too much";

    if (!_recvBuffer.isEmpty() && !_connectionState.isNull()
            && _connectionState.data()->stage == SocksState::D_CONNECTED)
    {
        qDebug() << "Stop recv data:" << _connectionState.data()->stage;
                    //(_connectionState.data()->stage == SocksState::D_CONNECTED)?"D_CONNECTED":"INIT";
        readSockdata(false);
    }

    //Send the whole buffer to the state, which should eat the portions it wants
    this->handleIncomingBytes(_recvBuffer);
}

//private slot
void SocksConnection::handleSocketClosed()
{
    //qDebug() << "Client" << _socket->peerAddress().toString() << ":" << _socket->peerPort() << "disconnected";
    this->deleteLater();
}
