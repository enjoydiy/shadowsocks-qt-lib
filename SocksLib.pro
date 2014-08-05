QT -= gui
QT += network

TARGET = SocksLib
TEMPLATE = lib

DEFINES += SOCKSLIB_LIBRARY

unix:!symbian {
	maemo5 {
		target.path = /opt/usr/lib
	} else {
		target.path = /usr/lib
	}
	INSTALLS += target
}

OTHER_FILES += \
    SocksLib.pro

INCLUDEPATH += .

HEADERS += \
    SocksSessionManager.h \
    SocksSession.h \
    SocksServer.h \
    SocksConnection.h \
    decorators/ThrottlingDecorator.h \
    decorators/QIODeviceDecorator.h \
    protocol/SocksReplyMessage4a.h \
    protocol/SocksProtocolMessage.h \
    protocol/Socks5UDPRequestMessage.h \
    protocol/Socks5RequestMessage.h \
    protocol/Socks5ReplyMessage.h \
    protocol/Socks5MethodSelectionMessage.h \
    protocol/Socks5GreetingMessage.h \
    protocol/Socks4RequestMessage.h \
    protocol/Socks4ReplyMessage.h \
    states/SocksState.h \
    states/Socks5UDPAssociateState.h \
    states/Socks5UDPAssociatedState.h \
    states/Socks5ConnectState.h \
    states/Socks5ConnectedState.h \
    states/Socks5AuthState.h \
    states/Socks5AuthenticatedState.h \
    states/Socks4InitialState.h \
    states/Socks4ConnectState.h \
    states/Socks4ConnectedState.h \
    states/InitialState.h \
    SocksLib_global.h \
    decorators/QTcpSocketDecorator.h \
    encrypt.h \
    base.h

SOURCES += \
    SocksSessionManager.cpp \
    SocksSession.cpp \
    SocksServer.cpp \
    SocksConnection.cpp \
    decorators/ThrottlingDecorator.cpp \
    decorators/QIODeviceDecorator.cpp \
    protocol/SocksReplyMessage4a.cpp \
    protocol/SocksProtocolMessage.cpp \
    protocol/Socks5UDPRequestMessage.cpp \
    protocol/Socks5RequestMessage.cpp \
    protocol/Socks5ReplyMessage.cpp \
    protocol/Socks5MethodSelectionMessage.cpp \
    protocol/Socks5GreetingMessage.cpp \
    protocol/Socks4RequestMessage.cpp \
    protocol/Socks4ReplyMessage.cpp \
    states/SocksState.cpp \
    states/Socks5UDPAssociateState.cpp \
    states/Socks5UDPAssociatedState.cpp \
    states/Socks5ConnectState.cpp \
    states/Socks5ConnectedState.cpp \
    states/Socks5AuthState.cpp \
    states/Socks5AuthenticatedState.cpp \
    states/Socks4InitialState.cpp \
    states/Socks4ConnectState.cpp \
    states/Socks4ConnectedState.cpp \
    states/InitialState.cpp \
    decorators/QTcpSocketDecorator.cpp \
    encrypt.cpp



win32: LIBS += -L$$PWD/openssl/ -lcrypto
win32: LIBS += -lgdi32 -lws2_32 -lcrypt32

INCLUDEPATH += $$PWD/openssl/
DEPENDPATH += $$PWD/openssl/

win32:win32-g++: PRE_TARGETDEPS += $$PWD/openssl/libcrypto.a

win32: LIBS += -L$$PWD/openssl/ -lssl

win32:win32-g++: PRE_TARGETDEPS += $$PWD/openssl/libssl.a
