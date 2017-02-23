DEPENDPATH += .
INCLUDEPATH += .
TEMPLATE = app
QT += network gui widgets

SOURCES += \
    main.cpp \
    SocketTestQ.cpp \
    tcpportlist.cpp \
    udpportlist.cpp \
    csslserver.cpp

HEADERS += \
    SocketTestQ.h \
    tcpportlist.h \
    udpportlist.h \
    csslserver.h

FORMS += \
    SocketTestQ.ui \
    tcpportlist.ui \
    udpportlist.ui

RESOURCES += \
    Image.qrc

win32:RC_ICONS += ethernet.ico

CONFIG(release, debug|release): CONFIG += release
CONFIG(debug, debug|release): CONFIG += debug
