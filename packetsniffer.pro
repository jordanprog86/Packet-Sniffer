#-------------------------------------------------
#
# Project created by QtCreator 2017-08-30T12:42:54
#
#-------------------------------------------------

QT       += core gui network
CONFIG    += console

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer 1.0
TEMPLATE = app

SOURCES += main.cpp\
        sniffer.cpp

HEADERS  += sniffer.h

FORMS    += sniffer.ui

RC_ICONS += sniffer_icons_2.ico

RESOURCES += \
    mdata.qrc



win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/ -lpacket
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/ -lpacketd
else:unix: LIBS += -L$$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/ -lpacket

INCLUDEPATH += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Include
DEPENDPATH += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Include

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/libpacket.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/libpacketd.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/packet.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/packetd.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/libpacket.a

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/ -lwpcap
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/ -lwpcapd
else:unix: LIBS += -L$$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/ -lwpcap

INCLUDEPATH += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Include
DEPENDPATH += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Include

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/libwpcap.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/libwpcapd.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/wpcap.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/wpcapd.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../../../../../../Downloads/WpdPack_4_1_2/WpdPack/Lib/libwpcap.a
