QT -= gui

CONFIG += console
CONFIG -= app_bundle
CONFIG += strict_c++

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS BUILD_QT

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

QMAKE_CFLAGS += -Wno-cast-align
QMAKE_CXXFLAGS += -Wno-cast-align

LIBS += -lrt -lpthread

SOURCES += \
    main.cpp \
    tcp_handler.c \
    rawsocket_http.c \
    routing_table.c \
    rawtcp.c

HEADERS += \
    tcp_handler.h \
    routing_table.h \
    outstream.h \
    rawtcp.h
