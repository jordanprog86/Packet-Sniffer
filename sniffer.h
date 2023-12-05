#ifndef SNIFFER_H
#define SNIFFER_H
#include "winsock2.h"
#include <QMainWindow>
#include <QStringList>
#include <QtWidgets>
#include "QtGui"
#include <QtCore>
#include "stdlib.h"
#include "sys/types.h"
#include "pcap/pcap.h"

namespace Ui {
class Sniffer;
}

class Sniffer : public QMainWindow
{
    Q_OBJECT

public:
    explicit Sniffer(QWidget *parent = 0);
    void findAlldevs();
    QString getStringFromUnsignedChar(const unsigned char *str, const int len );
    void addItem(int len, QString time, QString from, QString to, QString proto, QString info);
    QString getIp(u_char byte1, u_char byte2, u_char byte3, uchar byte4);
    QString fromUchar(u_char m_uchar);
    void getDevAndvancedInfos(pcap_if_t *d);
    char *iptos(u_long in);
    ~Sniffer();

protected:
    void changeEvent(QEvent *e);

private slots:
    void on_actionFindAllDevices_triggered();
    void on_actionLookupdev_triggered();


    void on_actionFindDevice_triggered();

    void on_actionNetLookup_triggered();

    void on_actionSniffer_triggered();

    void on_actionHome_triggered();

private:
    Ui::Sniffer *ui;
    QStringList deviceNames;
    bpf_u_int32 m_netp;
    QString currentText;
    int curColumn;
    int curRow;
    QString curtext;
    QTimer *lookupTimer;
    QInputDialog *lookupMinutes;
    bool interfaceSelected;
    int minutes;

private slots:
    void lookUp();

    void on_actionExit_triggered();
};

#endif // SNIFFER_H
