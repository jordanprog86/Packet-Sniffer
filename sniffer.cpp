#include "sniffer.h"
#include "ui_sniffer.h"
#include <QStyleFactory>
#include "stdlib.h"
#include "sys/types.h"
#include "winsock2.h"
#include "stdio.h"
#include "pcap.h"
#include "stdio.h"
#include "winsock.h"
#include "ethertype.h"
#include "wlanapi.h"
#include <QListWidgetItem>
#include <QDebug>
#include <iostream>

#define LINE_LEN 16
#define IPTOSBUFFERS    12
char errbuf[PCAP_ERRBUF_SIZE];

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

using namespace std;

Sniffer::Sniffer(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Sniffer)
{

    ui->setupUi(this);
    ui->Home->setLayout(ui->hbLayout);
    ui->sniffer->setLayout(ui->gridLayout);
    ui->stackedWidget->setCurrentIndex(0);
    setCentralWidget(ui->stackedWidget);

    setStyle(QStyleFactory::create("Fusion"));


    //Creons notre menu contextuel;

    ui->mListe->addAction(ui->actionProperties);

    //
    curColumn = 0;
    curRow = 0;
    //
    interfaceSelected = false;
    //
    minutes = 0;





}

Sniffer::~Sniffer()
{
    delete ui;
}

void Sniffer::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}
void Sniffer::findAlldevs()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    ui->devices_comboBox->clear();
    ui->mListe->clear();





    /* Retrieve the device list */
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        ui->Logdisplayer->append("Error in pcap_findalldevs: ");
         ui->Logdisplayer->append(errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {

        QListWidgetItem *devItem = new QListWidgetItem(ui->mListe);
        QString description;
        description.append(d->description);
        devItem->setText(d->description);
        devItem->setToolTip(d->name);



        ui->mListe->addItem(devItem);
        interfaceSelected = true;
        getDevAndvancedInfos(d);


        if (d->description)
        {


            ui->devices_comboBox->addItem(QString(d->name));
            deviceNames << d->name;

        }

        else
        {

            ui->Logdisplayer->append(" (No description available)\n");
        }
    }




}

void Sniffer::on_actionFindAllDevices_triggered()
{
    findAlldevs();
}

void Sniffer::on_actionLookupdev_triggered()
{
      lookupMinutes = new QInputDialog;
      bool success;
      minutes = lookupMinutes->getInt(this, "Lookup Time", "Enter the lookup Time in Minutes", 1,1,120,1,&success);

      qDebug()<<minutes;
      qDebug()<<success;
if(success && interfaceSelected)
{
      minutes = minutes *60;
      qDebug()<<minutes;
      lookupTimer = new QTimer;
      lookupTimer->start(1000);
      connect(lookupTimer, SIGNAL(timeout()), this, SLOT(lookUp()));


}
else
{
     qDebug()<<"Error occured:please make sure that you have selected an Interface";
}


}

void Sniffer::on_actionFindDevice_triggered()
{

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct in_addr addr;


    int ret;
    QString dev = ui->devices_comboBox->currentText();
    const char *devicename = dev.toLatin1().data();

    ret = pcap_lookupnet(devicename, &netp, &maskp, errbuf);
    if(ret == -1)
    {
        ui->Logdisplayer->append(errbuf);
        netp = 0;
        maskp = 0;


    }
    else
    {
        ui->Logdisplayer->append("Device looked up");
        ui->Logdisplayer->append("--------------------------------------------------------------------------------------------------------------");
        m_netp = netp;
        int netmask = (bpf_u_int32)maskp;
        int netip = (bpf_u_int32)netp;
        qDebug()<<netp;
        qDebug()<<netmask;
        ui->Logdisplayer->append("Netmask: "+ QString::number(netmask));
        ui->Logdisplayer->append("Dev ip: "+ QString::number(netip));
        ui->Logdisplayer->append("------------------------------------------------------------------------------------------------------------------");


    }


}

void Sniffer::on_actionNetLookup_triggered()
{

}
QString Sniffer::getStringFromUnsignedChar( const unsigned char *str, const int len ){
QString result = "";

// print string in reverse order
QString s;

s = QString( "%1" ).arg( str[len], 0, 16 );
// account for single-digit hex values (always must serialize as two digits)
if( s.length() == 1 )
result.append( "0" );
result.append( s );

return result;
}

void Sniffer::addItem(int len,QString time, QString from, QString to,QString proto, QString info)
{
    for(int i = 0; i < ui->m_tW->columnCount(); i++)
    {
        QTableWidgetItem *it = new QTableWidgetItem;



        if(i == 0)
        {
            it->setText(QString::number(len));
            ui->m_tW->setItem(curRow, i, it);
        }
        else if (i==1)
        {

        it->setText(time);
        ui->m_tW->setItem(curRow, i, it);
        }
        else if(i == 2)
        {
            it->setText(from);
             ui->m_tW->setItem(curRow, i, it);
        }
        else if(i == 3)
        {
            it->setText(to);
              ui->m_tW->setItem(curRow, i, it);
        }
        else if(i == 4)
        {
            it->setText(proto);
               ui->m_tW->setItem(curRow, i, it);
        }
        else if(i == 5)
        {
            it->setText(info);
                ui->m_tW->setItem(curRow, i, it);
        }


    }
    curRow++;
}

QString Sniffer::getIp(u_char byte1, u_char byte2, u_char byte3, uchar byte4)
{
    QString fb = QString::number(byte1);
    QString sb = QString::number(byte2);
    QString tb = QString::number(byte3);
    QString fthb = QString::number(byte4);
    QString ip;
    ip = QString::number(byte1)+"."+QString::number(byte2)+"."+QString::number(byte3)+"."+QString::number(byte4);
    return ip;


}

QString Sniffer::fromUchar(u_char m_uchar)
{

}

void Sniffer::on_actionSniffer_triggered()
{
    ui->stackedWidget->setCurrentIndex(1);
}

void Sniffer::on_actionHome_triggered()
{
    ui->stackedWidget->setCurrentIndex(0);
}

void Sniffer::lookUp()

{

    qDebug()<<minutes;

    if(minutes == 0)
    {
        lookupTimer->deleteLater();
        return;

    }
    else
    {
        minutes = minutes - 1;

    }


    struct pcap_pkthdr hdr;
    ip_header *ih;

    pcap_t *adhandle;
    struct bpf_program fp;
    char filter_exp[] = "port 80";


    const u_char *packet;




    QString dev = ui->devices_comboBox->currentText();
    const char* cd = dev.toLatin1().data();

      if( (adhandle = pcap_open_live(cd,10000,1,200,errbuf)) == NULL)
      {
          qDebug()<<"error opening the device";
          ui->Logdisplayer->append("error opening the device");
          ui->Logdisplayer->append(errbuf);
          printf(errbuf);
          return ;

      }
      else{
      qDebug()<<"DEVICE opened...";
      ui->Logdisplayer->append("DEVICE opened...");

      //we verify if the devices supports link-layer header
      if(pcap_datalink(adhandle) != DLT_EN10MB)
      {
          ui->Logdisplayer->append(QString("Device " + dev + "doesn't provide ethernet headers"));

      }
      else
      {
         ui->Logdisplayer->append(QString("Device<b> " + dev + "</b>provide ethernet headers"));
      }

      if(pcap_compile(adhandle, &fp,filter_exp,0,m_netp)== -1)
      {
          fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(adhandle));
          return ;
      }
      if (pcap_setfilter(adhandle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(adhandle));
      return ;
      }


      packet = pcap_next(adhandle,&hdr);
      if(packet == NULL)
      {
          qDebug()<<"didn't grab the packet";
          ui->Logdisplayer->append("didn't grab the packet");
      }
      else
      {
int length = (bpf_u_int32)hdr.len;
ui->Logdisplayer->append("<font color= red>Grabbed packet of length :</font>"+QString::number(length) );

ui->Logdisplayer->append(QString("received at.....%2").arg(ctime((const time_t*)&hdr.ts.tv_sec)));



//Affichons les addresses ip e depart et d'arrivée

      ih = (ip_header *) (packet +14); //length of ethernet header
         /* print ip addresses and udp ports */
         printf("From: %d.%d.%d.%d -> to :%d.%d.%d.%d\n",
             ih->saddr.byte1,
             ih->saddr.byte2,
             ih->saddr.byte3,
             ih->saddr.byte4,

             ih->daddr.byte1,
             ih->daddr.byte2,
             ih->daddr.byte3,
             ih->daddr.byte4
            );


//

QString sIp = getIp(ih->saddr.byte1,
                  ih->saddr.byte2,
                  ih->saddr.byte3,
                  ih->saddr.byte4);
QString dIp = getIp(ih->daddr.byte1,
                  ih->daddr.byte2,
                  ih->daddr.byte3,
                  ih->daddr.byte4);



addItem( length, QString("at..%2").arg(ctime((const time_t*)&hdr.ts.tv_sec)), sIp, dIp, "", "");
QString str;
u_char proto =ih->proto;
const char cProto =(const char)proto;
str.append(cProto);

qDebug()<<QString(str).toLatin1();

QString pac;
pac.append("<font color = blue>");
for(int i = 0; i < hdr.caplen + 1;i++)
{
              printf("%.2x ", packet[i-1]);
              QString p = getStringFromUnsignedChar(packet, i-1);
              pac.append(p + " ");

              if ( (i % LINE_LEN) == 0) pac.append("\n");
}
pac.append("</font>");
ui->Logdisplayer->append(pac);
ui->Logdisplayer->append("-----------------------------------------------------------------------------------------------------------------");
pcap_close(adhandle);

/* --------------------------------------------------------------*/

      }
      }
}
void Sniffer::getDevAndvancedInfos(pcap_if_t *d)
{
    pcap_addr_t *a;


    cout<<d->name<<":";
    cout<<"\tLoopback: ";
    if((d->flags & PCAP_IF_LOOPBACK) == true)
    {
        cout<<"Yes"<<endl;
    }
    else
    {
        cout<<"No"<<endl;
    }

    u_long ip = ((struct sockaddr_in *)(d->addresses->broadaddr))->sin_addr.S_un.S_addr;
    char *m_ip = iptos(ip);
    cout<<m_ip<<endl;
}

char *Sniffer::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
       static short which;
       u_char *p;

       p = (u_char *)&in;
       which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
       _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
       return output[which];
}

void Sniffer::on_actionExit_triggered()
{
    this->close();
}
