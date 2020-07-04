//#ifndef MAINWINDOW_H
//#define MAINWINDOW_H

#include <QMainWindow>
#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>
#include <winsock.h>
#include <protocol.h>
#include <capthread.h>
#include <QTime>
#include <QTimer>
#include <defence.h>
#include <QCloseEvent>
#include <ws2tcpip.h>
//#include <QValueAxis>
#include <QtCharts>
QT_CHARTS_USE_NAMESPACE

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    int WinPcapInitialized();
    int Packet_Capture();
    void showHexData(u_char*, int len);
    int lines,index_2;
    int deviceCount;
    pcap_if_t *alldevices;
    pcap_if_t *deviceFound;
    pcap_if_t *deviceFoundSel;
    pcap_if_t *deviceFound2;
    pcap_t *capturer; //抓取器
    pcap_t *capturer1; //抓取器
    char errbuf[PCAP_ERRBUF_SIZE];

    int tcpCount;//统计tcp包
    int interface_index;
    int promisc;
    u_int netmask;
    QString ip;
    QString selIP;
    int myIP;
    int i,k,num;
    QString IPexisted;
    int IPexistedNum = 0;
    pktCount *npacket;
    CapThread *capthread;
    datapktVec datapktLink;
    dataVec dataCharLink;
    pcap_dumper_t *dumpfile;
    int RowCount;
    int RowCount_2;
    int Sensitivity;
    QColor mark;
    int listeningPort;
    QTime startTime,stopTime;
    int elapsedTime;
    int rate = 0;
    QString rate1;

    QLineSeries *series0 = new QLineSeries();//绘图部分(折线图)
    QLineSeries *series1 = new QLineSeries();//绘图部分
    QLineSeries *seriesNull = new QLineSeries();//横坐标部分
/*
    QSplineSeries *series0 = new QSplineSeries();//绘图部分(曲线图)
    QSplineSeries *series1 = new QSplineSeries();//绘图部分
    QSplineSeries *seriesNull = new QSplineSeries();//横坐标部分
*/


    int range;//横坐标轴区间
    int Ymax=50;//纵坐标轴区间
    int Ymin=-50;
    int cap_num_in_max=50;
    int cap_num_out_max=50;
    int autoswitch=1;
    //qint64 current_time_total_s = QDateTime::currentSecsSinceEpoch();
    int listlength;
    int totallength = 0;
    int current_sec;
    int round = 0;//自动清空图像计时器
    int pac_num_in= 0;
    int pac_num_out= 0;
    int sec = 0;
    int paint = 0;
    int nCount,nIndex=0,nIndex1=0;
    QTimer *timer = new QTimer(this);

    QValueAxis *axisX = new QValueAxis();//用作X轴
    QValueAxis *axisY = new QValueAxis();//用作Y轴
    QChart *chart = new QChart();

    int pac_count_in[300]={0};//每秒包数 入站数组 初始化全0
    int pac_count_out[300]={0};//每秒包数 出站数组 初始化全0

private slots:
    int on_startButton_released();
    int on_pauseButton_released();
    int StartBtn_feedback();
    void updateTableWidget(QString timestr,  QString srcIP, QString dstIP, QString len, QString protoType);
    void showProtoTree(int row, int column);
    int on_clearButton_released();
    void on_listWidget_doubleClicked(const QModelIndex &index);
    void on_defence_triggered();
    void update(QString src,QString dst);
    void Delay(unsigned int msec); //延时模块
    void on_actionAbout_triggered();
    void on_pushButton_released();

    void update2();//更新出入站统计链表
    void repaint(QLineSeries *series0,QLineSeries *series1,QLineSeries *seriesNull);//重新绘制折线图
    void on_pushButton_3_released();

    void on_pushButton_4_released();

    void on_pushButton_5_released();

    void on_pushButton_7_released();

    void on_pushButton_6_released();

    //void autoclear();

private:
    Ui::MainWindow *ui;



};


//#endif // MAINWINDOW_H
