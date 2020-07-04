#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <vector>
#include <iostream>
#include <QTreeWidgetItem>
#include <QColor>
#include <QDir>
#include <qdebug.h>
#include <QCloseEvent>
#include <QFile>
/*
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
*/
#include <QTime>
#include <ws2tcpip.h>
#include <QtCharts>
//#include <dbghelp.h>

#include <algorithm> //max_element函数需要
#include<iostream>
#include <string.h>
//#include <QValueAxis>
QT_CHARTS_USE_NAMESPACE

using namespace std;
int netDeviceNum = 0;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Evil_Bxxch");
    RowCount =0;
    RowCount_2=0;
    nCount = ui->stackedWidget->count();
//=========================绘图组件初始化
    chart->layout()->setContentsMargins(1, 1, 1, 1);//设置外边界全部为2
    chart->setMargins(QMargins(0, 0, 0, 0));//设置内边界全部为0
    chart->addSeries(series0);
    chart->addSeries(series1);
    chart->addSeries(seriesNull);
    chart->setAxisX(axisX);
    chart->setAxisY(axisY);
    series0->attachAxis(axisX);
    series1->attachAxis(axisX);
    seriesNull->attachAxis(axisX);
    series0->attachAxis(axisY);
    series1->attachAxis(axisY);
    seriesNull->attachAxis(axisY);
//=========================按钮初始化
    ui->pushButton_4->setDisabled(true);//按钮初始化
    ui->pushButton_5->setDisabled(true);
    ui->pushButton_6->setDisabled(true);
    ui->pushButton_7->setDisabled(true);

    //=========抓包列表窗口=====================================
    {
    ui->tableWidget->setColumnCount(6);//6列
    ui->tableWidget_2->setColumnCount(3);//3列
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()
                                               << tr("序号")
                                               << tr("时间")
                                               << tr("源IP地址")
                                               << tr("目的IP地址")
                                               << tr("长度")
                                               << tr("协议类型"));

    ui->tableWidget->setColumnWidth(0, 60);
    ui->tableWidget->setColumnWidth(1, 240);
    ui->tableWidget->setColumnWidth(2, 170);
    ui->tableWidget->setColumnWidth(3, 170);
    ui->tableWidget->setColumnWidth(4, 80);
    ui->tableWidget->setColumnWidth(5, 80);//设置每列宽度
    ui->tableWidget->verticalHeader()->setVisible(false);//隐藏列表头
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);//按行选择
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);//选择单行
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);//禁止修改
    ui->comboBox_2->setCurrentIndex(7);

    connect(ui->tableWidget, SIGNAL(cellPressed(int,int)), this, SLOT(showProtoTree(int,int))); //cellClicked蜜汁失效 ?

    connect(timer, SIGNAL(timeout()), this, SLOT(update2())); //绘图

    ui->tableWidget->verticalHeader()->setVisible(false);    //隐藏列表头


    ui->tableWidget_2->setHorizontalHeaderLabels(QStringList()
                                               << tr("源IP")
                                               << tr("数量")
                                               << tr("频率 包/ s"));
    ui->tableWidget_2->setColumnWidth(0, 126);
    ui->tableWidget_2->setColumnWidth(1, 72);
    ui->tableWidget_2->setColumnWidth(2, 72);
    ui->tableWidget_2->setSelectionBehavior(QAbstractItemView::SelectRows);//按行选择
    ui->tableWidget_2->setSelectionMode(QAbstractItemView::SingleSelection);//选择单行
    ui->tableWidget_2->setEditTriggers(QAbstractItemView::NoEditTriggers);//禁止修改
    ui->tableWidget_2->verticalHeader()->setVisible(false);    //隐藏列表头
    }

    //=========包详细内容窗口===================================
    {
    ui->treeWidget->setColumnCount(1);//1列
    ui->treeWidget->setHeaderLabel(QString("详细内容"));
    ui->treeWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);//充满表宽度
    //ui->treeWidget->header()->setStretchLastSection(false);//关闭自适应宽度
    }

    //=========复选框与下拉列表初始化==================================
    {
    ui->comboBox->setCurrentIndex(0);//设置初始选项
    ui->pauseButton->setEnabled(false);
    ui->comboBox->setView(new QListView());//设置下拉列表子项高度
    ui->comboBox_3->setView(new QListView());
    ui->comboBox_4->setView(new QListView());
                                           //右键ui中的comboBox设置样式表修改样式
    //=========获取设备列表=========================================
    ui->comboBox->addItem(tr("请选择一个网卡接口(必选)").trimmed());//trimmed()修减字符串左右空白部分
    ui->checkBox->setChecked(true);
    //=========接口程序初始化==================================
    {


    if(WinPcapInitialized() < 0)
        {
    QMessageBox::warning(this, tr("Wrong!"), tr("无法获取网络适配器,请检查驱动程序"), QMessageBox::Ok);
        }
    }

    }
    //=========复选框设备列表==================================
    int i = 1;
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
    char ip6str[128];
    for(deviceFound=alldevices; deviceFound !=NULL ; deviceFound=deviceFound->next,i=i+1)//第一个分号前的内容是执行第一次循环前执行的，第二个分号前的内容是每次执行前都要判断的（如果该处表达式的值为真，那么执行循环体，如果为假，那么就跳出循环体），第二个分号后的内容是每执行完一次循环体后执行的
    {
            ui->comboBox->addItem(QString("%1:""%2").arg(i).arg(deviceFound->description).replace("Network adapter ",""));
            //在复选框中列出网络设备
//=========左侧网卡列表==================================
            QString des=deviceFound->description;
            capturer1 = pcap_open_live(deviceFound->name,65536,1,500,errbuf);
        //=========逐位获取设备ip地址==================================
                for (pcap_addr_t *tmp=deviceFound->addresses;tmp != NULL ; tmp=tmp->next) //逐位计算ip数值
                    {
                            if (tmp->addr->sa_family == AF_INET)
                            {
                                if (tmp->addr)
                                {
                                ip=inet_ntoa(((sockaddr_in*)tmp->addr)->sin_addr);
                                }
                                else ip="0.0.0.0";
                            }
                            else if (tmp->addr->sa_family == AF_INET6)
                            {
                                if (tmp->addr)
                                //ip="使用IPv6的设备"; //问题1：使用ipv6设备的地址读取
                                ip=QString(" (IPv6) ")+QString(ip6tos(tmp->addr, ip6str, sizeof(ip6str)));

                            }
                            else if (tmp->addr->sa_family == AF_UNSPEC)
                                ip="未指定协议族";
                     }
        //=========无地址置零==================================
                if(deviceFound->addresses == NULL)
                {
                ip="0.0.0.2";
                }
        //=========左侧列表列出地址等信息==================================
            ui->listWidget->insertItem(i
                                        ,QString(" %1:""%2\n""IP:%3\n" )
                                        .arg(i)
                                        .arg(des).replace("Network adapter ","")
                                        .arg(ip)
                                        //.arg(type)
                                        );
    }






    npacket = (pktCount *)malloc(sizeof(pktCount));//????
    capthread = NULL;


}

    //=========开始抓包按钮=====================================
int MainWindow::on_startButton_released()
{
    std::vector<datapkt *>::iterator it;
    for(it = datapktLink.begin(); it != datapktLink.end(); it++)
    {
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++)
    {
        free(*kt);
    }
    datapktVec().swap(datapktLink);
    dataVec().swap(dataCharLink);

    ui->treeWidget->clear();
    ui->textBrowser->clear();
    ui->comboBox->setEnabled(false);

    if(capthread != NULL)
    {
        delete capthread;
        capthread = NULL;
    }

    if(alldevices == NULL){
        if(WinPcapInitialized() < 0)
        {
            QMessageBox::warning(this, tr("Sniffer"), tr("无法获取适配器接口"), QMessageBox::Ok);
            return -1;
        }
    }

    memset(npacket, 0, sizeof(struct _pktCount));


    //==================================================

    //==========未出错执行=======================================

    if(StartBtn_feedback()<0)
    {
        return -1;
    }
    //==================================================
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    ui->startButton->setEnabled(false);
    ui->checkBox->setDisabled(true);
    //selIP = "0.0.0.0";
    netmask = 0;

    /*
    //==============数据库(弃用)=====================
    {
        QSqlDatabase database;
        if (QSqlDatabase::contains("qt_sql_default_connection"))
        {
            database = QSqlDatabase::database("qt_sql_default_connection"); //连接数据库
        }
        else
        {
            database = QSqlDatabase::addDatabase("QSQLITE"); //创建数据库
            database.setDatabaseName("MyDataBase.db");
            database.setUserName("FireWall");
            database.setPassword("123456");
        }
        qDebug() << "Creating" << endl;

        if (!database.open()) //打开数据库
        {
            qDebug() << "Error: Failed to connect database." << database.lastError();
        }
        else
        {
            qDebug() << "Opening" << endl;
            QSqlQuery sql_query;
            QString create_sql = "create table srcip (id int primary key, ip int)"; //创建表
            sql_query.prepare(create_sql);

            if(!sql_query.exec())
            {
                qDebug() << "Error: Fail to create table." << sql_query.lastError()<<endl;
            }
            else
            {
                qDebug() << "Table created!"<<endl;
            }
        }
    }
    */
    return 0;
}

int MainWindow::on_pauseButton_released()
{
    //sec =0;//绘图计时器归零
    //qDebug() << "pause" << endl;
    ui->startButton->setEnabled(true);
    ui->checkBox->setEnabled(true);
    ui->pauseButton->setEnabled(false);
    capthread->stop();//结束进程
    pcap_close(capturer);//关闭winpcap会话句柄，并释放其资源
    timer->stop();//绘图停止
    ui->comboBox->setEnabled(true);
    ui->graphicsView->clearMask();
    /*
    series0->clear();//图表清空
    series1->clear();//图表清空
    seriesNull->clear();//图表清空
    */
    return 0;
}

    //=========winpcap初始化====================================
int MainWindow::WinPcapInitialized()
{
    deviceCount = 0;
    if(pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevices, errbuf) == -1)
        return -1;//alldevice是winpcap抓取到的网卡
                        //if语句的条件在判断时会被执行
    for(deviceFound = alldevices; deviceFound; deviceFound = deviceFound->next)
    {
        deviceCount++;  //计算链表alldevices的节点个数
        return 0;
    }

    return 0;

}

    //=========================================================
MainWindow::~MainWindow()
{
    delete ui;
}

    //=========抓包主程序=========================================
int MainWindow::Packet_Capture()
{
    //=========根据复选框对网卡设备进行选择=========================================
{
    int interface_index = 0;
    //deviceFoundSel = alldevices;
    interface_index = ui->comboBox->currentIndex();
    for(deviceFoundSel = alldevices,num = 0; num < interface_index - 1; num++)
    {
        deviceFoundSel = deviceFoundSel->next; //在链表中遍历到所选的网卡设备
    }

}

    //========混杂模式=======================================
        if(ui->checkBox->isChecked()==true)
        {
            promisc=1;
        }
        else promisc=0;

    //=========抓取器=========================================
    capturer = pcap_open_live(deviceFoundSel->name,65536,promisc,500,errbuf);
                            //设备名,抓取的数据包长度,混杂模式,超时设置,错误缓冲器
    //=========错误反馈=========================================
    {
    if (capturer == NULL)
    {
        QMessageBox::warning(this,"Wrong!",tr("无法打开设备接口"),QMessageBox::Ok);
        pcap_freealldevs(alldevices);//释放全部设备
        alldevices = NULL;//指针指向空，重新初始化
        return -1;//返回错误
    }
    if(pcap_datalink(capturer) != DLT_EN10MB) //只支持以太网
    {
        QMessageBox::warning(this,"Wrong!",tr("请接入以太网或安装Winpcap驱动"),QMessageBox::Ok);
        pcap_freealldevs(alldevices);//释放所有设备
        alldevices = NULL;
        return -1;
    }
    }

    //=========获取所选设备地址=========================================
    if(deviceFoundSel->addresses != NULL)//如果接口没有地址，假设它在C类网络中
    {
        netmask = ((struct sockaddr_in *)(deviceFoundSel->addresses->netmask))->sin_addr.S_un.S_addr;
        //=========逐位获取地址=========================================
        for (pcap_addr_t *tmp=deviceFoundSel->addresses;tmp != NULL ; tmp=tmp->next)
            {
                    if (tmp->addr->sa_family == AF_INET)
                    {
                        if (tmp->addr)
                        {
                        selIP=inet_ntoa(((sockaddr_in*)tmp->addr)->sin_addr);
                        }
                        else selIP="0.0.0.0";
                    }
                    else selIP="0.0.0.0";
             }
    }
    if(deviceFoundSel->addresses == NULL)
    {
        netmask = 0xffffff; //255.255.255.0,C类地址子网掩码
        selIP="0.0.0.0";
    }

    pcap_freealldevs(alldevices);
    alldevices = NULL;

    capthread = new CapThread(capturer, npacket, datapktLink, dataCharLink, dumpfile);
    connect(capthread, SIGNAL(addOneCaptureLine(QString,QString,QString,QString,QString)), this, SLOT(updateTableWidget(QString,QString,QString,QString,QString)));
    capthread->start();
    return 1;

}

int MainWindow::StartBtn_feedback()
{
        //==========开始按钮反馈=====================================
        int interface_index = ui->comboBox->currentIndex();
        //==========错误反馈=====================================
        if(interface_index == 0)//未选择时错误反馈
                {
                QMessageBox::warning(this, "Wrong!", tr("未选择网卡设备！"), QMessageBox::Ok);
                ui->startButton->setEnabled(true);
                ui->checkBox->setEnabled(true);
                ui->comboBox->setEnabled(true);
                return -1;
                }

        //==========未出错执行=======================================
        if(interface_index != 0)
           {
                ui->pauseButton->setEnabled(true);
                //ui->listWidget->clear();//清空适配器列表
                timer->start(1000);//单位ms，定时1s
                tcpCount = 0 ;
                if(Packet_Capture() < 0 )
                {
                    return -1;//返回状态值
                }
           }

}

//================================================================

//void MainWindow::updateTableWidget(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP)
void MainWindow::updateTableWidget(QString timestr, QString srcIP, QString dstIP, QString len, QString protoType)
{
    int listeningPort = (ui->lineEdit->text()).toInt();
    RowCount = ui->tableWidget->rowCount();
    RowCount_2 = ui->tableWidget_2->rowCount();
    ui->tableWidget->insertRow(RowCount);
    QString orderNumber = QString::number(RowCount+1, 10); //序号，十进制数
    ui->tableWidget->setItem(RowCount, 0, new QTableWidgetItem(orderNumber)); //序号
        ui->tableWidget->item(RowCount,0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);//居中
    ui->tableWidget->setItem(RowCount, 1, new QTableWidgetItem(timestr)); //时间
        ui->tableWidget->item(RowCount,1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    ui->tableWidget->setItem(RowCount, 2, new QTableWidgetItem(srcIP)); //源ip
        ui->tableWidget->item(RowCount,2)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    ui->tableWidget->setItem(RowCount, 3, new QTableWidgetItem(dstIP)); //目的ip
        ui->tableWidget->item(RowCount,3)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    ui->tableWidget->setItem(RowCount, 4, new QTableWidgetItem(len)); //长度
        ui->tableWidget->item(RowCount,4)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    ui->tableWidget->setItem(RowCount, 5, new QTableWidgetItem(protoType)); //协议类型
        ui->tableWidget->item(RowCount,5)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);

        datapktLink[RowCount]->iph->proto;
//=========数据库部分=============================
/*
        QSqlQuery sql_query;
        QString insert_sql = "insert into srcip values (?,?)";
        sql_query.prepare(insert_sql);

            if(protoType == "TCP")
            {
                if(dstIP == selIP)
                {
                    {
                        databaseCount = databaseCount + 1 ;
                        ui->tableWidget_2->insertRow(RowCount_2);
                        ui->tableWidget_2->setItem(RowCount_2, 0, new QTableWidgetItem(srcIP)); //源ip
                        ui->tableWidget_2->setItem(RowCount_2, 1, new QTableWidgetItem(QString::number(RowCount_2))); //数量
                        ui->tableWidget_2->item(RowCount_2,0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                        sql_query.addBindValue(databaseCount-1);
                        sql_query.addBindValue(srcIP);
                    }
                    if(sql_query.exec());
                        {
                         qDebug() << sql_query.lastError();
                        }
                }
            }
*/

        if(ui->comboBox_3->currentIndex()==4)
            Sensitivity=3;
        else if (ui->comboBox_3->currentIndex()==3)
            Sensitivity=10;
        else if (ui->comboBox_3->currentIndex()==2)
            Sensitivity=20;
        else if (ui->comboBox_3->currentIndex()==1)
            Sensitivity=50;
        else if (ui->comboBox_3->currentIndex()==0)
            Sensitivity=100;

//===================所有包出入站统计=================
        if(dstIP==selIP)
        {
            ++pac_num_in;
        }
        else if(srcIP==selIP)
        {
            ++pac_num_out;
        }

//===================仅tcp/udp包入站统计=============
{
    if(protoType == "TCP" )
    {
        if(ui->lineEdit->text()!=NULL)
        {
            if(datapktLink[RowCount]->tcph->destPort == listeningPort)
            {
                QString src = srcIP;
                QString dst = dstIP;
                update(src,dst);
            }
        }
        else
            {
                QString src = srcIP;
                QString dst = dstIP;
                update(src,dst);
            }
    }

    else if(protoType == "UDP" )
    {
        if(ui->lineEdit->text()!=NULL)
        {
            if(datapktLink[RowCount]->udph->dport == listeningPort)
            {
                QString src = srcIP;
                QString dst = dstIP;
                update(src,dst);
            }
        }
        else
            {
                QString src = srcIP;
                QString dst = dstIP;
                update(src,dst);
            }
    }

}

        //===保持最新====

    if (RowCount_2 > 1)
    {       
        if(ui->checkBox_3->isChecked()==true)
        //if(RowCount%5 == 0 )
        {
        ui->tableWidget_2->scrollToItem(ui->tableWidget_2->item(RowCount_2, 0), QAbstractItemView::PositionAtBottom);
        }
    }


//===============================================


if(ui->checkBox_2->isChecked()==true) //自动刷新包列表
    {
        if(RowCount > 1)
        {
            index_2 = ui->comboBox_2->currentIndex();

            if (index_2 == 0)
            {
                lines=10;
            }
            else if(index_2==1)
            {
                lines=50;
            }
            else if(index_2==2)
            {
                lines=100;
            }
            else if(index_2==3)
            {
                lines=200;
            }
            else if(index_2==4)
            {
                lines=500;
            }
            else if(index_2==5)
            {
                lines=1000;
            }
            else if(index_2==6)
            {
                lines=5000;
            }
            else if(index_2==7)
            {
                lines=10000;
            }

            if(RowCount%lines == 0 )
            {
                ui->tableWidget->scrollToItem(ui->tableWidget->item(RowCount, 0), QAbstractItemView::PositionAtBottom);//设置滚动条位置
            }

        }

    }


    QColor color;
    if(protoType == "TCP" || protoType == "HTTP"){
        color = QColor(228,255,199);
    }
    else if(protoType == "UDP"){
        color = QColor(218,238,255);
    }
    else if(protoType == "ARP"){
        color = QColor(250,240,215);
    }
    else if(protoType == "ICMP"){
        color = QColor(252,224,255);
    }
    for(int i = 0; i < 6 ; i ++){
        ui->tableWidget->item(RowCount,i)->setBackgroundColor(color);
    }



    if(RowCount == 100000) //10万条包自动刷新
    {

        if(on_clearButton_released())
        {
            return;
        }
    }


}

void MainWindow::showProtoTree(int row, int column)
{
    //清空控件中的内容
    ui->treeWidget->clear();
    ui->textBrowser->clear();

    struct _datapkt *mem_data = (struct _datapkt *)datapktLink[row];
    //在编辑栏中要显示的数据包内容
    u_char *print_data = (u_char *)dataCharLink[row];
    int print_len = mem_data->len;
    showHexData(print_data, print_len);

    QString showStr;
    char buf[100];
    sprintf(buf, "接收到的第%d个数据包", row + 1);
    showStr = QString(buf);

    QTreeWidgetItem *root = new QTreeWidgetItem(ui->treeWidget);
    root->setText(0, showStr);


    //处理帧数据
    showStr = QString("链路层数据");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    root->setExpanded(true);
    level1->setText(0, showStr);
    level1->setExpanded(true);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->src[0], mem_data->ethh->src[1],
            mem_data->ethh->src[2], mem_data->ethh->src[3], mem_data->ethh->src[4], mem_data->ethh->src[5]);
    showStr = "源MAC: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->dest[0], mem_data->ethh->dest[1],
            mem_data->ethh->dest[2], mem_data->ethh->dest[3], mem_data->ethh->dest[4], mem_data->ethh->dest[5]);
    showStr = "目的MAC: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, showStr);

    sprintf(buf, "%04x", mem_data->ethh->type);
    showStr = "类型:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, showStr);

    //处理IP,ARP类型的数据包
    if(mem_data->ethh->type == 0x0806)      //ARP
    {
        //添加ARP协议头
        showStr = QString("ARP协议头");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        root->setExpanded(true);
        level2->setText(0, showStr);
        level2->setExpanded(true);

        sprintf(buf, "硬件类型: 0x%04x", mem_data->arph->htype);
        showStr = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, showStr);

        sprintf(buf, "协议类型: 0x%04x", mem_data->arph->prtype);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, showStr);

        sprintf(buf, "硬件地址长度: %d", mem_data->arph->hsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, showStr);

        sprintf(buf, "协议地址长度: %d", mem_data->arph->prsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, showStr);

        sprintf(buf, "操作码: %d", mem_data->arph->opcode);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arph->senderMac[0], mem_data->arph->senderMac[1],
                mem_data->arph->senderMac[2], mem_data->arph->senderMac[3], mem_data->arph->senderMac[4], mem_data->arph->senderMac[5]);
        showStr = "发送方MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->senderIp[0], mem_data->arph->senderIp[1], mem_data->arph->senderIp[2]
                ,mem_data->arph->senderIp[3]);
        showStr = "发送方IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arph->destMac[0], mem_data->arph->destMac[1],
                mem_data->arph->destMac[2], mem_data->arph->destMac[3], mem_data->arph->destMac[4], mem_data->arph->destMac[5]);
        showStr = "接收方MAC: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->destIp[0], mem_data->arph->destIp[1], mem_data->arph->destIp[2]
                ,mem_data->arph->destIp[3]);
        showStr = "接收方IP: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, showStr);
    }
    else if(mem_data->ethh->type == 0x0800)     //IP
    {
        //添加IP协议头
        showStr = QString("IP协议头");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, showStr);

        sprintf(buf, "版本: %d", IP_V(mem_data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, showStr);

        sprintf(buf, "IP首部长度: %d", IP_HL(mem_data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, showStr);

        sprintf(buf, "服务类型: %d", mem_data->iph->tos);
        showStr = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, showStr);

        sprintf(buf, "总长度: %d", mem_data->iph->ip_len);
        showStr = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, showStr);

        sprintf(buf, "标识: 0x%04x", mem_data->iph->identification);
        showStr = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, showStr);

        sprintf(buf, "标志(Reserved Fragment Flag): %d", (mem_data->iph->flags_fo & IP_RF) >> 15);
        showStr = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, showStr);

        sprintf(buf, "标志(Don't fragment Flag): %d", (mem_data->iph->flags_fo & IP_DF) >> 14);
        showStr = QString(buf);
        QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
        flag1->setText(0, showStr);

        sprintf(buf, "标志(More Fragment Flag): %d", (mem_data->iph->flags_fo & IP_MF) >> 13);
        showStr = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, showStr);

        sprintf(buf, "段偏移: %d", mem_data->iph->flags_fo & IP_OFFMASK);
        showStr = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, showStr);

        sprintf(buf, "生存期: %d", mem_data->iph->ttl);
        showStr = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, showStr);

        sprintf(buf, "协议: %d", mem_data->iph->proto);
        showStr = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, showStr);

        sprintf(buf, "首部校验和: 0x%04x", mem_data->iph->hchecksum);
        showStr = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->saddr[0], mem_data->iph->saddr[1], mem_data->iph->saddr[2]
                ,mem_data->iph->saddr[3]);
        showStr = "源IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->daddr[0], mem_data->iph->daddr[1], mem_data->iph->daddr[2]
                ,mem_data->iph->daddr[3]);
        showStr = "目的IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, showStr);

        //处理传输层udp, icmp, tcp
        if(mem_data->iph->proto == PROTO_ICMP)  //ICMP协议
        {
            //添加ICMP协议头
            showStr = QString("ICMP协议头");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            root->setExpanded(true);
            level4->setText(0, showStr);
            level4->setExpanded(true);

            sprintf(buf, "类型: %d", mem_data->icmph->type);
            showStr = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, showStr);

            sprintf(buf, "代码: %d", mem_data->icmph->code);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->icmph->chk_sum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, showStr);

            sprintf(buf, "标识: 0x%04x", mem_data->icmph->identification);
            showStr = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, showStr);

            sprintf(buf, "序列号: 0x%04x", mem_data->icmph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, showStr);
        }
        else if(mem_data->iph->proto == PROTO_TCP)  //TCP协议
        {
            showStr = QString("TCP协议头");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            root->setExpanded(true);
            level5->setText(0, showStr);
            level5->setExpanded(true);

            sprintf(buf, "源端口: %d", mem_data->tcph->srcPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->tcph->destPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "序列号: 0x%08x", mem_data->tcph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "确认号: 0x%08x", mem_data->tcph->ack_sql);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, showStr);

            sprintf(buf, "首部长度: %d bytes (%d)", TH_OFF(mem_data->tcph) * 4, TH_OFF(mem_data->tcph));
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", mem_data->tcph->th_flags);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, showStr);

            sprintf(buf, "CWR: %d", (mem_data->tcph->th_flags & TH_CWR) >> 7);
            showStr = QString(buf);
            QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
            cwrflag->setText(0, showStr);

            sprintf(buf, "ECE: %d", (mem_data->tcph->th_flags & TH_ECE) >> 6);
            showStr = QString(buf);
            QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
            eceflag->setText(0, showStr);

            sprintf(buf, "URG: %d", (mem_data->tcph->th_flags & TH_URG) >> 5);
            showStr = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, showStr);

            sprintf(buf, "ACK: %d", (mem_data->tcph->th_flags & TH_ACK) >> 4);
            showStr = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, showStr);

            sprintf(buf, "PUSH: %d", (mem_data->tcph->th_flags & TH_PUSH) >> 3);
            showStr = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, showStr);

            sprintf(buf, "RST: %d", (mem_data->tcph->th_flags & TH_RST) >> 2);
            showStr = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, showStr);

            sprintf(buf, "SYN: %d", (mem_data->tcph->th_flags & TH_SYN) >> 1);
            showStr = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, showStr);

            sprintf(buf, "FIN: %d", (mem_data->tcph->th_flags & TH_FIN));
            showStr = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, showStr);

            sprintf(buf, "窗口大小: %d", mem_data->tcph->wnd_size);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->tcph->checksum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "紧急指针: %d", mem_data->tcph->urg_ptr);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, showStr);

            if(mem_data->isHttp == true)
            {
                showStr = QString("HTTP协议头");
                QTreeWidgetItem *level8 = new QTreeWidgetItem(root);
                root->setExpanded(true);
                level8->setText(0, showStr);
                level8->setExpanded(true);

                QString content = "";
                u_char *httpps = mem_data->apph;

                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content)));
                            level8->addChild(new QTreeWidgetItem(level8,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a){
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += httpps2[i];
                }
                level8->addChild(new QTreeWidgetItem(level8,QStringList("(Data)(Data)")));
            }
        }
        else if(mem_data->iph->proto == PROTO_UDP)  //UDP协议
        {
            //添加UDP协议头
            showStr = QString("UDP协议头");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            root->setExpanded(true);
            level6->setText(0, showStr);
            level6->setExpanded(true); //展开部分子项

            sprintf(buf, "源端口: %d", mem_data->udph->sport);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->udph->dport);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "总长度: %d", mem_data->udph->len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->udph->crc);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, showStr);
        }
    }

//ui->treeWidget->expandAll();

}

void MainWindow::showHexData(u_char *print_data, int print_len) //采用了html标签，所以空格等字符都用html语言表示
{
    QString tempnum,tempchar;
    QString oneline;
    int i,line;
    tempchar = "<font>&nbsp;</font>";
    oneline = "<font></font>";
    for(i = 0 ; i < print_len ; i ++)
    {
        if(i % 16 == 0)//输出行号，每行16个字符
        {
            oneline += tempnum.sprintf("<font>%04x&nbsp;</font>",i);//十六进制行号
        }

        if(print_data[23]==17)//UDP
        {
                if(i>=0 && i<6)//显示dest MAC
                {
                oneline += tempnum.sprintf("<font color=blue>%02x </font>",print_data[i]);
                }
                else if(i>=6 && i<12 )//显示src MAC
                {
                oneline += tempnum.sprintf("<font color=green>%02x </font>",print_data[i]);
                }
                else if(i>=12 && i<14)//显示协议类型ipv4/6
                {
                oneline += tempnum.sprintf("<font color=brown>%02x </font>",print_data[i]);
                }
                else if(i>=26 && i<30)//显示src IP
                {
                oneline += tempnum.sprintf("<font color=DarkMagenta>%02x </font>",print_data[i]);
                }
                else if(i>=30 && i<34)//显示dst IP
                {
                oneline += tempnum.sprintf("<font color=DarkTurquoise>%02x </font>",print_data[i]);
                }
                else if(i>=34 && i< 36)//显示src Port
                {
                oneline += tempnum.sprintf("<font color=GreenYellow>%02x </font>",print_data[i]);
                }
                else if(i>=36 && i<38)//显示dst Port
                {
                oneline += tempnum.sprintf("<font color=DarkSlateBlue>%02x </font>",print_data[i]);
                }
                else if(i>=42)//显示包的数据段
                {
                oneline += tempnum.sprintf("<font color=red>%02x </font>",print_data[i]);
                }
                else
                {
                oneline += tempnum.sprintf("<font>%02x </font>",print_data[i]);
                }
        }

        else if(print_data[23]==6)//TCP
        {
                if(i>=0 && i<6)//显示dest MAC
                {
                oneline += tempnum.sprintf("<font color=blue>%02x </font>",print_data[i]);
                }
                else if(i>=6 && i<12 )//显示src MAC
                {
                oneline += tempnum.sprintf("<font color=green>%02x </font>",print_data[i]);
                }
                else if(i>=12 && i<14)//显示协议类型ipv4/6
                {
                oneline += tempnum.sprintf("<font color=brown>%02x </font>",print_data[i]);
                }
                else if(i>=26 && i<30)//显示src IP
                {
                oneline += tempnum.sprintf("<font color=DarkMagenta>%02x </font>",print_data[i]);
                }
                else if(i>=30 && i<34)//显示dst IP
                {
                oneline += tempnum.sprintf("<font color=DarkTurquoise>%02x </font>",print_data[i]);
                }
                else if(i>=34 && i<36)//显示src Port
                {
                oneline += tempnum.sprintf("<font color=GreenYellow>%02x </font>",print_data[i]);
                }
                else if(i>=36 && i<38)//显示dst Port
                {
                oneline += tempnum.sprintf("<font color=DarkSlateBlue>%02x </font>",print_data[i]);
                }
                else if(i>=54)//显示包的数据段
                {
                oneline += tempnum.sprintf("<font color=red>%02x </font>",print_data[i]);
                }
                else
                {
                oneline += tempnum.sprintf("<font>%02x </font>",print_data[i]);
                }
        }

        else //其他类型
        {
        oneline += tempnum.sprintf("<font>%02x </font>",print_data[i]);
        }

        if(isprint(print_data[i])) //判断是否为可打印字符
        {
            QString t(print_data[i]);
            //===========
            if(print_data[23]==17)//UDP
            {
                if(i>=0 && i<6)//显示dest MAC
                {
                tempchar += QString("<font color=blue>%1</font>").arg(t);
                }
                else if(i>=6 && i<12 )//显示src MAC
                {
                tempchar += QString("<font color=green>%1</font>").arg(t);
                }
                else if(i>=12 && i<14)//显示协议类型ipv4/6
                {
                tempchar += QString("<font color=brown>%1</font>").arg(t);
                }
                else if(i>=26 && i<30)//显示src IP
                {
                tempchar += QString("<font color=DarkMagenta>%1</font>").arg(t);
                }
                else if(i>=30 && i<34)//显示dst IP
                {
                tempchar += QString("<font color=DarkTurquoise>%1</font>").arg(t);
                }
                else if(i>=34 && i<36)//显示src Port
                {
                tempchar += QString("<font color=GreenYellow>%1</font>").arg(t);
                }
                else if(i>=36 && i<38)//显示dst Port
                {
                tempchar += QString("<font color=DarkSlateBlue>%1</font>").arg(t);
                }
                else if(i>=42)//显示包的数据段
                {
                tempchar += QString("<font color=red>%1</font>").arg(t);
                }
                else
                {
                tempchar += QString("<font>%1</font>").arg(t);
                }
            }

            else if(print_data[23]==6)//TCP
            {
                    if(i>=0 && i<6)//显示dest MAC
                    {
                    tempchar += QString("<font color=blue>%1</font>").arg(t);
                    }
                    else if(i>=6 && i<12 )//显示src MAC
                    {
                    tempchar += QString("<font color=green>%1</font>").arg(t);
                    }
                    else if(i>=12 && i<14)//显示协议类型ipv4/6
                    {
                    tempchar += QString("<font color=brown>%1</font>").arg(t);
                    }
                    else if(i>=26 && i<30)//显示src IP
                    {
                    tempchar += QString("<font color=DarkMagenta>%1</font>").arg(t);
                    }
                    else if(i>=30 && i<34)//显示dst IP
                    {
                    tempchar += QString("<font color=DarkTurquoise>%1</font>").arg(t);
                    }
                    else if(i>=34 && i<36)//显示src Port
                    {
                    tempchar += QString("<font color=GreenYellow>%1</font>").arg(t);
                    }
                    else if(i>=36 && i<38)//显示dst Port
                    {
                    tempchar += QString("<font color=DarkSlateBlue>%1</font>").arg(t);
                    }
                    else if(i>=54)//显示包的数据段
                    {
                    tempchar += QString("<font color=red>%1</font>").arg(t);
                    }
                    else
                    {
                    tempchar += QString("<font>%1</font>").arg(t);
                    }
            }

            else //其他类型
            {
            tempchar += QString("<font>%1</font>").arg(t);
            }
            //===========

        }
        else
        {
            tempchar += "<font>.</font>";
        }

        if((i+1)%16 == 0) //分界空格
        {
            ui->textBrowser->append(oneline+tempchar);
            tempchar = "<font>&nbsp;</font>";
            oneline = "<font></font>";
        }
    }



    if(print_data[23]==6||17)
    {
        line=16*((i/16)+1);//求出行数
        for(i; i <  line ; i ++) //补全缺少的部分
        {
            oneline += "<font>.. </font>";
        }
        ui->textBrowser->append(oneline+tempchar);
    }
    else
    {
        i %= 16;
        for(; i < 16 ; i ++) //补全缺少的部分
        {
            oneline += "<font>   </font>";
        }
        ui->textBrowser->append(oneline+tempchar);
    }

    ui->textBrowser->moveCursor(QTextCursor::Start); //保持滚动条顶部

}

int MainWindow::on_clearButton_released()
{
    listlength=ui->tableWidget->rowCount();//当前列表长度（条数）
    totallength=totallength+listlength;//总条数
    ui->tableWidget->clearContents();//清空tablewidget 不包括表头
    ui->treeWidget->clear();
    ui->textBrowser->clear();
    if(ui->pauseButton->isEnabled())
        {
            on_pauseButton_released();
            ui->startButton->setEnabled(false);
            ui->comboBox->setEnabled(false);
            ui->checkBox->setDisabled(true);
            Delay(1000);//重启间隔1s
            on_startButton_released();
        }
    else
        {
            on_startButton_released();
        }
    return 0;
}

void MainWindow::on_listWidget_doubleClicked(const QModelIndex &index)
{
      int selectedRow = ui->listWidget->currentRow();
      ui->comboBox->setCurrentIndex(selectedRow+1);
}

void MainWindow::on_defence_triggered()
{
    defence defender; //打开子窗口
    defender.show();
    defender.exec();
}

void MainWindow::update(QString src,QString dst) //右侧列表包统计与更新
{
    if(dst == selIP)
    {
    //qDebug()<<dst<<" "<<src<<endl; //这句话有bug，只有这句qDebug被if判断执行了，后面的部分全部直接执行了，要在括号里 :)
    if(ui->tableWidget_2->item(RowCount_2,0)==NULL)
        {
        if(RowCount_2>=1) //若列表有至少一个项目
            {
            if(src!=ui->tableWidget_2->item(RowCount_2-1,0)->text()) //当获得的源地址是新的地址
            {
                startTime = QTime::currentTime(); //新源地址计时

                if((ui->tableWidget_2->item(RowCount_2-1,1)->text()).toInt()<=Sensitivity) //判断若上一行数量过小，替换之
                {
                    ui->tableWidget_2->setItem(RowCount_2-1, 0, new QTableWidgetItem(src)); //源ip
                    ui->tableWidget_2->setItem(RowCount_2-1, 1, new QTableWidgetItem(QString::number(1))); //数量
                    ui->tableWidget_2->setItem(RowCount_2-1, 2, new QTableWidgetItem(rate1)); //频率
                    for(int i = 0; i < 3 ; i ++)
                    {
                        ui->tableWidget_2->item(RowCount_2-1,i)->setBackgroundColor(QColor (228,255,199));
                        ui->tableWidget_2->item(RowCount_2-1,i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                    }
                }

                if((ui->tableWidget_2->item(RowCount_2-1,1)->text()).toInt() > Sensitivity
                        && ((ui->tableWidget_2->item(RowCount_2-1,1)->text()).toInt()<=5000))

                { //若上一行数量足够大但不足5000，新开一行
                    ui->tableWidget_2->insertRow(RowCount_2);
                    ui->tableWidget_2->setItem(RowCount_2, 0, new QTableWidgetItem(src)); //源ip
                    ui->tableWidget_2->setItem(RowCount_2, 1, new QTableWidgetItem(QString::number(1))); //数量
                    ui->tableWidget_2->setItem(RowCount_2, 2, new QTableWidgetItem(rate1)); //频率
                    for(int i = 0; i < 3 ; i ++)
                    {
                        ui->tableWidget_2->item(RowCount_2,i)->setBackgroundColor(QColor (228,255,199));
                        ui->tableWidget_2->item(RowCount_2,i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                    }

                }

            }
            else //若是相同的源地址，上一行的包数量+1
            {
                QTime stopTime = QTime::currentTime();
                elapsedTime = startTime.msecsTo(stopTime)+1; //持续时间
                int num=(ui->tableWidget_2->item(RowCount_2-1,1)->text()).toInt();
                rate = ((num+1)*1000 / elapsedTime); //包每秒
                rate1=QString::number(rate);
                //=============================
                if (num<100)
                    {
                        rate1="Safe";
                        mark=QColor (228,255,199);
                    }

                else
                    {
                        if (rate>=1000 && num>1000)
                        {
                            mark=QColor(255,100,100);
                        }
                        else if ((rate<1000 && rate>=100) || ( rate>=1000 && num>=100 && num<=1000))
                        {
                            mark=QColor(255,255,60);
                        }
                        else if ((rate<100 && rate>=0) || ( num < 100))
                        {
                            mark=QColor (228,255,199);
                        }
                    }
                        //=============================

                ui->tableWidget_2->setItem(RowCount_2-1, 1, new QTableWidgetItem(QString::number(num+1)));
                ui->tableWidget_2->item(RowCount_2-1,0)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                ui->tableWidget_2->item(RowCount_2-1,1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                ui->tableWidget_2->setItem(RowCount_2-1, 2, new QTableWidgetItem(rate1)); //频率
                ui->tableWidget_2->item(RowCount_2-1,2)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);


                for(int i = 0; i < 3 ; i ++) //整行上色
                {
                    ui->tableWidget_2->item(RowCount_2-1,i)->setBackgroundColor(mark);
                }

                if (num > 4999) //若上一行数量足够大且超过5000，新开一行
                {
                    startTime = QTime::currentTime();//新计数行计时
                    ui->tableWidget_2->insertRow(RowCount_2);
                    ui->tableWidget_2->setItem(RowCount_2, 0, new QTableWidgetItem(src)); //源ip
                    ui->tableWidget_2->setItem(RowCount_2, 1, new QTableWidgetItem(QString::number(1))); //数量
                    ui->tableWidget_2->setItem(RowCount_2, 2, new QTableWidgetItem(rate1)); //频率
                    for(int i = 0; i < 3 ; i ++)
                    {
                        ui->tableWidget_2->item(RowCount_2,i)->setBackgroundColor(QColor (228,255,199));
                        ui->tableWidget_2->item(RowCount_2,i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
                    }
                }
            }
            }
        else //若列表没有项目，创建一个
        {
            startTime = QTime::currentTime();//初始化项目计时
            ui->tableWidget_2->insertRow(0);
            ui->tableWidget_2->setItem(0, 0, new QTableWidgetItem(src)); //源ip
            ui->tableWidget_2->setItem(0, 1, new QTableWidgetItem(QString::number(1))); //数量
            ui->tableWidget_2->setItem(0, 2, new QTableWidgetItem("Safe")); //频率

            for(int i = 0; i < 3 ; i ++)
            {
                ui->tableWidget_2->item(0,i)->setBackgroundColor(QColor (228,255,199));
                ui->tableWidget_2->item(0,i)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
            }
        }
        }
    }
}

void MainWindow::Delay(unsigned int msec) //延时模块
{
    QTime t = QTime::currentTime().addMSecs(msec);

    while( QTime::currentTime() < t )

    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
}

void MainWindow::on_actionAbout_triggered()
{
    //QMessageBox::about(this,"关于","Designed By Estamel_GG" "\n" "V1.0"); //非html形式，不能添加颜色，\n换行
    QMessageBox::about(this,"关于","Designed By <font color='red'>Estamel_GG</font>" "<br/>" "V2.6"); //html形式，添加颜色，<br/>换行
}

void MainWindow::on_pushButton_released()
{
    //on_pauseButton_released();
    //Delay(100);
    for(int i = ui->tableWidget_2->rowCount();i > 0;i--)
    {
       ui->tableWidget_2->removeRow(0); //循环删除第0行。每次删数第0行后，剩余部分会自动上移一行
    }
    //on_startButton_released();
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen) //获取ipv6地址
{
    socklen_t sockaddrlen;
    sockaddrlen = sizeof(struct sockaddr_in6);
    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        addrlen,
        NULL,
        0,
        NI_NUMERICHOST) != 0) address = NULL;
    return address;
}

//=====绘图部分==========================================================================

void MainWindow::update2()//更新绘图数据，每秒执行一次
{

    //=====绘图优化===============================
/*
    if(nIndex1==0) //折线图
    {
        if(sec>=299) //自动删除最开头的数据
        {
           series0->remove(0);//删除前三个点
           series1->remove(0);//删除前三个点
           seriesNull->remove(0);//删除前一个点

        }
    }

    else

    if(nIndex1==1) //面积图
    {
*/

    //}

/*
    if(nIndex1==0) //折线图
    {
        series0->append(sec, pac_num_in);
        series1->append(sec, pac_num_out*-1);
        seriesNull->append(sec,0);
    }

    else

    if(nIndex1==1) //面积图 （只能保留一个，不能用按钮切换！！！！！！，已经添加了基点，不能重绘）
    {
*/
        series0->append(sec, 0);
        series0->append(sec, pac_num_in);
        series0->append(sec, 0);

        series1->append(sec, 0);
        series1->append(sec, pac_num_out*-1);
        series1->append(sec, 0);

        seriesNull->append(sec,0);
    //}

        if(sec>=299) //自动删除最开头的数据
        {
           series0->remove(0);//删除前三个点
           series0->remove(1);
           series0->remove(2);

           series1->remove(0);//删除前三个点
           series1->remove(1);
           series1->remove(2);

           seriesNull->remove(0);
        }

        for(i=0;i<299;i++)//向前顺移一个，留出第300个空
        {
            pac_count_in[i]=pac_count_in[i+1];
            pac_count_out[i]=pac_count_out[i+1];
        }

        pac_count_in[299]=pac_num_in;//在入站包数组中添加元素
        pac_count_out[299]=pac_num_out;//在出站包数组中添加元素

        repaint(series0,series1,seriesNull);//定时重新绘图
    //===================
    /*
    qDebug()<<"Sec:"<<sec<<" In:"<<pac_num_in<<endl;
    qDebug()<<"Sec:"<<sec<<" Out:"<<pac_num_out<<endl;
    */
        pac_num_in= 0;//置零
        pac_num_out= 0;
        sec++;
        qDebug()<<sec<<endl;

}



void MainWindow::repaint(QLineSeries *series0,QLineSeries *series1,QLineSeries *seriesNull)
{


    if (paint == 1)
    {


        //series0->setUseOpenGL(true);

        if(ui->comboBox_4->currentIndex()==0)//可视区间大小
        {
            range=60;
        }
        else if (ui->comboBox_4->currentIndex()==1)
        {
            range=300;
        }

        //chart->createDefaultAxes();//自动坐标系

        if(sec >= range)//动态移动图像
            {         //新的x值处在X轴显示区的之外了
                axisX->setRange(sec-range, sec);
            }
        else
        {
            axisX->setRange(0, range);
        }
        //======================================================获得当前视图中的最高点
        if(ui->comboBox_4->currentIndex()==0)
        {
            cap_num_in_max=*max_element(pac_count_in+238,pac_count_in+299); //238和299决定了求最大元素的范围，决定了何时修正Y坐标轴
            cap_num_out_max=*max_element(pac_count_out+238,pac_count_out+299);
            axisX->setTickCount(7);//网格线个数（7线=6格）
            axisY->setTickCount(7);
        }

        if(ui->comboBox_4->currentIndex()==1)
        {
            cap_num_in_max=*max_element(pac_count_in,pac_count_in+299);
            cap_num_out_max=*max_element(pac_count_out,pac_count_out+299);
            axisX->setTickCount(6);//网格线个数（6线=5格）
            axisY->setTickCount(6);
        }
        //======================================================
        if(autoswitch==1) //动态扩展高度
        {
            if(cap_num_in_max > 50 || cap_num_out_max > 50)
            {
                if(cap_num_in_max>=cap_num_out_max)//确保区间包括出入站最大值
                {
                    Ymax=cap_num_in_max*(1.2);//按历史最大高度计算Y轴上下限
                    Ymin=Ymax*(-1);
                }
                if(cap_num_out_max>cap_num_in_max)
                {
                    Ymin=cap_num_out_max*(-1.2);
                    Ymax=Ymin*(-1);
                }

            }
            else
            {
                Ymax=50;
                Ymin=-50;
            }
        }

        axisY->setRange(Ymin, Ymax);

        series0->setPen(QPen(QColor(65,105,225),2,Qt::SolidLine));
        series1->setPen(QPen(QColor(154,205,50),2,Qt::SolidLine));
        seriesNull->setPen(QPen(QColor(0,0,0),1,Qt::SolidLine));

        series0->setName("入站");//图例
        series1->setName("出站");
        seriesNull->setName("临界");

        ui->graphicsView->setChart(chart);
        ui->graphicsView->setRenderHint(QPainter::Antialiasing);

    }
}

void MainWindow::on_pushButton_4_released()
{
    autoswitch=1;
    series0->clear();//图表清空
    series1->clear();//图表清空
    seriesNull->clear();//图表清空

    sec=0;//秒表置零
    Ymax=50;//坐标初始化
    Ymin=-50;
    cap_num_in_max=50;
    cap_num_out_max=50;
    memset(pac_count_in,0,sizeof(pac_count_in));//清空数组
    memset(pac_count_out,0,sizeof(pac_count_out));
}

void MainWindow::on_pushButton_5_released()
{
    autoswitch=0;
    Ymax=Ymax*0.8;
    Ymin=Ymin*0.8;
}

void MainWindow::on_pushButton_6_released()
{
    autoswitch=0;
    Ymax=Ymax*1.2;
    Ymin=Ymin*1.2;
}

void MainWindow::on_pushButton_7_released()
{
    autoswitch=1;
}

/*
void MainWindow::autoclear()
{
    round++;//每分钟+1
    QDateTime time = QDateTime::currentDateTime();
    QString str = time.toString("yyyy-MM-dd hh:mm:ss ddd"); //设置显示格式
    qDebug()<<"min:"<<round<<" at "<<str<<endl;
    if(round == 30) //每30分钟清理图像
    {
        on_pushButton_4_released();
    }
}
*/
void MainWindow::on_pushButton_3_released()
{

    ++nIndex;

    if (nIndex >= nCount)
    {
        nIndex = 0;
    }

    ui->stackedWidget->setCurrentIndex(nIndex);

    if(nIndex==0)
    {
        paint=0;
        ui->pushButton_3->setText("↓Current:Hex");
        ui->pushButton_4->setEnabled(false);
        ui->pushButton_5->setEnabled(false);
        ui->pushButton_6->setEnabled(false);
        ui->pushButton_7->setEnabled(false);
    }
    else if (nIndex==1)
    {
        paint=1;
        ui->pushButton_3->setText("↓Current:I/O");
        ui->pushButton_4->setEnabled(true);
        ui->pushButton_5->setEnabled(true);
        ui->pushButton_6->setEnabled(true);
        ui->pushButton_7->setEnabled(true);
    }


}
