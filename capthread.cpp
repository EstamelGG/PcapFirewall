#include "capthread.h"
#include <utilities.h>
#include <QTextStream>
#include <qdebug.h>
CapThread::CapThread(pcap_t *capturer, pktCount *npacket, datapktVec& datapktLLink, dataVec& dataCharLLink, pcap_dumper_t *dumpfile):
    datapktLink(datapktLLink), dataCharLink(dataCharLLink)
{
    stopped = false;
    this->capturer = capturer;
    this->npacket = npacket;
    //this->dumpfile = dumpfile;
}

void CapThread::run()
{
    int res;
    struct tm *ltime;
    time_t local_tv_sec;
    struct pcap_pkthdr *header;     //数据包头
    const u_char *pkt_data = NULL;   //网络中收到的字节流数据
    u_char *ppkt_data;

    //对结束标志进行判断，同时抓取下一个数据包
    while(stopped != true && (res = pcap_next_ex(capturer, &header, &pkt_data)) >= 0)
    {
        if(res == 0)     //读取数据包超时
            continue;
        //用于存储捕获的数据包中的信息
        struct _datapkt *data = (struct _datapkt*)malloc(sizeof(struct _datapkt));
        data->isHttp =false;
        memset(data, 0, sizeof(struct _datapkt));

        data->len = header->len;

        //分析出错或所接收数据包不在处理范围内
        utilities* fc = new utilities;
        if(fc->analyze_frame(pkt_data, data, npacket) < 0)
            continue;

        //将本地化后的数据装入一个链表，以便在主窗口中相应控件中显示对应信息
        ppkt_data = (u_char *)malloc(header->len * sizeof(u_char));
        memcpy(ppkt_data, pkt_data, header->len);

        datapktLink.push_back(data);
        dataCharLink.push_back(ppkt_data);

        //更新显示中的统计信息
        //emit updatePktCount();

        //预处理，获得时间、长度

        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        data->time[0] = ltime->tm_year + 1900;
        data->time[1] = ltime->tm_mon + 1;
        data->time[2] = ltime->tm_mday;
        data->time[3] = ltime->tm_hour;
        data->time[4] = ltime->tm_min;
        data->time[5] = ltime->tm_sec;

        //获取时间戳
        QString timestr;
        QTextStream(&timestr) << data->time[0] << "/" << data->time[1] << "/" << data->time[2]
                                                << " " << data->time[3] << ":" << data->time[4]
                                                << ":" << data->time[5];
        char *buf = (char *)malloc(80 * sizeof(char));
        //获取数据包长度
        QString pkt_len = QString::number(data->len);

        //获得当前协议
        QString protoType = QString(data->pktType);
        //获得源IP地址,首先对网络层协议进行判断，IP协议或者ARP协议
        QString srcIP;
        if(data->ethh->type == 0x0806)  //ARP
        {
            sprintf(buf, "%d.%d.%d.%d", data->arph->senderIp[0], data->arph->senderIp[1], data->arph->senderIp[2], data->arph->senderIp[3]);
            srcIP = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == 0x0800) //IP
        {
            sprintf(buf, "%d.%d.%d.%d", data->iph->saddr[0], data->iph->saddr[1], data->iph->saddr[2], data->iph->saddr[3]);
            srcIP = QString(QLatin1String(buf));
        }
        //获得目的IP地址
        QString dstIP;
        if(data->ethh->type == 0x0806)
        {
            sprintf(buf, "%d.%d.%d.%d", data->arph->destIp[0], data->arph->destIp[1], data->arph->destIp[2], data->arph->destIp[3]);
            dstIP = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == 0x0800)
        {
            sprintf(buf, "%d.%d.%d.%d", data->iph->daddr[0], data->iph->daddr[1], data->iph->daddr[2], data->iph->daddr[3]);
            dstIP = QString(QLatin1String(buf));
        }

        //emit addOneCaptureLine(timestr, srcMac, dstMac, pkt_len, protoType, srcIP, dstIP);

        emit addOneCaptureLine(timestr , srcIP, dstIP, pkt_len, protoType);
        free(buf);
    }
}

void CapThread::stop()
{
    QMutexLocker locker(&m_lock);
    stopped = true;
}



