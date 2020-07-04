#include "defence.h"
#include "ui_defence.h"
#include <QMessageBox>
#include <QDebug>
#include <QProcess>
#include <QFile>
#include <QCloseEvent>
defence::defence(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::defence)
{
    ui->setupUi(this);
    this->setWindowTitle("C0ver me!");
    QFile file("banned.ini");
        if(!file.open(QIODevice::ReadOnly|QIODevice::Text))
        {
            qDebug()<<"打开失败！";
        }
        while(!file.atEnd()){
            QByteArray line=file.readLine();
            QString str(line);
            str.remove("\n");
            ui->listWidget->addItem(str);//读取文件内容
        }
}


defence::~defence()
{
    delete ui;
}

void defence::on_pushButton_released()
{

    if(ui->lineEdit->text()==NULL) //没有输入
        QMessageBox::warning(this, tr("Wrong!"), tr("没有IP内容"), QMessageBox::Ok);

    else
    {
        QString ip=ui->lineEdit->text();

        QRegExp regExp("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

        if(!regExp.exactMatch(ip)) //判断不符合ip格式
        {
            QMessageBox::warning(this, tr("warning"), tr("ip地址错误"));
        }

        else
            {
            if(quchong()==0)
                {
                cmd = QString ( "netsh advfirewall firewall add rule name=" "%1_in" " dir=in action=block remoteip=" "%2" ) //入站禁止
                        .arg(ip).arg(ip);
                QProcess p(0);
                p.start("cmd", QStringList()<<"/c"<<cmd);
                p.waitForStarted();
                p.waitForFinished(); //此处需要管理员权限

                cmd1 = QString ( "netsh advfirewall firewall add rule name=" "%1_out" " dir=out action=block remoteip=" "%2" ) //出站禁止
                        .arg(ip).arg(ip);
                QProcess q(0);
                p.start("cmd", QStringList()<<"/c"<<cmd1);
                p.waitForStarted();
                p.waitForFinished(); //此处需要管理员权限

                ui->listWidget->addItem(ip);
                }
            }
    }
    ui->lineEdit->clear();
}

void defence::on_pushButton_2_released()
{
    if(ui->listWidget->currentItem()==NULL)
        QMessageBox::warning(this, tr("warning"), tr("未选中"));
    else
    {
    QString ip2=ui->listWidget->currentItem()->text();
    QListWidgetItem *item = ui->listWidget->takeItem(ui->listWidget->currentRow());
    cmd2 = QString ( "netsh advfirewall firewall delete rule name=" "%1_in" ).arg(ip2);
    QProcess p(0);
    p.start("cmd", QStringList()<<"/c"<<cmd2);
    p.waitForStarted();
    p.waitForFinished();

    cmd3 = QString ( "netsh advfirewall firewall delete rule name=" "%1_out" ).arg(ip2);
    QProcess q(0);
    p.start("cmd", QStringList()<<"/c"<<cmd3);
    p.waitForStarted();
    p.waitForFinished();

    delete item;
    }
}

void defence::closeEvent(QCloseEvent *event)
{
    QStringList lines;
        QString line;
        int row=0;
         QFile file("banned.ini");//打开该文件进入编辑模式

         if(file.open(QIODevice::WriteOnly))//如果被打开
              {
             file.resize("banned.ini",0);//清空内容
             while (row<(ui->listWidget->count()))
                {
                 line=ui->listWidget->item(row)->text();
                 QTextStream stream( &file );//开始写入文本
                 stream<<line<<"\r\n";//如果是单个"\n"  保存文本的时候不会换行
                 row++;
                }
              }
                 file.close();
}

int defence::quchong()
{
    int i=0;

    while(i<ui->listWidget->count())
    {
        exist=ui->listWidget->item(i)->text();
        if(exist==ui->lineEdit->text())
        {
            QMessageBox::warning(this, tr("Wrong!"), tr("已经存在"), QMessageBox::Ok);
            return -1;
        }
        else
        {
            i++;
        }
    }
  return 0;
}
