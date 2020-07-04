#ifndef DEFENCE_H
#define DEFENCE_H

#include <QDialog>

namespace Ui {
class defence;
}

class defence : public QDialog
{
    Q_OBJECT

public:
    explicit defence(QWidget *parent = nullptr);
    ~defence();
    QString ip,cmd,cmd1,cmd2,cmd3,exist;
    int RowCount;
private slots:
    void on_pushButton_released();
    void on_pushButton_2_released();
    int quchong();

private:
    Ui::defence *ui;

protected:
     void closeEvent(QCloseEvent *event);


};

#endif // DEFENCE_H
