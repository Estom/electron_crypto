* 第一部分的数据输出接口实现√

* 完成输入设置√

* 完成界面渲染√

* 搜索框的加锁小图标或者钥匙√

* 完成输入内容的检查√

```
    QString qstr = ui->textEdit->toPlainText();
    if (qstr.trimmed().length() == 0) {
        ui->label_26->setText("the message can not be empty\n");
        return;
    } else if (qstr.length() > 255) {
        ui->label_26->setText("the message can not be longer than 255 characters.\n");
        return;
    }
```
* encrypt进度条实现√

```
    encrypt = false;
    ui->pushButton->setDisabled(true);
    QString notice = "calculating...";
    ui->label_26->setText(notice);
```
* 输入接口的实现√


* 颜色搭配
* 数据格式化与高亮显示
* 添加图标和提示
* 对输入数据的长度进行判定