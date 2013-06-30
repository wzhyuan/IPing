#!/bin/bash
pid=`pgrep "delay"`
if [ "$pid" = "" ] ; then
    echo "Fping服务没有启动！"
else
    kill -9 $pid
    pid1=`pgrep "delay"`
    if [ "$pid1" = "" ] ; then
            echo "成功杀死Fping进程：" $pid
        else
                echo "Fping进程杀死失败！"
                exit 1
            fi
fi

cd /home/Fping
/home/Fping/Fping.sh

echo "Fping服务成功启动!" 

