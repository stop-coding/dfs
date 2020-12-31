#!/bin/bash
action=$1

if [ $action == "start" ];then
killall -9 smbd
killall -9 nmbd

/usr/local/samba/sbin/nmbd -D
/usr/local/samba/sbin/smbd -D
elif [ $action == "stop" ];then
killall -9 smbd
killall -9 nmbd
elif [ $action == "restart" ];then
killall -9 smbd
killall -9 nmbd

/usr/local/samba/sbin/nmbd -D
/usr/local/samba/sbin/smbd -D
else
	echo "no thing to do"
	echo "exp: $0 start/stop/restart"
	echo "exp: $0 start"
fi
