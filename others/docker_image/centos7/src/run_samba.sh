#!/bin/bash

nodeip=$1

echo "exp: cmd <target ip>"
if [ ! -z $nodeip ];then
	sed -i "s/addr=127.0.0.1/addr=$nodeip/g" /etc/cafs/cafs.conf
	echo "run samba server is[$nodeip]"
else
	echo "run samba server is[127.0.0.1]"
fi

smbd -D
nmbd -D

echo "start running samba!!!!"

while true
do
	echo "check smbd status....."
	for smbdpid in `ps -ef|grep 'smbd -D'|grep -v grep|awk '{print $2}'`
	do
		echo "check smbd[$smbdpid]"
		kill -0 $smbdpid
		if [ $? != 0 ];then
			echo "smbd[$smbdpid] is not running, exit..."
			exit 1;
		fi
	done
	if [ -z $smbdpid ];then
		echo "smbd have been exited!!! retry run it"
		smbd -D
		nmbd -D
	fi
	echo "smbd is running!!!"
	sleep 3000
done




