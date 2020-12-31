#!/bin/bash

work_path=$1

tar zxf $work_path/samba.tar.gz -C $work_path
export PKG_CONFIG_PATH="/usr/lib64/pkgconfig/:/usr/local/lib/pkgconfig/:/usr/local/lib64/pkgconfig"

echo "/usr/local/lib" >> /etc/ld.so.conf.d/ld_samba.conf
echo "/usr/local/lib64" >> /etc/ld.so.conf.d/ld_samba.conf
echo "/usr/local/samba/lib" >> /etc/ld.so.conf.d/ld_samba.conf
echo "/usr/local/samba/lib/vfs" >> /etc/ld.so.conf.d/ld_samba.conf

ldconfig

chmod +x $work_path/build_samba_with_cafs.sh
cd $work_path
sh ./build_samba_with_cafs.sh

if [ ! -d "/usr/local/samba/" ];then
	echo "build samba fail"
	exit 1
fi

if [ ! -f "/usr/local/samba/lib/vfs/cafs.so" ];then
	echo "build cafs.so for samba fail"
	exit 1
fi

cp $work_path/smb.conf /usr/local/samba/etc/
mkdir /etc/samba/
mkdir /home

yum install -y expect net-tools

ln -s  /usr/local/samba/etc/smb.conf /etc/samba/smb.conf
ln -s  /usr/local/samba/sbin/smbd /usr/sbin/smbd
ln -s  /usr/local/samba/sbin/nmbd /usr/sbin/nmbd
ln -s  /usr/local/samba/bin/smbstatus /usr/bin/smbstatus
ln -s  /usr/local/samba/bin/smbpasswd /usr/bin/smbpasswd
ln -s  /usr/local/samba/bin/smbclient /usr/bin/smbclient

chmod +x $work_path/set_samba_pwd.sh
cp $work_path/set_samba_pwd.sh /home/
./set_samba_pwd.sh root 123123
if [ $? != 0 ];then
	echo "set samba username and password fail"
	exit 1
fi

chmod +x /home/run_samba.sh
echo "build samba images success!!!!"



