#!/bin/bash
cafs_path=$1
samba_src_path=$2
install_path=$3

cur_path=`pwd`

if [ ! -d "$cafs_path" ];then
	cafs_path=$cur_path/cafs
fi

echo "cafs_path:$cafs_path"

if [ ! -f "$samba_src_path" ];then
	if [ ! -f "$cur_path/samba-4.12.6.tar.gz" ];then
		echo "can't find samba source on target path[$cur_path]."
		exit 1
	else
		samba_src_path=$cur_path/samba-4.12.6.tar.gz
	fi
fi

echo "samba_src_path:$samba_src_path"

if [ ! -d "$install_path" ];then
	install_path="/usr/local/samba"
	echo "install samba target path[$install_path]."
fi

echo "install samba target path[$install_path]."

if [ ! -d "$cur_path/workspace" ];then
	mkdir $cur_path/workspace
	tar zxf $samba_src_path -C $cur_path/workspace
	if [ $? != 0 ];then
		echo "tar zxf [$samba_src_path] to $cur_path/workspace fail."
		exit 1
	fi
	cp  $cafs_path/*.patch $cur_path/workspace

	cd $cur_path/workspace

	for path_file in `ls *.patch`
	do
		echo "do patch: $path_file"
		patch -bp0 < $path_file
	done
fi
cd $cur_path/workspace
samba_dir=`ls |grep samba-`
echo "samba_dir:$samba_dir"

if [ ! -d "$samba_dir" ];then
	echo "invalid samba directory path[$samba_dir]."
	exit 1
fi

cd $cur_path/workspace/$samba_dir
cp -f $cur_path/cafs/vfs_cafs.c $cur_path/workspace/$samba_dir/source3/modules/

./configure --prefix=$install_path CFLAGS+='-pipe' --enable-cafs

make -j && make -j install

if [ $? != 0 ];then
	echo "build samba fail, check log."
	exit 1
fi
echo '---------------------------------'
echo 'build success!!!!'