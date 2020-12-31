#!/bin/sh
src_path=$1
target_path=$2
if [ ! -d "$src_path" ];then
	echo "target_path is empty..."
	echo "exp:$0 <ca source code path> <packet save path>"
	exit 1
fi

if [ ! -d "$target_path" ];then
	echo "target_path is empty..."
	echo "exp:$0 <ca source code path> <packet save path>"
	exit 1
fi

#--exclude=$src_path/app --exclude=$src_path/Debug_build_out --exclude=$src_path/build --exclude=$src_path/build_lib --exclude=$src_path/othres
src_path=`realpath $src_path`
target_path=`realpath $target_path`

echo "pack $src_path to $target_path"
cd $src_path
chmod +x ./autobuild.sh
./autobuild.sh  $src_path
echo "pack: ca.tar.gz"
tar zcvf $target_path/ca.tar.gz -C $src_path .\
		--exclude=./.git \
		--exclude=./others\
		--exclude=./etcd_client/fsmsg/build \
		--exclude=./build_lib/arpc/build \
		--exclude=./build_lib/fsmsg/build \
		--exclude=./build \
		--exclude=./Debug_build_out \
		--exclude=./open_src/samba  > /dev/null
echo "pack: samba.tar.gz"
tar zcvf $target_path/samba.tar.gz -C $src_path/open_src/samba . > /dev/null

echo "----------success!!-------------"