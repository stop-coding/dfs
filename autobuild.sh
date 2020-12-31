#!/bin/bash

git_ip=$2
cur_path=$1

echo ""
echo "########### build cafs starting... ############"
echo ""

echo ""
echo "########### build dependency lib"
echo ""
if [ -z $git_ip ];then
	git_ip="172.24.37.53"
	echo "default git server ip :$git_ip "
fi
if [ -z $cur_path ];then
	cur_path=`pwd`
	echo "work path:$cur_path"
fi

if [ ! -d $cur_path ];then
	cur_path=`pwd`
	echo "work path:$cur_path"
fi

if [ ! -d "$cur_path/build_lib" ];then
	mkdir $cur_path/build_lib
fi

cd $cur_path/build_lib
if [ ! -d "$cur_path/build_lib/arpc" ];then
	git clone --depth=1 git@172.24.37.135:rlh/arpc.git -b master
else
	git pull
fi

if [ ! -d "$cur_path/build_lib/serializer" ];then
	git clone --depth=1 git@172.24.37.135:rlh/serializer.git -b master
else
	git pull
fi


if [ ! -d "$cur_path/build_lib/arpc/build" ];then
	mkdir $cur_path/build_lib/arpc/build
fi
rm -rf $cur_path/build_lib/arpc/build/*
cd $cur_path/build_lib/arpc/build
cmake ../

if [ ! -d "$cur_path/build_lib/serializer/build" ];then
	mkdir $cur_path/build_lib/serializer/build
fi
rm -rf $cur_path/build_lib/serializer/build/*
cd $cur_path/build_lib/serializer/build
cmake ../

cd $cur_path/build_lib/arpc/build
make arpc -j4

cd $cur_path/build_lib/serializer/build
make fsmsg -j4

cd $cur_path/

echo "###### cppy header!!!"

if [ ! -d "$cur_path/inc/" ];then
	mkdir $cur_path/inc/
fi
cp $cur_path/build_lib/arpc/inc/*.h 					$cur_path/inc/
cp $cur_path/build_lib/serializer/inc/*.h 				$cur_path/inc/

echo "-----"
echo "###### cppy lib!!!"
if [ ! -d "$cur_path/lib/" ];then
	mkdir $cur_path/lib/
fi
cp -f $cur_path/build_lib/arpc/Debug_build_out/lib/*.so 			$cur_path/lib
cp -f $cur_path/build_lib/serializer/Debug_build_out/lib/*.so 		$cur_path/lib

echo "-----"
echo "########### build dependency end"
echo ""

echo ""
echo "########### build cafs master"
echo ""

git pull

if [ ! -d "$cur_path/etcd_client/build" ];then
	mkdir $cur_path/etcd_client/build
fi
rm -rf $cur_path/etcd_client/build/*
cd $cur_path/etcd_client/build
cmake ../
make -j4 && make -j4 install
rm -rf $cur_path/etcd_client/build

cd $cur_path
if [ ! -d "$cur_path/build" ];then
	mkdir $cur_path/build
fi
rm -rf $cur_path/build/*
cd $cur_path/build
cmake ../

make -j4
echo "########### make install"
make -j4 install

echo ""
echo "########### build cafs end!!!!   ############"
echo ""

if [ ! -d "$cur_path/app/build" ];then
	mkdir $cur_path/app/build
fi
rm -rf $cur_path/app/build/*
cd $cur_path/app/build
cmake ../
make -j4 && make -j4 install

echo ""
echo "########### build app end!!!!   ############"
echo ""