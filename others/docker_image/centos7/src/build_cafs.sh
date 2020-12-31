#!/bin/bash

cur_path=$1

echo ""
echo "########### build cafs starting... ############"
echo ""

echo ""
echo "########### build dependency lib"
echo ""
if [ -z $cur_path ];then
	cur_path=`pwd`
	echo "work path:$cur_path"
fi

if [ ! -d $cur_path ];then
	cur_path=`pwd`
	echo "work path:$cur_path"
fi

tar zxvf $cur_path/ca.tar.gz -C $cur_path

rm -rf $cur_path/build_lib/arpc/build
mkdir $cur_path/build_lib/arpc/build
cd $cur_path/build_lib/arpc/build
cmake ../

rm -rf $cur_path/build_lib/serializer/build
mkdir $cur_path/build_lib/serializer/build
cd $cur_path/build_lib/serializer/build
cmake ../

cd $cur_path/build_lib/arpc/build
make arpc  -j4

cd $cur_path/build_lib/serializer/build
make fsmsg  -j4

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

rm -rf $cur_path/etcd_client/build
mkdir $cur_path/etcd_client/build
cd $cur_path/etcd_client/build
cmake ../
make -j4 && make -j4 install

rm -rf $cur_path/build
mkdir $cur_path/build
cd $cur_path/build/
cmake ../
make -j4
echo "########### make install"
make -j4 install


mkdir /usr/include/cafs
cp /usr/include/libcafs.h /usr/include/cafs
chmod +x /usr/local/bin/cafs*
chmod +x /usr/local/bin/server_*
echo "/usr/local/lib" >> /etc/ld.so.conf.d/ld_cafs.conf
echo "/usr/local/lib64" >> /etc/ld.so.conf.d/ld_cafs.conf

ldconfig
mkdir /home

echo ""
echo "########### build cafs end!!!!   ############"
echo ""


