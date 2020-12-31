#!/bin/sh
imags_name=$1
left_new_num=$2
echo "Did rm docker image: <$imags_name> ??"
read -p "yes or no:" user_in
if [ $user_in != 'y' ] && [ $user_in != 'yes' ];then
	echo "stop to rm images."
	exit 0
fi
if [ -z $left_new_num ];then
	left_new_num=0
fi
i=0
echo "ignore image new num:$i"
for image in `docker images |grep $imags_name|awk '{print $3}'`
do
	let i++
	if [ $i -le $left_new_num ];then
		echo "ignore rm image:$image"
		continue
	fi
	echo "will rm image:$image"
	for conter in `docker ps -a|grep $image|awk '{print $1}'`
	do
		docker rm $conter
		echo "rm stop container $conter success"
	done
	docker rmi $image
	echo "rm image:$image success"
done
echo "----------success!!-------------"