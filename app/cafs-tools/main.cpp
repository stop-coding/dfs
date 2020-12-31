/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */

/*!
* \file xxx.x
* \brief xxx
* 
* 包含..
*
* \copyright 2020 Ruijie Network. All rights reserved.
* \author hongchunhua@ruijie.com.cn
* \version v1.0.0
* \date 2020.08.05
* \note none 
*/

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "cafs_tools.hpp"
#include <iostream>

using namespace cafs;
using namespace std;

static bool isstop = false;
void SignalFunc(int sig_num)
{
	switch (sig_num)
	{
	case SIGINT:
		isstop = true;
		exit(0);
		break;
	case SIGQUIT:
		isstop = true;
		break;
	case SIGHUP:
		break;
	default:
		break;
	}
	cout<<sig_num<<endl;
	return;
}
/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	toolbox box(argc, argv);

	if(!box.isok()) {
		return 0;
	}

	signal(SIGINT, SignalFunc);//注册信号
	signal(SIGHUP, SignalFunc); 
	signal(SIGQUIT, SignalFunc);

	box.dispatch(isstop);//接收命令
	
	return 0;
}

