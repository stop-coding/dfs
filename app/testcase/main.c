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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>

#include "libcafs.h"
#include "cafs_testcase.h"

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct cafs_mount_info conf_ctx;
	cafs_mount_handle_t handle =NULL;
	struct statvfs stbuf;
	int ret;
	const char * cwd;
	uint32_t test_case_num, i;
	const struct test_case *pcase;

	if (argc < 3) {
		CAFS_LOG_ERROR("Usage: %s <ini conf path> <mount path>", argv[0]);
		CAFS_LOG_NOTICE("EXP: %s cafs_conf.ini /home/hongchunhua/", argv[0]);
		return 0;
	}

	memset(&conf_ctx, 0, sizeof(conf_ctx));
	conf_ctx.config_path = argv[1];

	ret = cafs_create(&conf_ctx, &handle);
	if (ret != 0 ) {
		CAFS_LOG_ERROR("error: cafs_create");
		goto end;
	}

	ret = cafs_init(handle);
	if (ret != 0 ) {
		CAFS_LOG_ERROR("error: cafs_init fail.");
		goto end;
	}

	ret = cafs_mount(handle, argv[2]);
	if (ret != 0 ) {
		CAFS_LOG_ERROR("error: cafs_mount fail.");
		goto end;
	}
	ret = cafs_statfs(handle, "/", &stbuf);
	if (ret != 0 ) {
		CAFS_LOG_ERROR("error: cafs_statfs fail.");
		goto umount;
	}
	CAFS_LOG_NOTICE("------------fs info---------------");
	CAFS_LOG_NOTICE("f_blocks:%lu", stbuf.f_blocks);
	CAFS_LOG_NOTICE("f_bsize:%lu", stbuf.f_bsize);
	CAFS_LOG_NOTICE("fs all size:%lu KB", stbuf.f_blocks * stbuf.f_bsize/1024);
	CAFS_LOG_NOTICE("f_bfree:%lu", stbuf.f_bfree);
	CAFS_LOG_NOTICE("free size:%lu KB", stbuf.f_bfree * stbuf.f_bsize/1024);
	CAFS_LOG_NOTICE("f_fsid:%lu", stbuf.f_fsid);
	CAFS_LOG_NOTICE("f_bsize:%lu", stbuf.f_bsize);
	CAFS_LOG_NOTICE("---------------------------------\n");
	test_case_num = get_case_num();
	for (i = 0; i < test_case_num; i++){
		pcase = get_case(i);
		if (!pcase) {
			continue;
		}
		CAFS_LOG_NOTICE("+++++++++++++ test case:%u ++++++++++++", i);
		CAFS_LOG_NOTICE("test information:%s.", pcase->test_info);
		ret = pcase->t_case(handle);
		if (ret == 0) {
			CAFS_LOG_NOTICE("case pass! info: %s.", pcase->test_sucess_info);
		}else{
			CAFS_LOG_ERROR("case run error: %s.", pcase->test_error_info);
		}
		CAFS_LOG_NOTICE("++++++++++++++++++++++++++++++++++++++\n");
	}
umount:
	ret = cafs_unmount(handle);
	if (ret != 0 ) {
		CAFS_LOG_ERROR("error: cafs_unmount fail.");
	}
	CAFS_LOG_NOTICE("unmout success!!\n");
end:
	ret = cafs_finish(handle);
	if (ret != 0 ) {
		CAFS_LOG_ERROR("error: cafs_finish fail.");
	}
	CAFS_LOG_NOTICE("clean cafs finish!!\n");
	return 0;
}

