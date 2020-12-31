/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */

/*!
* \file x.h
* \brief 
* 
* ....
*
* \copyright 2020 Ruijie Network. All rights reserved.
* \author hongchunhua@ruijie.com.cn
* \version v1.0.0
* \date 2020.08.05
* \note none 
*/

#ifndef _CAFS_TESTCASE_H_
#define _CAFS_TESTCASE_H_

#include "cafs_public.h"
#include "libcafs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct test_case{
	const char *test_info;
	int (*t_case)(cafs_mount_handle_t h);
	const char *test_sucess_info;
	const char *test_error_info;
};

const struct test_case *get_case(uint32_t case_id);
uint32_t get_case_num();

#ifdef __cplusplus
}
#endif

#endif
