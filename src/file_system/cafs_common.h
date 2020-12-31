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

#ifndef _CAFS_COMMON_H_
#define _CAFS_COMMON_H_

#include "cafs_log.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

CAFS_BOOL is_sub_dir(const char *root_dir, const char *sub_dir);

uint32_t get_parent_dir(const char *cwd_path, char *parent_buf, uint32_t buf_len);
int get_abspath(const char *path, const char *root_path, const char *cwd_path, char *new_path, uint32_t buf_len);
int check_valid_path(const char *path);
const char *get_usr_cwdpath(const char *root_path, const char *cwd_path);
int get_abspath_r(const char *path, char *new_path, uint32_t buf_len);
int get_file_name(const char *path, char *file_name, uint32_t buf_len);
#ifdef __cplusplus
}
#endif

#endif
