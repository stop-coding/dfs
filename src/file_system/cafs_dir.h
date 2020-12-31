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

#ifndef _CAFS_DIR_H_
#define _CAFS_DIR_H_

#include "cafs_public.h"
#include "cafs_common.h"
#include "fsmsg.h"

#include<dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cafs_dir;

struct cafs_dir_ops {
    struct dirent *(*readdir)(struct cafs_dir *d);
    int64_t (*tell)(struct cafs_dir *d);
    int (*seek)(struct cafs_dir *d, int64_t offset);
    int (*rewind)(struct cafs_dir *d);
};

struct cafs_dir {
    const char *name;
    struct cafs_dir_ops *ops;
    void      *usr_ctx;
    char      dir_ctx[0];
};

struct cafs_dir_param {
    const char *open_path;
    const struct mds_node_obj *mds;
    uint64_t uid;
    uint64_t gid;
    uint64_t client_id;
};

struct cafs_dir *create_dir(struct cafs_dir_param *param);
int destroy_dir(struct cafs_dir *dir);


#ifdef __cplusplus
}
#endif

#endif
