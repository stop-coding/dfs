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

#ifndef _CAFS_DENTRY_H_
#define _CAFS_DENTRY_H_

#include <stdint.h>
#include "cafs_common.h"
#include "fsmsg.h"
#include "libcafs.h"


struct cafs_dentry_info
{
    uint64_t ino;
    uint32_t mode;
    char  d_name[FS_MAX_FILE_NAME_LIMIT + 4];
};

struct cafs_dentry;

struct cafs_dentry_ops {
  void (*get)(struct cafs_dentry *d);
  void (*put)(struct cafs_dentry *d);
  const struct cafs_dentry_info* (*get_parent)(struct cafs_dentry *d);
  const struct cafs_dentry_info* (*get_self)(struct cafs_dentry *d);
};

struct cafs_dentry {
  struct cafs_dentry_ops *ops;
  struct cafs_rwlock rwlock;
  void      *usr_ctx;
  char      dentry_ctx[0];
};

struct cafs_dentry *create_dentry(const CommonDentry *parent, const CommonDentry *self);
int destroy_dentry(struct cafs_dentry *d);


#endif /* _DENTRY_H */
