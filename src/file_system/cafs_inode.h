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

#ifndef _CAFS_INODE_H_
#define _CAFS_INODE_H_

#include <stdint.h>
#include "cafs_mds_msg.h"

struct cafs_inode;

struct cafs_inode_ops {
  void (*ref_add)(struct cafs_inode *i);
  void (*ref_dec)(struct cafs_inode *i);
  const CommonInode *(*get_inode)(struct cafs_inode *i);
};

struct cafs_inode {
  struct cafs_rwlock rwlock;
  struct cafs_inode_ops *ops;
  void      *usr_ctx;
  char      ino_ctx[0];
};

struct cafs_inode *create_inode(const CommonInode *inode);
int destroy_inode(struct cafs_inode *inode);

#endif /* _INODE_H */
