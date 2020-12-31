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

#ifndef _CAFS_FS_H_
#define _CAFS_FS_H_

#include "cafs_log.h"
#include "cafs_config.h"
#include "cafs_inode.h"
#include "cafs_dentry.h"
#include "cafs_dir.h"
#include "cafs_file.h"

#include <sys/statvfs.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif
struct fs_obj;

struct fs_obj_ops {
  int (*mount)(struct fs_obj *obj, const char *mount_path);
  int (*unmount)(struct fs_obj *obj);
  int (*statfs)(struct fs_obj *obj, struct statvfs *stbuf);
  const char *(*getcwd)(struct fs_obj *obj);
  int (*chdir)(struct fs_obj *obj, const char *path);
  int (*opendir)(struct fs_obj *obj, const char *path, struct cafs_dir **pdir);
  int (*closedir)(struct fs_obj *obj, struct cafs_dir *dir);
  int (*readdir)(struct fs_obj *obj, struct cafs_dir *dir, struct dirent **dirent);
  int (*telldir)(struct fs_obj *obj, struct cafs_dir *dir, int64_t *offset);
  int (*seekdir)(struct fs_obj *obj, struct cafs_dir *dir, int64_t offset);
  int (*rewinddir)(struct fs_obj *obj, struct cafs_dir *dir);
  int (*mkdir)(struct fs_obj *obj, const char *path, uint32_t mode);
  int (*rmdir)(struct fs_obj *obj, const char *path);
  int (*open)(struct fs_obj *obj, const char *path, int flags, uint32_t mode);
  int (*close)(struct fs_obj *obj, int fd);
  int64_t (*lseek)(struct fs_obj *obj, int fd, int64_t offset, int whence);
  int64_t (*read)(struct fs_obj *obj, int fd, char *buf, int64_t size, int64_t offset);
  int64_t (*write)(struct fs_obj *obj, int fd, const char *buf, int64_t size, int64_t offset);
  int (*fstatx)(struct fs_obj *obj, int fd, struct cafs_statx *stx, unsigned int want, unsigned int flags);
  int (*ftruncate) (struct fs_obj *obj, int fd, int64_t size);
  int (*fallocate)(struct fs_obj *obj, int fd, int mode, int64_t offset, int64_t length);
  int (*fsetattrx)(struct fs_obj *obj, int fd, struct cafs_statx *stx, int mask);
  int (*fsync)(struct fs_obj *obj, int fd);
  int (*rename)(struct fs_obj *obj, const char *from, const char *to);
  int (*setattrx)(struct fs_obj *obj, const char *path, struct cafs_statx *stx, int mask, int flags);
  int (*link)(struct fs_obj *obj, const char *existing, const char *newname);
  int (*unlink)(struct fs_obj *obj, const char *path);
  int (*symlink)(struct fs_obj *obj, const char *existing, const char *newname);
  int (*readlink)(struct fs_obj *obj, const char *path, char *buf, int64_t size);
  int (*statx)(struct fs_obj *obj, const char *path, struct cafs_statx *stx, unsigned int want, unsigned int flags);
};

struct fs_obj{
    uint64_t  fs_max_size;
    uint64_t  fs_free_size;
    uint64_t  fs_used_size;
    struct statvfs vfs;
    struct fs_obj_ops *ops;
    uint8_t is_mounted;
    char  fs_ctx[0];
};


struct fs_obj_param{
    const struct cafs_cfg_obj *cfg;
    uint64_t client_id;
};
/*!
 *  @brief  创建一个文件系统对象
 *
 *  @param[in]  conf  连接对象
 *  @return  struct connect_obj * 请求消息的操作对象; (<em>NULL</em>: fail ; ( <em>非NULL</em>: succeed
 *
 */
struct fs_obj *cafs_create_fs(struct fs_obj_param *p);


/*!
 *  @brief  销毁一个文件系统对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_fs(struct fs_obj *obj);


#ifdef __cplusplus
}
#endif

#endif
