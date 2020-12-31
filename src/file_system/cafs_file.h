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

#ifndef _CAFS_FILE_H_
#define _CAFS_FILE_H_

#include "cafs_public.h"
#include "cafs_mds.h"
#include "cafs_pfile.h"
#include "libcafs.h"
#ifdef __cplusplus
extern "C" {
#endif



struct cafs_file;

struct cafs_file_ops {
	int64_t (*lseek)(struct cafs_file *file, int64_t offset, int whence);
	int64_t (*read) (struct cafs_file *file, char *buf, int64_t size,int64_t offset);
	int64_t (*write)(struct cafs_file *file, const char *buf, int64_t size,int64_t offset);
	int (*ftruncate) (struct cafs_file *file, int64_t size);
	int (*fstatx)(struct cafs_file *file, struct cafs_statx *stx, unsigned int want, unsigned int flags);
	int (*fallocate)(struct cafs_file *file, int mode, int64_t offset, int64_t length);
	int (*fsync)(struct cafs_file *file);
	int (*fsetattrx)(struct cafs_file *file, struct cafs_statx *stx, int mask);
	int (*unlink)(struct cafs_file *file);
	const struct mds_node_obj *(*get_mds_nod)(struct cafs_file *file);
};

struct cafs_file {
	struct cafs_file_ops *ops;
	const char *name;
	const char *path;
	void      *usr_ctx;
	char      file_ctx[0];
};

struct cafs_file *create_file(const char *file_path,
    						  uint64_t client_id,
							  int flags,
							  uint32_t mode,
							  struct pfile_obj *pfile,
							  const struct mds_node_obj *mds_node);

int destroy_file(struct cafs_file *file);


#ifdef __cplusplus
}
#endif

#endif
