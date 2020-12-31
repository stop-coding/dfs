/*
 * Copyright(C) 2019 Ruijie Network. All rights reserved.
 */
/*!
* \file x.c
* \brief  
* 
* 
* 
* \author hongchunhua@ruijie.com.cn
* \version v1.0.0
* \date 2020.08.05 
*/
#include <unistd.h>
#include <fcntl.h>

#include "cafs_public.h"
#include "cafs_common.h"
#include "cafs_file.h"
#include "cafs_mds.h"
#include "cafs_pfile.h"
#include "libcafs.h"

#define FILE_REQUEST_WAIT_TIMEOUT  (2*1000)
#define FILE_OPEN_BIG_IO_CHANNEL (1<<0)

#define FILE_CTX(ctx_name, obj, ret)\
struct _file_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _file_ctx *)obj->file_ctx;

struct _file_ctx{ 
	int 	flags;
	int      mode;
	CommonInode *inode;
    char     filename[FS_MAX_FILE_NAME_LIMIT + 4];
	char 	*fpath;
	uint64_t uid;
    uint64_t gid;
    uint64_t client_id;
	const struct mds_node_obj *mds_node;
	struct pfile_obj *pfile;
    int64_t offset;
	uint32_t max_rw_block_size;
	int		 usr_flags;
	uint64_t write_size;
	struct cafs_rwlock rwlock;
};

static int alloc_expect_fsize(struct cafs_file *file, int64_t fsize);
static int _create_request(struct cafs_file *file, struct mds_rsp_msg *rsp, uint32_t mode);
static int _open_request(struct cafs_file *file, struct mds_rsp_msg *rsp, uint32_t mode);
static int _alloc_request(struct cafs_file *file, struct mds_rsp_msg *rsp, uint64_t alloc_size);
static CommonUtime *set_time(CommonUtime *time, struct timespec *now);
static int _setattr_request(struct cafs_file *file, struct mds_rsp_msg *rsp, struct cafs_statx *stx, uint32_t mode);
static int _close_request(struct cafs_file *file, struct mds_rsp_msg *rsp);

static int64_t file_lseek(struct cafs_file *file, int64_t offset, int whence);
static int64_t file_read (struct cafs_file *file, char *buf, int64_t size, int64_t offset);
static int file_preadv (struct cafs_file *file,const struct iovec *iov,
		 int iovcnt, int64_t offset);
static int64_t file_write (struct cafs_file *file, const char *buf, int64_t size, int64_t offset);
static int file_pwritev (struct cafs_file *file, const struct iovec *iov,
		  int iovcnt, int64_t offset);
static int file_ftruncate (struct cafs_file *file, int64_t size);
static int file_fstatx (struct cafs_file *file, struct cafs_statx *stx,
		 unsigned int want, unsigned int flags);
static const struct mds_node_obj *get_mds_node(struct cafs_file *file)
{
	FILE_CTX(ctx, file, NULL);
	return ctx->mds_node;
}
static int file_fallocate(struct cafs_file *file, int mode, int64_t offset, int64_t length);

static int file_fsync(struct cafs_file *file)
{
	return 0;
}
static int file_fsetattrx(struct cafs_file *file, struct cafs_statx *stx, int mask);

static int file_unlink(struct cafs_file *file);

static struct cafs_file_ops file_ops = {
	  .lseek =&file_lseek,
	  .read = &file_read,
	  .write = &file_write,
	  .ftruncate = &file_ftruncate,
	  .fstatx = &file_fstatx,
	  .fallocate = &file_fallocate,
	  .fsync = &file_fsync,
	  .fsetattrx = &file_fsetattrx,
	  .unlink = &file_unlink,
	  .get_mds_nod = &get_mds_node,
};
struct cafs_file *create_file(const char *file_path,
    						  uint64_t client_id,
							  int flags,
							  uint32_t mode,
							  struct pfile_obj *pfile,
							  const struct mds_node_obj *mds_node)
{
    struct cafs_file *obj = NULL;
    int ret;
    struct _file_ctx *ctx;
    uint32_t path_len;
	struct mds_rsp_msg rsp;
	char file_name[FS_MAX_FILE_NAME_LIMIT *2] = {0};

    LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, NULL, "file_path is null fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!pfile, NULL, "pfile is null fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_node, NULL, "mds_node is null fail.");

    obj = (struct cafs_file *)CAFS_ALLOC(sizeof(struct cafs_file) + sizeof(struct _file_ctx), NULL);
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC cafs_file fail.");
    memset(obj, 0, sizeof(struct cafs_file) + sizeof(struct _file_ctx));
    obj->ops = &file_ops;

    ctx = (struct _file_ctx *)obj->file_ctx;

    ret = cafs_rwlock_init(&ctx->rwlock);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");

	//获取文件名
	ret = get_file_name(file_path, ctx->filename, FS_MAX_FILE_NAME_LIMIT);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "path[%s] get_file_name fail.", file_path);
	obj->name = ctx->filename;

	path_len = strlen(file_path);
    path_len = (path_len < PATH_MAX)?path_len:PATH_MAX;

	ctx->fpath = CAFS_ALLOC(path_len + 1, NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!obj, free_obj, "CAFS_ALLOC cafs_file fail.");

    memcpy(ctx->fpath, file_path, path_len);
	ctx->fpath[path_len] = '\0';
	obj->path = ctx->fpath;

	ctx->offset = 0;
	ctx->mds_node = mds_node;
	ctx->pfile = pfile;
	ctx->flags = flags;
	ctx->client_id = client_id;
	ctx->uid = getuid();
	ctx->gid = getgid();
	ctx->max_rw_block_size = (1024*1024); //1M
	ctx->write_size = 0;

	if ((flags&O_CREAT)){
		mode &=(~S_IFMT);
		mode |= S_IFREG;
		//CAFS_LOG_NOTICE("create mode:%o", mode);
		ret = _create_request(obj, &rsp, mode);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "_create_request fail.");
		ctx->inode = rsp.msg->create.inode;
		rsp.msg->create.inode = NULL;
	}else{
		ret = _open_request(obj, &rsp, mode);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "_open_request fail.");
		ctx->inode = rsp.msg->open.inode;
		rsp.msg->open.inode = NULL;
	}
	cafs_mds_put_rsp(&rsp);

	if ((!S_ISREG(ctx->inode->mode)) && (flags&O_WRONLY&O_RDWR)) {
		CAFS_LOG_ERROR("open path[%s] is not reg, can't do write/read operation.", ctx->fpath);
		goto free_obj;
	}
	//CAFS_LOG_NOTICE("inode->mode:%o", ctx->inode->mode);
	if (flags&O_APPEND) {
		ctx->offset = (int64_t)ctx->inode->size;
	}

    return obj;
free_obj:

	if (ctx->inode) {
        fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), ctx->inode);
        ctx->inode = NULL;
    }

    SAFE_CAFS_FREE(ctx->fpath);
    cafs_rwlock_destroy(&ctx->rwlock);
    SAFE_CAFS_FREE(obj);

    return NULL;
}

int destroy_file(struct cafs_file *file)
{
	struct mds_rsp_msg rsp;
	int ret;
	const CommonFile *i_file;
	uint32_t i;
	const struct pfile_node_obj *pfile_node;
	FILE_CTX(ctx, file, CAFS_ERR);

	ret = cafs_rwlock_wrlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "file[%p] cafs_rwlock_rdlock fail.", file);

	if(ctx->write_size && ctx->inode){
		ret = file_ftruncate(file, ctx->inode->size);
		LOG_ERROR_IF_VAL_TRUE(ret, "file[%s] ftruncate fail.", file->path);
	}
	
	ret = _close_request(file, &rsp);
	if (ret != 0) {
		CAFS_LOG_ERROR("_close_request fail.");
	}
	cafs_mds_put_rsp(&rsp);
	if (ctx->inode) {
        fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), ctx->inode);
        ctx->inode = NULL;
    }
	cafs_rwlock_unlock(&ctx->rwlock);
	SAFE_CAFS_FREE(ctx->fpath);
	cafs_rwlock_destroy(&ctx->rwlock);
    SAFE_CAFS_FREE(file);
	
    return ret;
}

	/*参数 whence 为下列其中一种:
    SEEK_SET 参数offset 即为新的读写位置.
    SEEK_CUR 以目前的读写位置往后增加offset 个位移量.
    SEEK_END 将读写位置指向文件尾后再增加offset 个位移量. 当whence 值为SEEK_CUR 或
    SEEK_END 时, 参数offet 允许负值的出现.*/

static int64_t file_lseek(struct cafs_file *file, int64_t offset, int whence)
{
	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->inode, CAFS_ERR, "ctx->inode is null fail.");

	switch(whence) {
		case SEEK_SET:
			ctx->offset = offset;
			break;
		case SEEK_CUR:
			ctx->offset += offset;
			break;
		case SEEK_END:
			ctx->offset = ctx->inode->size + offset;
			break;
		default:
			break;
	}
	return ctx->offset;
}

static int64_t file_read(struct cafs_file *file, char *buf, int64_t size, int64_t offset)
{
	const struct pfile_node_obj *pfile_node;
	uint32_t i, read_start_index = 0;
	struct pfile_r_msg r_msg;
	uint64_t file_index;
	const CommonFile *i_file;
	int ret;
	uint64_t fsize = 0;
	int64_t read_size = 0;
	uint64_t data_offset = 0;
	uint64_t expect_read_size = 0;

	FILE_CTX(ctx, file, CAFS_ERR);

	ret = cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "file[%p] cafs_rwlock_rdlock fail.", file);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!(ctx->flags|O_RDONLY|O_RDWR), unlock, "it can't read.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->inode, unlock, "ctx->inode is null fail.");
	fsize = ctx->inode->size;

	if (offset < 0) {
		offset = ctx->offset;
	}else{
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE((uint64_t)offset > fsize, unlock, 
									"read offset[%ld] over fsize[%lu].",offset, fsize);
	}

	size = (fsize < (uint64_t)(size + offset))?((int64_t)fsize - offset):size;
	expect_read_size = size;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->inode->file, unlock, "inode->file is null, fail.");
	i_file = ctx->inode->file;
	data_offset = offset;
	for (i = 0; i < i_file->n_obj; i++) {
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!i_file->obj[i], unlock, "i_file->obj[%u] is null, fail.", i);
		if (data_offset < i_file->obj[i]->obj_max_size) {
			read_start_index = i;
			break;
		}
		data_offset -= i_file->obj[i]->obj_max_size;
	}
	CAFS_LOG_DEBUG("file to read size:%ld, offset:%ld", size, offset);
	file_index = 0;
	for (i = read_start_index; i < i_file->n_obj && size > 0; i++) {
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!i_file->obj[i], unlock, "i_file->obj[%u] is null, fail.", i);
		if(expect_read_size > 128*1024){
			pfile_node = ctx->pfile->ops->get_bigio(ctx->pfile, i_file->obj[i]->cnode_id);
		}else{
			pfile_node = ctx->pfile->ops->get(ctx->pfile, i_file->obj[i]->cnode_id);
		}
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pfile_node, unlock, "pfile_node get fail.");
		memset(&r_msg, 0, sizeof(r_msg));
		r_msg.client_id = ctx->client_id;
		r_msg.gid = 0;
		r_msg.obj_id = i_file->obj[i]->obj_id;
		r_msg.r_offset = data_offset;
		if (((uint64_t)size +r_msg.r_offset <= i_file->obj[i]->obj_max_size)) {
			r_msg.r_max_size = size;
		}else{
			r_msg.r_max_size = i_file->obj[i]->obj_max_size - r_msg.r_offset;
		}
		
		read_size = pfile_node->ops->read(pfile_node, &r_msg, (uint8_t*)buf + file_index, r_msg.r_max_size);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(read_size < 0, unlock, "read fail, read size[%ld], expect [%lu].", read_size, r_msg.r_max_size);

		if ((uint64_t)read_size != r_msg.r_max_size) {
			CAFS_LOG_NOTICE("read size less, read size[%ld], expect [%lu].", read_size, r_msg.r_max_size);
		}
		size -= read_size;
		data_offset += read_size;
		file_index += read_size;
		CAFS_LOG_DEBUG("file cur read size:%ld, index:%ld, left:%ld", read_size, file_index, size);
		break;
	}
	CAFS_LOG_DEBUG("file total read size:%ld, left:%ld", file_index, size);
	cafs_rwlock_unlock(&ctx->rwlock);
  	return (int64_t)file_index;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return CAFS_ERR;
}


static int file_preadv (struct cafs_file *file,const struct iovec *iov,
		 int iovcnt, int64_t offset)
{
  	CAFS_LOG_ERROR("to do.");
  	return 0;
}

static int64_t file_write(struct cafs_file *file, const char *buf, int64_t size, int64_t offset)
{
	const struct pfile_node_obj *pfile_node;
	uint32_t i, write_start_index = 0;
	struct pfile_w_msg w_msg;
	uint64_t file_index;
	int ret;
	uint64_t expect_file_size = 0;
	const CommonFile *i_file;
	int64_t write_size;
	uint64_t max_size = 0;
	uint64_t data_offset = 0;
	uint64_t expect_write_size = size;

	FILE_CTX(ctx, file, CAFS_ERR);

	ret = cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "file[%p] cafs_rwlock_wrlock fail.", file);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(size <= 0, unlock, "size invalid.");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!(ctx->flags|O_WRONLY|O_RDWR), unlock, "it can't write.");

	if (offset < 0) {
		offset = ctx->offset;
	}

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->inode, unlock, "inode is null, fail.");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->inode->file, unlock, "inode->file is null, fail.");
	i_file = ctx->inode->file;

	for (i = 0; i < i_file->n_obj; i++) {
		max_size += i_file->obj[i]->obj_max_size;
	}

	expect_file_size = (uint64_t)(size + offset);
	expect_file_size = (expect_file_size > ctx->inode->size)?expect_file_size:ctx->inode->size;
	if (expect_file_size > max_size) {
		ret = alloc_expect_fsize(file, expect_file_size);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "alloc fail, expect size[%lu].", expect_file_size);
	}

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->inode->file->obj, unlock, "inode->file is null, fail.");
	
	data_offset = offset;
	for (i = 0; i < i_file->n_obj; i++) {
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!i_file->obj[i], unlock, "i_file->obj[%u] is null, fail.", i);
		if (data_offset < i_file->obj[i]->obj_max_size) {
			write_start_index = i;
			break;
		}
		data_offset -= i_file->obj[i]->obj_max_size;
	}
	CAFS_LOG_DEBUG("file to write size:%ld, offset:%ld", size, offset);
	file_index = 0;
	for (i = write_start_index; i < i_file->n_obj && size > 0; i++) {
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!i_file->obj[i], unlock, "i_file->obj[%u] is null, fail.", i);
		if(expect_write_size/ctx->max_rw_block_size || expect_file_size > ctx->max_rw_block_size){
			pfile_node = ctx->pfile->ops->get_bigio(ctx->pfile, i_file->obj[i]->cnode_id);
			ctx->usr_flags |= FILE_OPEN_BIG_IO_CHANNEL;
		}else{
			pfile_node = ctx->pfile->ops->get(ctx->pfile, i_file->obj[i]->cnode_id);
		}
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pfile_node, unlock, "pfile_node get fail.");

		memset(&w_msg, 0, sizeof(w_msg));
		w_msg.client_id = ctx->client_id;
		w_msg.gid = ctx->client_id;
		w_msg.obj_id = i_file->obj[i]->obj_id;
		w_msg.w_offset = data_offset;
		if ((uint64_t)size +w_msg.w_offset <= i_file->obj[i]->obj_max_size) {
			w_msg.w_max_size = size;
		}else{
			w_msg.w_max_size = i_file->obj[i]->obj_max_size - w_msg.w_offset;
		}
		size -= w_msg.w_max_size;
		write_size = pfile_node->ops->write(pfile_node, &w_msg, (uint8_t*)buf + file_index, w_msg.w_max_size);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(write_size < 0, unlock, "write fail, offset[%lu], expect write size[%lu].", w_msg.w_offset, w_msg.w_max_size);
		if ((uint64_t)write_size != w_msg.w_max_size) {
			CAFS_LOG_DEBUG("write size less, write size[%ld], but expect [%lu].", write_size, w_msg.w_max_size);
		}

		file_index += write_size;
		CAFS_LOG_DEBUG("file cur write size:%ld, index:%ld, left:%ld", write_size, file_index, size);
		break;
	}
	cafs_rwlock_unlock(&ctx->rwlock);
	cafs_rwlock_wrlock(&ctx->rwlock);
	ctx->write_size += file_index;
	ctx->inode->size += file_index;
	//file_ftruncate(file, ctx->write_size);
	CAFS_LOG_DEBUG("file write size:%lu success, file size:%lu KB", file_index, ctx->inode->size/1024);
	cafs_rwlock_unlock(&ctx->rwlock);
	return (int64_t)file_index;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return CAFS_ERR;
}

static int file_unlink(struct cafs_file *file)
{
	const struct pfile_node_obj *pfile_node;
	uint32_t i;
	struct pfile_w_msg w_msg;
	int64_t write_size;
	int ret;
	const CommonFile *i_file;
	uint8_t buf = 32;

	FILE_CTX(ctx, file, CAFS_ERR);

	ret = cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "file[%p] cafs_rwlock_wrlock fail.", file);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!(ctx->flags|O_WRONLY|O_RDWR), unlock, "it can't write.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->inode, unlock, "inode is null, fail.");
	i_file = ctx->inode->file;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!i_file, unlock, "inode->file is null, fail.");
	for (i = 0; i < i_file->n_obj; i++) {
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!i_file->obj[i], unlock, "i_file->obj[%u] is null, fail.", i);
		pfile_node = ctx->pfile->ops->get(ctx->pfile, i_file->obj[i]->cnode_id);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pfile_node, unlock, "pfile_node get fail.");

		memset(&w_msg, 0, sizeof(w_msg));
		w_msg.client_id = ctx->client_id;
		w_msg.gid = ctx->client_id;
		w_msg.obj_id = i_file->obj[i]->obj_id;
		w_msg.w_offset = 0;
		w_msg.w_max_size = 1;
		write_size = pfile_node->ops->write(pfile_node, &w_msg, &buf, w_msg.w_max_size);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(write_size < 0, unlock, "write fail, offset[%lu], expect write size[%lu].", w_msg.w_offset, w_msg.w_max_size);
		break;
	}
	cafs_rwlock_unlock(&ctx->rwlock);
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return CAFS_ERR;
}

static int file_pwritev (struct cafs_file *file, const struct iovec *iov,
		  int iovcnt, int64_t offset)
{
  CAFS_LOG_ERROR("to do.");
  return 0;
}

static int file_ftruncate(struct cafs_file *file, int64_t size)
{
  	int ret;
	struct mds_rsp_msg rsp;
	struct timespec atime;
	struct timespec mtime;
	struct timeval now;
	struct cafs_statx stx= {0};
	uint32_t mask = CAFS_SETATTR_ATIME|CAFS_SETATTR_MTIME|CAFS_SETATTR_SIZE;
	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(size < 0, CAFS_ERR, "size[%ld] is negtive, fail.", size);
	
	gettimeofday(&now, NULL);	// 线程安全
	stx.stx_atime.tv_sec = now.tv_sec;
	stx.stx_atime.tv_nsec = now.tv_usec * 10000;

	stx.stx_mtime.tv_sec = now.tv_sec;
	stx.stx_mtime.tv_nsec = now.tv_usec * 10000;

	stx.stx_size = size;

	stx.stx_mode = ctx->inode->mode;//后期要删除屏蔽

	ret = _setattr_request(file, &rsp, &stx, mask);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_setattr_request fail.");

	if ((mask&CAFS_SETATTR_ATIME) && ctx->inode->file && ctx->inode->file->atime) {
		ctx->inode->file->atime->tv_sec = stx.stx_atime.tv_sec;
		ctx->inode->file->atime->tv_nsec = stx.stx_atime.tv_nsec;
	}

	if ((mask&CAFS_SETATTR_MTIME) && ctx->inode->file && ctx->inode->file->mtime) {
		ctx->inode->file->mtime->tv_sec = stx.stx_mtime.tv_sec;
		ctx->inode->file->mtime->tv_nsec = stx.stx_mtime.tv_nsec;
	}

	if ((mask&CAFS_SETATTR_SIZE)) {
		ctx->inode->size = stx.stx_size;
	}
	cafs_mds_put_rsp(&rsp);
	return 0;
}

static int file_fstatx (struct cafs_file *file, struct cafs_statx *stx,
		 unsigned int want, unsigned int flags)
{
  	int ret;
	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!stx, CAFS_ERR, "stx null fail.");

	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->inode, CAFS_ERR, "inode null fail.");
	stx->stx_blksize = 4*1024;
	stx->stx_blocks = 1024;
	stx->stx_dev = 0;
	stx->stx_mask = want;
	stx->stx_rdev = 0;
	stx->stx_version = 0;
	stx->stx_gid = ctx->inode->gid;
	stx->stx_ino = ctx->inode->ino;
	stx->stx_uid = ctx->inode->uid;
	stx->stx_size = ctx->inode->size;
	stx->stx_mode = ctx->inode->mode;
	stx->stx_nlink = ctx->inode->nlink;
	stx->stx_btime.tv_sec = ctx->inode->btime->tv_sec;
	stx->stx_ctime.tv_sec = ctx->inode->ctime->tv_sec;
	stx->stx_btime.tv_nsec = ctx->inode->btime->tv_nsec;
	stx->stx_ctime.tv_nsec = ctx->inode->ctime->tv_nsec;
	stx->stx_mtime.tv_sec = 0;

  	return 0;
}

static int alloc_expect_fsize(struct cafs_file *file, int64_t fsize)
{
	CommonInode *inode;
	struct mds_rsp_msg rsp;
	int ret;

	FILE_CTX(ctx, file, CAFS_ERR);

	ret = _alloc_request(file, &rsp, fsize);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_alloc_request fail.");

	if (ctx->inode) {
        fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), ctx->inode);
        ctx->inode = NULL;
    }

	ctx->inode = rsp.msg->alloc.inode;
	rsp.msg->alloc.inode = NULL;
	return 0;
}

static int file_fallocate(struct cafs_file *file, int mode, int64_t offset, int64_t length)
{
	return alloc_expect_fsize(file, offset + length);
}

static int file_fsetattrx(struct cafs_file *file, struct cafs_statx *stx, int mask)
{
	int ret;
	struct mds_rsp_msg rsp;
	struct timespec atime;
	struct timespec mtime;
	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!stx, CAFS_ERR, "stx is 0 fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->inode, CAFS_ERR, "inode is null fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->inode->file, CAFS_ERR, "file is null fail.");

	ret = _setattr_request(file, &rsp, stx, mask);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_setattr_request fail.");

	if ((mask&CAFS_SETATTR_ATIME) && ctx->inode->file->atime) {
		ctx->inode->file->atime->tv_sec = stx->stx_atime.tv_sec;
		ctx->inode->file->atime->tv_nsec = stx->stx_atime.tv_nsec;
	}

	if ((mask&CAFS_SETATTR_MTIME) && ctx->inode->file->mtime) {
		ctx->inode->file->mtime->tv_sec = stx->stx_mtime.tv_sec;
		ctx->inode->file->mtime->tv_nsec = stx->stx_mtime.tv_nsec;
	}

	if ((mask&CAFS_SETATTR_SIZE)) {
		ctx->inode->size = stx->stx_size;
	}

	if ((mask&CAFS_SETATTR_MODE)) {
		ctx->inode->mode = stx->stx_mode;
	}
	cafs_mds_put_rsp(&rsp);
	return 0;
}

static int _create_request(struct cafs_file *file, struct mds_rsp_msg *rsp, uint32_t mode)
{
	CaMdsReqHead req_head;
	CaMdsRspHead *rsp_head;
	struct mds_req_msg req;
	int ret;

	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp, CAFS_ERR, "rsp null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), &req_head, sizeof(CaMdsReqHead));
	req_head.file_path = ctx->fpath;
	req_head.root_path = NULL;
	req_head.uid = ctx->uid;
	req_head.gid = ctx->gid;
	req_head.client_id = ctx->client_id;
	req_head.ino = (ctx->inode)?ctx->inode->ino:0;

	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_CREATE;
	INIT_REQ_FSMSG(req.op_id, &req.msg.create);
	req.msg.create.head = &req_head;
	req.msg.create.mode = mode;
	req.msg.create.flags = ctx->flags;
	req.msg.create.old_size = 0;

	rsp->op_id = req.op_id;
	ret = cafs_mds_request(ctx->mds_node, &req, rsp, FILE_REQUEST_WAIT_TIMEOUT);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "request op[%d] fail.", req.op_id);

	rsp_head = rsp->msg->create.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);
	
	return 0;
put_rsp:
	cafs_mds_put_rsp(rsp);
	return -1;
}

static int _open_request(struct cafs_file *file, struct mds_rsp_msg *rsp, uint32_t mode)
{
	CaMdsReqHead req_head;
	CaMdsRspHead *rsp_head;
	struct mds_req_msg req;
	int ret;

	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp, CAFS_ERR, "rsp null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), &req_head, sizeof(CaMdsReqHead));
	req_head.file_path = ctx->fpath;
	req_head.root_path = NULL;
	req_head.uid = 0;
	req_head.gid = 0;
	req_head.client_id = 0;
	req_head.ino = (ctx->inode)?ctx->inode->ino:0;

	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_OPEN;
	INIT_REQ_FSMSG(req.op_id, &req.msg.open);
	req.msg.open.head = &req_head;
	req.msg.open.mode = mode;
	req.msg.open.flags = ctx->flags;
	req.msg.open.old_size = 0;

	ret = cafs_mds_request(ctx->mds_node, &req, rsp, FILE_REQUEST_WAIT_TIMEOUT);;
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, ret, "request op[%d] fail.", req.op_id);

	rsp_head = rsp->msg->open.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);

	return 0;
put_rsp:
	ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(rsp);
	return ret;
}

static int _alloc_request(struct cafs_file *file, struct mds_rsp_msg *rsp, uint64_t alloc_size)
{
	CaMdsReqHead req_head;
	CaMdsRspHead *rsp_head;
	struct mds_req_msg req;
	int ret;

	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp, CAFS_ERR, "rsp null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), &req_head, sizeof(CaMdsReqHead));
	req_head.file_path = ctx->fpath;
	req_head.root_path = NULL;
	req_head.uid = ctx->uid;
	req_head.gid = ctx->gid;
	req_head.client_id = ctx->client_id;
	req_head.ino = (ctx->inode)?ctx->inode->ino:0;

	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_ALLOC;
	INIT_REQ_FSMSG(req.op_id, &req.msg.alloc);
	req.msg.alloc.head = &req_head;
	req.msg.alloc.flags = ctx->flags;
	req.msg.alloc.size = alloc_size;
	rsp->op_id = req.op_id;
	ret = cafs_mds_request(ctx->mds_node, &req, rsp, FILE_REQUEST_WAIT_TIMEOUT);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "request op[%d] fail.", req.op_id);

	rsp_head = rsp->msg->alloc.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "alloc result[%d] fail.", rsp_head->rsp_result);

	return 0;
put_rsp:
	ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(rsp);
	return ret;
}

static CommonUtime *set_time(CommonUtime *time, struct timespec *now)
{
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_UTIME), time, sizeof(CommonUtime));
	time->tv_sec = now->tv_sec;
	time->tv_nsec = now->tv_nsec;
	return time;
}
static int _setattr_request(struct cafs_file *file, struct mds_rsp_msg *rsp, struct cafs_statx *stx, uint32_t mask)
{
	CaMdsReqHead req_head;
	CaMdsRspHead *rsp_head;
	struct mds_req_msg req;
	CommonUtime _atime;
	CommonUtime _mtime;
	int ret;

	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!stx, CAFS_ERR, "stx null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->inode, CAFS_ERR, "inode null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->inode->file, CAFS_ERR, "inode->file null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), &req_head, sizeof(CaMdsReqHead));
	req_head.file_path = ctx->fpath;
	req_head.root_path = NULL;
	req_head.uid = ctx->uid;
	req_head.gid = ctx->gid;
	req_head.client_id = ctx->client_id;
	req_head.ino = (ctx->inode)?ctx->inode->ino:0;

	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_SETATTR;
	INIT_REQ_FSMSG(req.op_id, &req.msg.setattr);
	req.msg.setattr.head = &req_head;
	req.msg.setattr.flags = mask;

	req_head.gid = (mask&CAFS_SETATTR_GID)?stx->stx_gid:2000;
	req_head.uid = (mask&CAFS_SETATTR_UID)?stx->stx_uid:2000;

	req.msg.setattr.atime = (mask&CAFS_SETATTR_ATIME)?set_time(&_atime, &stx->stx_atime):ctx->inode->file->atime;
	req.msg.setattr.mtime = (mask&CAFS_SETATTR_MTIME)?set_time(&_mtime, &stx->stx_mtime):ctx->inode->file->mtime;
	req.msg.setattr.size =  (mask&CAFS_SETATTR_SIZE)?stx->stx_size:ctx->inode->size;
	req.msg.setattr.mode = (mask&CAFS_SETATTR_MODE)?stx->stx_mode:ctx->inode->mode;
	rsp->op_id = req.op_id;
	ret = cafs_mds_request(ctx->mds_node, &req, rsp, FILE_REQUEST_WAIT_TIMEOUT);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "request op[%d] fail.", req.op_id);

	rsp_head = rsp->msg->setattr.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "setattr result[%d] fail.", rsp_head->rsp_result);

	return 0;

put_rsp:
	ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(rsp);
	return ret;

}

static int _close_request(struct cafs_file *file, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	CaMdsRspHead *rsp_head;
	struct mds_req_msg req;
	CommonUtime atime;
	CommonUtime mtime;
	int ret;

	FILE_CTX(ctx, file, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp, CAFS_ERR, "rsp null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), &req_head, sizeof(CaMdsReqHead));
	req_head.file_path = ctx->fpath;
	req_head.root_path = NULL;
	req_head.uid = ctx->uid;
	req_head.gid = ctx->gid;
	req_head.client_id = ctx->client_id;
	req_head.ino = (ctx->inode)?ctx->inode->ino:0;

	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_CLOSE;
	INIT_REQ_FSMSG(req.op_id, &req.msg.close);
	req.msg.close.head = &req_head;
	rsp->op_id = req.op_id;
	ret = cafs_mds_request(ctx->mds_node, &req, rsp, FILE_REQUEST_WAIT_TIMEOUT);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "request op[%d] fail.", req.op_id);

	rsp_head = rsp->msg->close.head;
	//LOG_THEN_RETURN_VAL_IF_TRUE(rsp_head->rsp_result, CAFS_ERR, "rsp result[%d] for opt file[%s] fail.", rsp_head->rsp_result, ctx->fpath);
	if (rsp_head->rsp_result) {
		if (rsp_head->rsp_result == (-ENOENT)) {
			return 0;// todo 关闭文件夹会返回不存在，暂时屏蔽，等MDS定位
		}else{
			LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "rsp result[%d] for opt file[%s] fail.", rsp_head->rsp_result, ctx->fpath);
		}
	}
	return 0;

put_rsp:
    ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(rsp);
	return ret;
}
