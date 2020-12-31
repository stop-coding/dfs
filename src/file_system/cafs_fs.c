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
#include "cafs_fs.h"
#include "cafs_mds.h"
#include "cafs_pfile.h"

#include "klist.h"
#include "khash.h"

#define FS_REQUEST_WAIT_TIMEOUT  (2*1000)

#define FS_OBJ_CTX(ctx_name, obj, ret)\
struct _fs_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _fs_ctx *)obj->fs_ctx;

static void _dir_obj_free(void *iter);
static void _file_obj_free(void *iter);

KHASH_MAP_INIT_INT(h_dentry, struct cafs_dentry *);
KHASH_MAP_INIT_INT(h_inode, struct cafs_inode *);

KHASH_MAP_INIT_INT(h_dir, struct cafs_dir *);
KHASH_MAP_INIT_INT(h_file, struct cafs_file *);

KLIST_INIT(l_dir, struct cafs_dir *, _dir_obj_free);

KLIST_INIT(l_file, struct cafs_file *, _file_obj_free);

struct _dir_ctx{
	char *name;
};

struct _fs_ctx{
	struct mds_obj *mds;
	struct pfile_obj *pfile;
	struct _dir_ctx root;
    struct _dir_ctx cwd;
	khash_t(h_dentry)  *d_map;
	khash_t(h_inode)   *i_map;
	khash_t(h_dir)  *dir_map;
	int dir_fd;
	khash_t(h_file)   *file_map;
	int file_fd;
	klist_t(l_dir)  *opendir_list;
	klist_t(l_file)  *open_list;
	uint64_t uid;
    uint64_t gid;
    uint64_t client_id;
	uint32_t fs_id;
    struct cafs_rwlock rwlock;
};

#define CAFS_MAGIC_ID 0x3512

// function
static void set_statfs(struct statvfs *vfs);
static int destroy_fs_ctx(struct fs_obj *obj);

// fs op
static int fs_mount(struct fs_obj *obj, const char *root);
static int fs_unmount(struct fs_obj *obj);
static int fs_statfs(struct fs_obj *obj, struct statvfs *stbuf);
static const char* fs_getcwd(struct fs_obj *obj);
static int fs_chdir(struct fs_obj *obj, const char *path);
static int fs_opendir (struct fs_obj *obj, const char *path, struct cafs_dir **pdir);
static int fs_closedir (struct fs_obj *obj, struct cafs_dir *dir);
static int fs_readdir(struct fs_obj *obj, struct cafs_dir *dir, struct dirent **dirent);
static int fs_telldir (struct fs_obj *obj, struct cafs_dir *dir, int64_t *offset);
static int fs_seekdir (struct fs_obj *obj, struct cafs_dir *dir, int64_t offset);
static int fs_rewinddir (struct fs_obj *obj, struct cafs_dir *dir);
static int fs_mkdir(struct fs_obj *obj, const char *path, uint32_t mode);
static int fs_rmdir(struct fs_obj *obj, const char *path);

//file
static int fs_open(struct fs_obj *obj, const char *path, int flags, uint32_t mode);
static int fs_close(struct fs_obj *obj, int fd);
static int64_t fs_lseek(struct fs_obj *obj, int fd, int64_t offset, int whence);
static int64_t fs_read(struct fs_obj *obj, int fd, char *buf, int64_t size, int64_t offset);
static int64_t fs_write(struct fs_obj *obj, int fd, const char *buf, int64_t size, int64_t offset);
static int fs_fstatx(struct fs_obj *obj, int fd, struct cafs_statx *stx, unsigned int want, unsigned int flags);
static int fs_ftruncate(struct fs_obj *obj, int fd, int64_t size);
static int fs_fallocate(struct fs_obj *obj, int fd, int mode, int64_t offset, int64_t length);
static int fs_fsetattrx(struct fs_obj *obj, int fd, struct cafs_statx *stx, int mask);
static int fs_fsync(struct fs_obj *obj, int fd);
static int fs_fchmod(struct fs_obj *obj, int fd, mode_t mode);

static int fs_rename(struct fs_obj *obj, const char *from, const char *to);
static int fs_setattrx(struct fs_obj *obj, const char *path, struct cafs_statx *stx, int mask, int flags);
static int fs_link(struct fs_obj *obj, const char *existing, const char *newname);
static int fs_unlink(struct fs_obj *obj, const char *path);
static int fs_statx(struct fs_obj *obj, const char *path, struct cafs_statx *stx, unsigned int want, unsigned int flags);

static int fs_symlink(struct fs_obj *obj, const char *existing, const char *newname);
static int fs_readlink(struct fs_obj *obj, const char *path, char *buf, int64_t size);

static struct fs_obj_ops fs_ops = {
	.mount =&fs_mount,
	.unmount =&fs_unmount,
	.statfs = &fs_statfs,
	.getcwd = &fs_getcwd,
	.chdir = &fs_chdir,
	.opendir = &fs_opendir,
	.closedir = &fs_closedir,
	.readdir = &fs_readdir,
	.telldir = &fs_telldir,
	.seekdir = &fs_seekdir,
	.rewinddir = &fs_rewinddir,
	.mkdir = &fs_mkdir,
	.rmdir = &fs_rmdir,
	.open  = &fs_open,
	.close = &fs_close,
	.lseek = &fs_lseek,
	.read = &fs_read,
	.write = &fs_write,
	.fstatx  = &fs_fstatx,
	.ftruncate = &fs_ftruncate,
	.fsetattrx = &fs_fsetattrx,
	.fsync = &fs_fsync,
	.rename = &fs_rename,
	.setattrx = &fs_setattrx,
	.link =&fs_link,
	.unlink=&fs_unlink,
	.statx = &fs_statx,
	.symlink = &fs_symlink,
	.readlink = &fs_readlink,
};

struct fs_obj *cafs_create_fs(struct fs_obj_param *param)
{
	struct fs_obj *obj = NULL;
	int ret;
	struct _fs_ctx *ctx;
	struct mds_cfg mds_cfg;
	struct pfile_cfg pfile_cfg;

	LOG_THEN_RETURN_VAL_IF_TRUE(!param, NULL, "root is null");

	obj = (struct fs_obj *)CAFS_ALLOC(sizeof(struct fs_obj) + sizeof(struct _fs_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC fs_obj fail.");
	memset(obj, 0, sizeof(struct fs_obj) + sizeof(struct _fs_ctx));
	
	// ops func
	obj->ops = &fs_ops;
	ctx = (struct _fs_ctx *)obj->fs_ctx;

	// MDS
	memset(&mds_cfg, 0, sizeof(mds_cfg));
	mds_cfg.cfg = param->cfg;
	ctx->mds = cafs_create_mds(&mds_cfg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->mds, free_obj, "cafs_create_mds fail.");

	// PFILE
	memset(&pfile_cfg, 0, sizeof(pfile_cfg));
	pfile_cfg.cfg = param->cfg;
	ctx->pfile = cafs_create_pfile(&pfile_cfg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->pfile, free_obj, "cafs_create_pfile fail.");


	ctx->d_map = kh_init(h_dentry);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->d_map, free_obj, "kh_init fail.");

	ctx->i_map = kh_init(h_inode);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->i_map, free_obj, "kh_init fail.");

	ctx->dir_map = kh_init(h_dir);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->dir_map, free_obj, "kh_init fail.");

	ctx->file_map = kh_init(h_file);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->file_map, free_obj, "kh_init fail.");

	ctx->opendir_list = kl_init(l_dir);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->opendir_list, free_obj, "kh_init fail.");

	ctx->open_list = kl_init(l_file);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->open_list, free_obj, "kh_init fail.");

	// lock
	ret = cafs_rwlock_init(&ctx->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");

	ctx->uid = getuid();
	ctx->gid = getgid();
	ctx->client_id = param->client_id;
	ctx->fs_id = 0;

	set_statfs(&obj->vfs);

	return obj;
free_obj:
	ret = destroy_fs_ctx(obj);
	LOG_ERROR_IF_VAL_TRUE(ret, "destroy_fs_ctx fail in create fs obj.");

	cafs_rwlock_destroy(&ctx->rwlock);

	SAFE_CAFS_FREE(obj);

	return NULL;
}

int cafs_destroy_fs(struct fs_obj *obj)
{
	int ret;
	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	cafs_rwlock_wrlock(&ctx->rwlock);
	
	ret = destroy_fs_ctx(obj);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "destroy_fs_ctx fail.");

	CAFS_LOG_NOTICE("destroy_fs_ctx success!!");

	cafs_rwlock_unlock(&ctx->rwlock);
	cafs_rwlock_destroy(&ctx->rwlock);
	SAFE_CAFS_FREE(obj);
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return CAFS_ERR;
}

// private

static int destroy_fs_ctx(struct fs_obj *obj)
{
	int ret;
	struct cafs_dentry *dentry;
	struct cafs_inode *inode;
	struct cafs_dir *dir;
	struct cafs_file *file;
	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	SAFE_CAFS_FREE(ctx->cwd.name);
	SAFE_CAFS_FREE(ctx->root.name);

	if (ctx->d_map){
		kh_foreach_value(ctx->d_map, dentry, destroy_dentry(dentry));
		kh_clear(h_dentry, ctx->d_map);
		kh_destroy(h_dentry, ctx->d_map);
		ctx->d_map = NULL;
	}

	if (ctx->i_map){
		kh_foreach_value(ctx->i_map, inode, destroy_inode(inode));
		kh_clear(h_inode, ctx->i_map);
		kh_destroy(h_inode, ctx->i_map);
		ctx->i_map = NULL;
	}

	if (ctx->dir_map){
		kh_foreach_value(ctx->dir_map, dir, destroy_dir(dir));
		kh_clear(h_dir, ctx->dir_map);
		kh_destroy(h_dir, ctx->dir_map);
		ctx->dir_map = NULL;
	}

	if (ctx->file_map){
		kh_foreach_value(ctx->file_map, file, destroy_file(file));
		kh_clear(h_file, ctx->file_map);
		kh_destroy(h_file, ctx->file_map);
		ctx->file_map = NULL;
	}

	if (ctx->opendir_list) {
		kl_destroy(l_dir, ctx->opendir_list);
		ctx->opendir_list = NULL;
	}

	if (ctx->open_list) {
		kl_destroy(l_file, ctx->open_list);
		ctx->open_list = NULL;
	}

	SAFE_DESTROY_OBJ(ctx->mds, cafs_destroy_mds, ret);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, error, "cafs_destroy_mds fail.");

	CAFS_LOG_NOTICE("cafs_destroy_mds success!!");

	SAFE_DESTROY_OBJ(ctx->pfile, cafs_destroy_pfile, ret);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, error, "cafs_destroy_pfile fail.");

	CAFS_LOG_NOTICE("cafs_destroy_pfile success!!");

	return 0;
error:
	return CAFS_ERR;
}

static void set_statfs(struct statvfs *vfs) 
{
	vfs->f_bsize  = 4*1024;		// 块大小 4k
	vfs->f_frsize = 4*1024;			// 块内分片？
	vfs->f_blocks =64*1024*1024;			// 块数量
	vfs->f_bfree  = 64*1024*1024;
	vfs->f_bavail  = 64*1024*1024;
	vfs->f_files  = 4*1024*1024;
	vfs->f_ffree  = 4*1024*1024;
	vfs->f_favail  = 4*1024*1024;
	vfs->f_namemax = FS_MAX_FILE_NAME_LIMIT;
	vfs->f_fsid = CAFS_MAGIC_ID;
	return;
}

static void _dir_obj_free(void *iter)
{
	if (((kliter_t(l_dir)*)iter)->data) {
		destroy_dir(((kliter_t(l_dir)*)iter)->data);
		((kliter_t(l_dir)*)iter)->data = NULL;
	}
}

static void _file_obj_free(void *iter)
{
	if (((kliter_t(l_file)*)iter)->data) {
		destroy_file(((kliter_t(l_file)*)iter)->data);
		((kliter_t(l_file)*)iter)->data = NULL;
	}
}

static int get_file_unique_fd(int *fd, khash_t(h_file) *map)
{
	khiter_t iter = 0; //iter
	int i;
	(*fd)++;
	for (i = 0; i < 1000; i++) {
		iter = kh_get(h_file, map, *fd);
		if (iter == kh_end(map)){
			return *fd;
		}
		(*fd)++;
	}
	return *fd;
}

static int get_dir_unique_fd(int *fd, khash_t(h_dir) *map)
{
	khiter_t iter = 0; //iter
	int i;
	(*fd)++;
	for (i = 0; i < 1000; i++) {
		iter = kh_get(h_dir, map, *fd);
		if (iter == kh_end(map)){
			return *fd;
		}
		(*fd)++;
	}
	return *fd;
}

// 定义request函数
#define DEF_REQUEST_FUNC(_op_id, _op_name)\
static int _##_op_name##_request(const char *file_path, struct _fs_ctx *ctx, struct mds_rsp_msg *rsp)\
{\
	CaMdsReqHead req_head;\
	struct mds_req_msg req;\
	int ret;\
	LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, CAFS_ERR, "file path null.");\
	ret = init_request_head(file_path, NULL, ctx, &req_head);\
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");\
	memset(&req, 0, sizeof(req));\
	req.op_id = _op_id;\
	LOG_THEN_RETURN_VAL_IF_TRUE(!cafs_get_msg_op(_op_id), CAFS_ERR, "cafs_get_msg_op fail.");\
	INIT_REQ_FSMSG(req.op_id, &req.msg._op_name);\
	req.msg._op_name.head = &req_head;\
	ret = _mds_request(file_path, &req, ctx, rsp);\
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");\
	return 0;\
}

#define DEF_REQUEST_INO_FUNC(_op_id, _op_name)\
static int _##_op_name##_request(const char *file_path, uint64_t ino, struct _fs_ctx *ctx, struct mds_rsp_msg *rsp)\
{\
	CaMdsReqHead req_head;\
	struct mds_req_msg req;\
	int ret;\
	LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, CAFS_ERR, "file path null.");\
	ret = init_request_head(file_path, NULL, ctx, &req_head);\
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");\
	req_head.ino = ino;\
	memset(&req, 0, sizeof(req));\
	req.op_id = _op_id;\
	LOG_THEN_RETURN_VAL_IF_TRUE(!cafs_get_msg_op(_op_id), CAFS_ERR, "cafs_get_msg_op fail.");\
	INIT_REQ_FSMSG(req.op_id, &req.msg._op_name);\
	req.msg._op_name.head = &req_head;\
	ret = _mds_request(file_path, &req, ctx, rsp);\
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");\
	return 0;\
}

// conmon
static int init_request_head(const char *file_path, const char *mds_path, struct _fs_ctx *ctx, CaMdsReqHead *head) {
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), head, sizeof(CaMdsReqHead));
	head->file_path = (char *)file_path;
	head->root_path = (char *)mds_path;
	head->uid = ctx->uid;
	head->gid = ctx->gid;
	head->client_id = ctx->client_id;
	return 0;
}

static int _mds_request(const char *file_path, struct mds_req_msg *req, struct _fs_ctx *ctx, struct mds_rsp_msg *rsp)
{
	struct mds_node_obj *mds_node;
	int ret;

	mds_node = (struct mds_node_obj *)ctx->mds->ops->get(ctx->mds, file_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_node, CAFS_ERR, "get mds_node fail, file_path[%s].", file_path);

	rsp->op_id = req->op_id;
	ret = cafs_mds_request(mds_node, req, rsp, FS_REQUEST_WAIT_TIMEOUT);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "request op[%d] fail.", req->op_id);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "get_rsp op[%d] path[%s] fail.", rsp->op_id, file_path);
	ret = ctx->mds->ops->put(ctx->mds, mds_node);

	return 0;
free_node:
	cafs_mds_put_rsp(rsp);
	ret = ctx->mds->ops->put(ctx->mds, mds_node);
	return -1;
}

DEF_REQUEST_FUNC(MSG_OP_TYPE_E_LOOKUP, lookup);
DEF_REQUEST_FUNC(MSG_OP_TYPE_E_LOOKUPINO, lookupino);
DEF_REQUEST_FUNC(MSG_OP_TYPE_E_GETATTR, getattr);
DEF_REQUEST_FUNC(MSG_OP_TYPE_E_RMDIR, rmdir);
DEF_REQUEST_FUNC(MSG_OP_TYPE_E_UNLINK, unlink);
DEF_REQUEST_FUNC(MSG_OP_TYPE_E_READLINK, readlink);

static int _mkdir_request(const char *file_path, struct _fs_ctx *ctx,  uint32_t mode, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, CAFS_ERR, "file path null.");
	ret = init_request_head(file_path, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_MKDIR;
	INIT_REQ_FSMSG(req.op_id, &req.msg.mkdir);
	req.msg.mkdir.head = &req_head;
	req.msg.mkdir.mode = mode;
	ret = _mds_request(file_path, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}

static int _rename_request(const char *from_path, const char *to_path, struct _fs_ctx *ctx, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!from_path, CAFS_ERR, "file path null.");
	ret = init_request_head(from_path, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_RENAME;
	INIT_REQ_FSMSG(req.op_id, &req.msg.rename);
	req.msg.rename.head = &req_head;
	req.msg.rename.new_file_path = (char*)to_path;
	ret = _mds_request(from_path, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}

static int _link_request(const char *existing, const char *newname, struct _fs_ctx *ctx, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!existing, CAFS_ERR, "existing path null.");
	ret = init_request_head(existing, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_LINK;
	INIT_REQ_FSMSG(req.op_id, &req.msg.link);
	req.msg.link.head = &req_head;
	req.msg.link.link_target_path = (char*)newname;
	ret = _mds_request(existing, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}

static int _symlink_request(const char *existing, const char *newname, struct _fs_ctx *ctx, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;

	ret = init_request_head(existing, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_SYMLINK;
	INIT_REQ_FSMSG(req.op_id, &req.msg.link);
	req.msg.symlink.head = &req_head;
	req.msg.symlink.symlink_path = (char*)newname;
	ret = _mds_request(existing, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}

static CommonUtime *set_time(CommonUtime *time, struct timespec *now)
{
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_UTIME), time, sizeof(CommonUtime));
	time->tv_sec = now->tv_sec;
	time->tv_nsec = now->tv_nsec;
	return time;
}

static int _setattr_request(const char *file_path, struct _fs_ctx *ctx, struct cafs_statx *stx, uint32_t mask, struct mds_rsp_msg *rsp)
{
	CommonUtime _atime;
	CommonUtime _mtime;
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	
	ret = init_request_head(file_path, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");

	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_SETATTR;
	INIT_REQ_FSMSG(req.op_id, &req.msg.setattr);
	req.msg.setattr.head = &req_head;
	req.msg.setattr.flags = mask;

	req_head.gid = (mask&CAFS_SETATTR_GID)?stx->stx_gid:2000;
	req_head.uid = (mask&CAFS_SETATTR_UID)?stx->stx_uid:2000;

	req.msg.setattr.atime = (mask&CAFS_SETATTR_ATIME)?set_time(&_atime, &stx->stx_atime):NULL;
	req.msg.setattr.mtime = (mask&CAFS_SETATTR_MTIME)?set_time(&_mtime, &stx->stx_mtime):NULL;
	req.msg.setattr.size =  (mask&CAFS_SETATTR_SIZE)?stx->stx_size:(4*1024);
	req.msg.setattr.mode = (mask&CAFS_SETATTR_MODE)?stx->stx_mode:0;

	ret = _mds_request(file_path, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");

	return 0;
}

static int _do_mount (struct fs_obj *obj, const char *path)
{
  	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	CaMdsRspLookup *lookup;
	CommonInode *inode;
	uint32_t path_len;
	int ret;

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	memset(&rsp, 0, sizeof(rsp));
	ret = _lookup_request(path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_lookup_request fail.");

	rsp_head = rsp.msg->lookup.head;
	if (rsp_head->rsp_result) {
		CAFS_LOG_ERROR("mount [%s] not existed, mkdir try.", path);
		cafs_mds_put_rsp(&rsp);
		memset(&rsp, 0, sizeof(rsp));
		ret = _mkdir_request("/home", ctx, 0666, &rsp);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mkdir_request fail.");

		rsp_head = rsp.msg->lookup.head;
		LOG_ERROR_IF_VAL_TRUE(rsp_head->rsp_result, "mkdir: /home result[%d].", rsp_head->rsp_result);

		cafs_mds_put_rsp(&rsp);
		memset(&rsp, 0, sizeof(rsp));
		ret = _mkdir_request(path, ctx, 0666, &rsp);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mkdir_request fail.");
		rsp_head = rsp.msg->lookup.head;
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "mkdir result[%d] fail.", rsp_head->rsp_result);

		cafs_mds_put_rsp(&rsp);
		memset(&rsp, 0, sizeof(rsp));
		ret = _lookup_request(path, ctx, &rsp);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, ret, "_lookup_request fail, ret:%d.", ret);
	}
	inode = rsp.msg->lookup.inode;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!S_ISDIR(inode->mode), put_rsp, "path[%s] is not dir, fail.", path);

	path_len = strlen(path);
	ctx->root.name = CAFS_ALLOC(path_len + 1, NULL);
	memcpy(ctx->root.name, path, path_len);
	ctx->root.name[path_len] = '\0';

	ctx->cwd.name = CAFS_ALLOC(path_len + 1, NULL);
	memcpy(ctx->cwd.name, path, path_len);
	ctx->cwd.name[path_len] = '\0';
	cafs_mds_put_rsp(&rsp);
	CAFS_LOG_NOTICE("mount path[%s] success!!", ctx->root.name);

	return 0;
put_rsp:
	ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(&rsp);
	return ret;
}

// file system op
static int fs_mount(struct fs_obj *obj, const char *root)
{
	CaMdsRspOpendir *opendir;
	int ret;
	const char *root_path;
	char abs_path[PATH_MAX] = {0};

	LOG_THEN_RETURN_VAL_IF_TRUE(obj->is_mounted, CAFS_ERR, "fs is mounted, fail.");

	root_path= (root) ? root :"/";
	ret = get_abspath_r(root_path, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", root_path, abs_path);

	ret = _do_mount(obj, abs_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_do_opendir[%s] fail.", abs_path);

	obj->is_mounted = CAFS_TRUE;

	return 0;
}

static int fs_unmount(struct fs_obj *obj)
{
	int ret;
	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	
	SAFE_CAFS_FREE(ctx->root.name);
	SAFE_CAFS_FREE(ctx->cwd.name);

	obj->is_mounted = CAFS_FALSE;

	return 0;
}


static int fs_statfs(struct fs_obj *obj, struct statvfs *stbuf)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
  	CommonInode  *inode;
	int ret;
	const struct cafs_inode *pinode;

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");

	*stbuf = obj->vfs;

	return 0;
}

static const char* fs_getcwd(struct fs_obj *obj)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	struct cafs_dentry_info dentry;
	FS_OBJ_CTX(ctx, obj, NULL);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, NULL, "fs not mounted, fail.");

	return get_usr_cwdpath(ctx->root.name, ctx->cwd.name);
}

static int fs_chdir (struct fs_obj *obj, const char *path)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	CaMdsRspLookup *lookup;
	CommonInode *inode;
	uint32_t path_len;
	int ret;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null, fail.");
	
	CAFS_LOG_DEBUG("user change dir:%s", path);

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", path, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _lookup_request(abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_lookup_request fail.");

	rsp_head = rsp.msg->lookup.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail, chdir[%s].", rsp_head->rsp_result, abs_path);
	inode = rsp.msg->lookup.inode;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!S_ISDIR(inode->mode), put_rsp, "path[%s] is not dir, fail.", abs_path);

	SAFE_CAFS_FREE(ctx->cwd.name);

	path_len = strlen(abs_path);
	ctx->cwd.name = CAFS_ALLOC(path_len + 1, NULL);
	memcpy(ctx->cwd.name, abs_path, path_len);
	ctx->cwd.name[path_len] = '\0';
	cafs_mds_put_rsp(&rsp);

	return 0;
put_rsp:
	ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(&rsp);
	return ret;
}


static int fs_opendir (struct fs_obj *obj, const char *path, struct cafs_dir **pdir)
{
	int ret;
	char abs_path[PATH_MAX] = {0};
	struct cafs_dir_param param = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "obj is null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!pdir, CAFS_ERR, "pdir null, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", path, ctx->cwd.name);
	param.open_path = abs_path;
	param.uid = ctx->uid;
	param.gid = ctx->gid;

	param.mds = ctx->mds->ops->get(ctx->mds, abs_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(!param.mds, CAFS_ERR, "abs_path[%s] get_mds node fail.", abs_path);

	*pdir = create_dir(&param);
	LOG_THEN_RETURN_VAL_IF_TRUE(!(*pdir), CAFS_ERR, "create_dir fail.");

	return 0;
}

static int fs_closedir (struct fs_obj *obj, struct cafs_dir *dir)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "obj is null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dir, CAFS_ERR, "dir null, fail.");

	return destroy_dir(dir);
}

static int fs_readdir(struct fs_obj *obj, struct cafs_dir *dir, struct dirent **dirent)
{
	uint64_t i;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "obj is null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dir, CAFS_ERR, "dir null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dirent, CAFS_ERR, "dirent null, fail.");

	*dirent =  dir->ops->readdir(dir);
	return 0;
}
static int fs_telldir (struct fs_obj *obj, struct cafs_dir *dir, int64_t *offset)
{
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "obj is null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dir, CAFS_ERR, "dir null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!offset, CAFS_ERR, "offset null, fail.");

	*offset = dir->ops->tell(dir);
	return 0;
}

static int fs_seekdir (struct fs_obj *obj, struct cafs_dir *dir, int64_t offset)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dir, CAFS_ERR, "dir null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(offset < 0, CAFS_ERR, "offset  is low with 0, fail.");

	return dir->ops->seek(dir, offset);
}

static int fs_rewinddir (struct fs_obj *obj, struct cafs_dir *dir)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "obj is null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dir, CAFS_ERR, "dir null, fail.");

	return dir->ops->rewind(dir);
}

static int fs_mkdir(struct fs_obj *obj, const char *path, uint32_t mode)
{
  	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	struct cafs_dir *dir;
	CaMdsRspOpendir *opendir;
	int ret;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", path, ctx->cwd.name);
	
	memset(&rsp, 0, sizeof(rsp));
	ret = _mkdir_request(abs_path, ctx, mode, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mkdir_request fail.");

	rsp_head = rsp.msg->mkdir.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}

static int fs_rmdir(struct fs_obj *obj, const char *path)
{
  	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	struct cafs_dir *dir;
	CaMdsRspOpendir *opendir;
	int ret;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", path, ctx->cwd.name);
	
	memset(&rsp, 0, sizeof(rsp));
	ret = _rmdir_request(abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_rmdir_request fail.");

	rsp_head = rsp.msg->rmdir.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);

	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}

static int fs_open(struct fs_obj *obj, const char *path, int flags, uint32_t mode)
{
	struct cafs_file *fs_file = NULL;
	int file_fd = 0;
	khiter_t iter = 0; //iter
	const struct mds_node_obj *mds_node;
	int ret;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", path, ctx->cwd.name);

	mds_node = ctx->mds->ops->get(ctx->mds, abs_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_node, CAFS_ERR, "abs_path[%s] get_mds node fail.", abs_path);

	fs_file = create_file(abs_path, ctx->client_id, flags, mode, ctx->pfile, mds_node);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "create_file[%s] fail.", abs_path);

	file_fd = get_file_unique_fd(&ctx->file_fd, ctx->file_map);
	iter = kh_get(h_file, ctx->file_map, file_fd);
    if (iter == kh_end(ctx->file_map)){
        iter = kh_put(h_file, ctx->file_map, file_fd, &ret);
        LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, free_file, " kh_put file_fd[%d] fail.", file_fd);
    }
    kh_value(ctx->file_map, iter) = fs_file; // file保存

	return file_fd;
free_file:

	ret = destroy_file(fs_file);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "destroy_file fail.");

	return -1;
}

static int fs_close(struct fs_obj *obj, int fd)
{
	CaMdsRspHead *rsp_head;
	struct cafs_file *fs_file;
	uint64_t ino = 0;
	khiter_t iter = 0; //iter
	struct cafs_inode *fs_inode;
	int ret;
	char abs_path[PATH_MAX] = {0};
	char file_name[FS_MAX_FILE_NAME_LIMIT *2] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	kh_del(h_file, ctx->file_map, iter); 
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	ctx->mds->ops->put(ctx->mds, fs_file->ops->get_mds_nod(fs_file));

	CAFS_LOG_DEBUG("file name:%s, file path:%s.", fs_file->name, fs_file->path);
	ret = destroy_file(fs_file);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "destroy_file fail.");//删除文件夹会报错，这里暂时屏蔽

	return 0;
}

static int64_t fs_lseek(struct fs_obj *obj, int fd, int64_t offset, int whence)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->lseek(fs_file, offset, whence);
}

static int64_t fs_read(struct fs_obj *obj, int fd, char *buf, int64_t size, int64_t offset)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->read(fs_file, buf, size, offset);
}

static int64_t fs_write(struct fs_obj *obj, int fd, const char *buf, int64_t size, int64_t offset)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->write(fs_file, buf, size, offset);
}

static int fs_fstatx(struct fs_obj *obj, int fd, struct cafs_statx *stx, unsigned int want, unsigned int flags)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->fstatx(fs_file, stx, want, flags);
}

static int fs_ftruncate(struct fs_obj *obj, int fd, int64_t size)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->ftruncate(fs_file, size);
}
static int fs_fsync(struct fs_obj *obj, int fd)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->fsync(fs_file);
}

static int fs_fallocate(struct fs_obj *obj, int fd, int mode, int64_t offset, int64_t length)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->fallocate(fs_file, mode, offset, length);
}

static int fs_fsetattrx(struct fs_obj *obj, int fd, struct cafs_statx *stx, int mask)
{
	struct cafs_file *fs_file;
	khiter_t iter = 0; //iter

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] invalid, fail.", fd);

	iter = kh_get(h_file, ctx->file_map, fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(iter == kh_end(ctx->file_map), CAFS_ERR, "can't find fd[%d], fail.", fd);

    fs_file = kh_value(ctx->file_map, iter);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "get fd[%d] fs_file ptr is null.", fd);

	return fs_file->ops->fsetattrx(fs_file, stx, mask);
}

static int fs_rename (struct fs_obj *obj, const char *from, const char *to)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	char from_abs_path[PATH_MAX] = {0};
	char to_abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!from, CAFS_ERR, "path null, fail.");

	ret = get_abspath(from, ctx->root.name, ctx->cwd.name, from_abs_path, sizeof(from_abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", from, ctx->cwd.name);

	ret = get_abspath(to, ctx->root.name, ctx->cwd.name, to_abs_path, sizeof(to_abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", to, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _rename_request(from_abs_path, to_abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_rename_request fail.");

	rsp_head = rsp.msg->rename.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}

static int fs_setattrx(struct fs_obj *obj, const char *path, struct cafs_statx *stx, int mask, int flags)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", abs_path, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _setattr_request(abs_path, ctx, stx, mask, &rsp);
	LOG_DEBUG_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "setattr request fail.");

	rsp_head = rsp.msg->setattr.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail, path[%s].", rsp_head->rsp_result, abs_path);
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}

static int fs_link(struct fs_obj *obj, const char *existing, const char *newname)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	char exist_abs_path[PATH_MAX] = {0};
	char new_abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!existing, CAFS_ERR, "existing null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!newname, CAFS_ERR, "newname null, fail.");

	ret = get_abspath(existing, ctx->root.name, ctx->cwd.name, exist_abs_path, sizeof(exist_abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", existing, ctx->cwd.name);

	ret = get_abspath(newname, ctx->root.name, ctx->cwd.name, new_abs_path, sizeof(new_abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", newname, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _link_request(exist_abs_path, new_abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_link_request fail.");

	rsp_head = rsp.msg->link.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}

static int fs_unlink(struct fs_obj *obj, const char *path)
{
	struct cafs_file *fs_file;
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	const struct mds_node_obj *mds_node;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", abs_path, ctx->cwd.name);

	// 先删除文件
	mds_node = ctx->mds->ops->get(ctx->mds, abs_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_node, CAFS_ERR, "abs_path[%s] get_mds node fail.", abs_path);

	fs_file = create_file(abs_path, ctx->client_id, 0, 0755, ctx->pfile, mds_node);
	LOG_THEN_RETURN_VAL_IF_TRUE(!fs_file, CAFS_ERR, "create_file[%s] fail.", abs_path);

	ret = fs_file->ops->unlink(fs_file);
	ctx->mds->ops->put(ctx->mds, fs_file->ops->get_mds_nod(fs_file));
	CAFS_LOG_DEBUG("unlink file path:%s.", fs_file->path);
	destroy_file(fs_file);

	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "unlink[%s] fail.", abs_path);

	// 在删除文件元数据
	memset(&rsp, 0, sizeof(rsp));
	ret = _unlink_request(abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_unlink_request fail.");

	rsp_head = rsp.msg->unlink.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);
	cafs_mds_put_rsp(&rsp);

	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}
static int fs_statx(struct fs_obj *obj, const char *path, struct cafs_statx *stx, unsigned int want, unsigned int flags)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	CommonInode *inode;
	int ret;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", abs_path, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _lookup_request(abs_path, ctx, &rsp);
	LOG_DEBUG_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_lookup_request fail.");

	rsp_head = rsp.msg->lookup.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail, path[%s].", rsp_head->rsp_result, abs_path);

	inode = rsp.msg->lookup.inode;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!inode, put_rsp, "inode is null fail.");

	stx->stx_gid = inode->gid;
	stx->stx_ino = inode->ino;
	stx->stx_uid = inode->uid;
	stx->stx_size = inode->size;
	stx->stx_mode = inode->mode;
	stx->stx_nlink = inode->nlink;
	stx->stx_mask = 0;
	stx->stx_dev = 0;
	stx->stx_rdev = 0;

	if(inode->file && inode->file->mtime){
		stx->stx_mtime.tv_sec = inode->file->mtime->tv_sec;
		stx->stx_mtime.tv_nsec = inode->file->mtime->tv_nsec;
	}else{
		stx->stx_mtime.tv_sec = 0;
		stx->stx_mtime.tv_nsec = 0;
	}

	if(inode->file && inode->file->atime){
		stx->stx_atime.tv_sec = inode->file->atime->tv_sec;
		stx->stx_atime.tv_nsec = inode->file->atime->tv_nsec;
	}else{
		stx->stx_atime.tv_sec = 0;
		stx->stx_atime.tv_nsec = 0;
	}

	if (inode->btime){
		stx->stx_btime.tv_sec = inode->btime->tv_sec;
		stx->stx_ctime.tv_nsec = inode->btime->tv_nsec;
	}else{
		stx->stx_btime.tv_sec = 0;
	}

	if (inode->ctime){
		stx->stx_ctime.tv_sec = inode->ctime->tv_sec;
		stx->stx_ctime.tv_nsec = inode->ctime->tv_nsec;
	}else{
		stx->stx_ctime.tv_sec = 0;
	}

	stx->stx_blksize = 4*1024;
	stx->stx_blocks = 1024;
	stx->stx_version = 0;
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	ret = rsp_head->rsp_result;
	cafs_mds_put_rsp(&rsp);
	return ret;
}
static int fs_symlink(struct fs_obj *obj, const char *existing, const char *newname)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	char exist_abs_path[PATH_MAX] = {0};
	char new_abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!existing, CAFS_ERR, "existing null, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!newname, CAFS_ERR, "newname null, fail.");

	ret = get_abspath(existing, ctx->root.name, ctx->cwd.name, exist_abs_path, sizeof(exist_abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", existing, ctx->cwd.name);

	ret = get_abspath(newname, ctx->root.name, ctx->cwd.name, new_abs_path, sizeof(new_abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", newname, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _symlink_request(exist_abs_path, new_abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_link_request fail.");

	rsp_head = rsp.msg->symlink.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "symlink[%s] to [%s] fail, rsp result[%d].", 
								exist_abs_path, new_abs_path, rsp_head->rsp_result);
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}

static int fs_readlink(struct fs_obj *obj, const char *path, char *buf, int64_t size)
{
	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;
	int real_path_len = 0;
	char abs_path[PATH_MAX] = {0};

	FS_OBJ_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj->is_mounted, CAFS_ERR, "fs not mounted, fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null, fail.");

	ret = get_abspath(path, ctx->root.name, ctx->cwd.name, abs_path, sizeof(abs_path));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get_abspath fail, path[%s], name[%s].", path, ctx->cwd.name);

	memset(&rsp, 0, sizeof(rsp));
	ret = _readlink_request(abs_path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, " readlink[%s] request fail.", abs_path);

	rsp_head = rsp.msg->readlink.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "readlink[%s] fail, get rsp result[%d].", 
								abs_path, rsp_head->rsp_result);
	real_path_len = strlen(rsp.msg->readlink.realpath);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!real_path_len, put_rsp, " readlink[%s] real path fail.", abs_path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(real_path_len >= size, put_rsp, "real path len[%d] over buf size[%ld].", real_path_len, size);
	memcpy(buf, rsp.msg->readlink.realpath, real_path_len);
	buf[real_path_len] = '\0';
	CAFS_LOG_NOTICE("symlink realpath:%s.", buf);
	cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
	cafs_mds_put_rsp(&rsp);
	return -1;
}