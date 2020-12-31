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

#include "cafs_public.h"
#include "cafs_common.h"
#include "cafs_fs.h"
#include "libcafs.h"

#include <unistd.h>

struct cafs_context {
  struct cafs_cfg_obj *cfg;
  struct fs_obj  *fs;
  uint64_t client_id;
  struct cafs_rwlock rwlock;
  uint16_t      flags;
  uint8_t       is_inited;
  void      *usr_ctx;
};


#define MOUNT_HANDLE_CTX(ctx_name, handle, ret)               \
struct cafs_context *ctx_name = (struct cafs_context *)handle;\
LOG_THEN_RETURN_VAL_IF_TRUE(!ctx_name, ret, "ctx is null");\
CAFS_LOG_DEBUG("cafs api:%s", __FUNCTION__);

/*!
 *  @brief  加载本地静态参数到内存，创建文件系统全局对象
 *
 *  @param[in]  conf_ctx  参数
 *  @param[out] out_handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_create(struct cafs_mount_info *conf_ctx, cafs_mount_handle_t *out_handle)
{
	struct cafs_context *ctx = NULL;
	int   ret;

	LOG_THEN_RETURN_VAL_IF_TRUE(!conf_ctx, CAFS_ERR, "conf_ctx is null");
	LOG_THEN_RETURN_VAL_IF_TRUE(!out_handle, CAFS_ERR, "out_handle is null");
	LOG_THEN_RETURN_VAL_IF_TRUE(!conf_ctx->config_path, CAFS_ERR, "config_path is null");

	ctx = CAFS_ALLOC(sizeof(struct cafs_context), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx, CAFS_ERR, "CAFS_ALLOC fail");
	memset(ctx, 0, sizeof(struct cafs_context));

	ctx->cfg = create_cfg_obj(conf_ctx->config_path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->cfg, free_ctx, "create_cfg_obj configure file[%s] fail,", conf_ctx->config_path);

	ctx->usr_ctx = conf_ctx->usr_ctx;
	cafs_rwlock_init(&ctx->rwlock);
	if (conf_ctx->usr_id > 0) {
		ctx->client_id = conf_ctx->usr_id;
	}else{
		ctx->client_id = 10086;// 这里需要生成唯一性算法
	}

	*out_handle = (void*)ctx;
	return 0;
free_ctx:
  	if (ctx) {
   		CAFS_FREE(ctx, NULL);
  	}
  	return CAFS_ERR;
}

/*!
 *  @brief  初始化CA系统，不挂载文件
 *    初始化，主要完成远程资源获取能力。如连接配置中心建立并获取，建立session，鉴权等
 *    初始化成功后，说明已经具备文件系统操作能力，可以进行文件系统操作，如mount
 * 
 *  @param[in]  handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_init(cafs_mount_handle_t handle)
{
  	int ret;
	struct fs_obj_param fs_cfg;
  	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	cafs_rwlock_wrlock(&ctx->rwlock);

	memset(&fs_cfg, 0, sizeof(fs_cfg));
	fs_cfg.cfg = ctx->cfg;
	ctx->fs = cafs_create_fs(&fs_cfg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->fs, unlock, "cafs_create_fs fail.");

	ctx->is_inited = CAFS_TRUE;
	cafs_rwlock_unlock(&ctx->rwlock);

  	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 *  @brief  清理资源，退出文件系统。需要先umount后执行
 *    
 *    
 * 
 *  @param[inout]  handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_finish(cafs_mount_handle_t handle)
{
	int   ret;
  	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	cafs_rwlock_wrlock(&ctx->rwlock);

	if (ctx->fs) {
		cafs_destroy_fs(ctx->fs);
		ctx->fs = NULL;
	}
	
	if (ctx->cfg) {
		destroy_cfg_obj(ctx->cfg);
	}
	CAFS_LOG_NOTICE("cafs_destroy_fs success!!");
	cafs_rwlock_unlock(&ctx->rwlock);

	cafs_rwlock_destroy(&ctx->rwlock);

	SAFE_CAFS_FREE(handle);
	return 0;
}

/*!
 *  @brief  挂载文件系统
 *
 *  @param[in]  info  挂载参数
 *  @param[out] out_handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_mount(cafs_mount_handle_t handle, const char *root)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->fs, unlock, "ctx->fs is null.");

	ret = ctx->fs->ops->mount(ctx->fs, root);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "mount fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 *  @brief  卸载文件系统
 *
 *  @param[inout] handle  文件系统句柄，卸载成功则设置为NULL
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_unmount (cafs_mount_handle_t handle)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	cafs_rwlock_rdlock(&ctx->rwlock);

	ret = ctx->fs->ops->unmount(ctx->fs);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "mount fail.");
	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 *  @brief  获取文件系统信息
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path    文件路径, can be any path within the mounted filesystem
 *  @param[out] stbuf   文件系统信息
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_statfs (cafs_mount_handle_t handle, const char *path,
		     struct statvfs *stbuf)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!stbuf, CAFS_ERR, "stbuf is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->statfs(ctx->fs, stbuf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "statfs fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;

}

/*!
 * @brief Get the current working directory.
 *
 * @param handle the cafs mount to get the current working directory for.
 * @returns the path to the current working directory
 */
const char *cafs_getcwd (cafs_mount_handle_t handle)
{
    const char *cwd = NULL;
	MOUNT_HANDLE_CTX(ctx, handle, NULL);

	cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	cwd = ctx->fs->ops->getcwd(ctx->fs);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, unlock, "getcwd fail.");
	cafs_rwlock_unlock(&ctx->rwlock);
	
	return cwd;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return NULL;
}

/*!
 * @brief Change the current working directory.
 *
 * @param handle the cafs mount to change the current working directory for.
 * @param path the path to the working directory to change into.
 * @returns 0 on success, negative error code otherwise.
 */
int cafs_chdir (cafs_mount_handle_t handle, const char *path)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = check_valid_path(path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "check_valid_path fail.");

	ret = ctx->fs->ops->chdir(ctx->fs, path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "chdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 *  @brief  打开一个目录
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path    目录路径
 *  @param[out] dirp   目录句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_opendir (cafs_mount_handle_t handle, const char *path,
		      struct cafs_dir **dirpp)
{
    int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!dirpp, CAFS_ERR, "dirpp is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");
	CAFS_LOG_DEBUG("opendir[%s]", path);
	ret = ctx->fs->ops->opendir(ctx->fs, path, dirpp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "opendir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);
	CAFS_LOG_DEBUG("dirpp->name[%s]", (*dirpp)->name);
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 *  @brief  关闭一个已打开的目录信息
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[inout] dirp   目录句柄,关闭成功会被置空
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 */
int cafs_closedir (cafs_mount_handle_t handle, struct cafs_dir *dirp)
{
    int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!dirp, CAFS_ERR, "dirpp is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->closedir(ctx->fs, dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "closedir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);
	
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 *  @brief  读取下一个目录信息
 *  注意：函数非安全情况，当目录操作符号dirp提前释放，则dirent也被释放，在访问则会段错误！
 * 
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp  目录句柄
 *  @return  struct dirent *; (<em>NULL</em>: fail ; ( <em>others</em>: succeed
 *
 */
struct dirent *cafs_readdir (cafs_mount_handle_t handle, struct cafs_dir *dirp)
{
    int ret = 0;
	struct dirent *ret_dir;
	MOUNT_HANDLE_CTX(ctx, handle, NULL);

	LOG_THEN_RETURN_VAL_IF_TRUE(!dirp, NULL, "dirp is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->readdir(ctx->fs, dirp, &ret_dir);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "readdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);
	if (ret_dir){
		CAFS_LOG_DEBUG("readdir->name[%s]", ret_dir->d_name);
	}
	return ret_dir;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
    return NULL;
}
/*!
 *  @brief  读取下一个目录信息（安全版）
 *  调用者分配一个struct dirent来获取目录信息
 * 
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp  目录句柄
 *  @param[out] de    目录结构信息
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_readdir_r (cafs_mount_handle_t handle, struct cafs_dir *dirp,
			struct dirent *de)
{
    int ret = 0;
	struct dirent *ret_dir;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!dirp, CAFS_ERR, "dirp is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->readdir(ctx->fs, dirp, &ret_dir);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "readdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);
	*de = *ret_dir;
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
    return CAFS_ERR;
}
/*!
 *  @brief  获取当前目录索引位置（偏移量）
 *   
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp    目录句柄
 *  @return  int64_t, 目录索引偏移量; (<em>小于0</em>: fail ; ( <em>大于等于0</em>: succeed
 *
 */
int64_t cafs_telldir(cafs_mount_handle_t handle, struct cafs_dir *dirp)
{
   	int ret = 0;
	int64_t offset = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!dirp, CAFS_ERR, "dirp is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->telldir(ctx->fs, dirp, &offset);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "readdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return offset;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
    return CAFS_ERR;
}

/*!
 *  @brief  根据偏移量移动到对应的目录指向位置
 *   
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp    目录句柄
 *  @param[in]  offset  偏移量，该偏移量必须是由telldir返回的值来确定
 *  @return  void;
 *
 */
void cafs_seekdir (cafs_mount_handle_t handle, struct cafs_dir *dirp,
		   int64_t offset)
{
    int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, ;);

	LOG_THEN_RETURN_IF_VAL_TRUE(!dirp, "dirp is null.");
	LOG_THEN_RETURN_IF_VAL_TRUE(offset < 0, "offset is low with 0.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->seekdir(ctx->fs, dirp, offset);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "readdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
    return;
}

/*!
 *  @brief  回到目录索引起始位置
 *   
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp    目录句柄
 *  @return  void;
 *
 */
void cafs_rewinddir (cafs_mount_handle_t handle, struct cafs_dir *dirp)
{
    int ret = 0;
	int64_t offset = 0;
	MOUNT_HANDLE_CTX(ctx, handle, ;);

	LOG_THEN_RETURN_IF_VAL_TRUE(!dirp, "dirp is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->rewinddir(ctx->fs, dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "readdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
    return;
}
/*!
 *  @brief  创建目录
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path the path of the directory to create.  This must be either an
 *        absolute path or a relative path off of the current working directory.
 *  @param[in]  mode the permissions the directory should have once created.
 *  @returns 0 on success or a negative return code on error.
 */
int cafs_mkdir(cafs_mount_handle_t handle, const char *path, mode_t mode)
{
    int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->mkdir(ctx->fs, path, mode);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "mkdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 *  @brief  删除目录
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path the path of the directory to remove.
 *  @returns 0 on success or a negative return code on error.
 */
int cafs_rmdir (cafs_mount_handle_t handle, const char *path)
{
    int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->rmdir(ctx->fs, path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "rmdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 * Create a link.
 *
 *  @param[in] handle  文件系统句柄
 *  @param[in] existing the path to the existing file/directory to link to.
 *  @param[in] newname the path to the new file/directory to link from.
 *  @returns 0 on success or a negative return code on error.
 */
int cafs_link (cafs_mount_handle_t handle, const char *existing, const char *newname)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!existing, CAFS_ERR, "existing is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!newname, CAFS_ERR, "newname is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->link(ctx->fs, existing, newname);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "rmdir fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 * Read a symbolic link.
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path the path to the symlink to read
 *  @param[out] buf the buffer to hold the path of the file that the symlink points to.
 *  @param[in]  size the length of the buffer
 *  @returns number of bytes copied on success or negative error code on failure
 */
int cafs_readlink (cafs_mount_handle_t handle, const char *path, char *buf, int64_t size)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf || !size, CAFS_ERR, "buf is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->readlink(ctx->fs, path, buf, size);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "readlink[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 * Creates a symbolic link.
 *
 *  @param[in] handle  文件系统句柄
 *  @param[in] existing the path to the existing file/directory to link to.
 *  @param[in] newname the path to the new file/directory to link from.
 *  @returns 0 on success or a negative return code on failure.
 */
int cafs_symlink (cafs_mount_handle_t handle, const char *existing, const char *newname)
{
 	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!existing, CAFS_ERR, "existing is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!newname, CAFS_ERR, "newname is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->symlink(ctx->fs, existing, newname);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "symlink[%s] to [%s] fail.", existing, newname);

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 * Removes a file, link, or symbolic link.  If the file/link has multiple links to it, the
 * file will not disappear from the namespace until all references to it are removed.
 * 
 *  @param[in] handle  文件系统句柄
 *  @param[in] path the path of the file or link to unlink.
 *  @returns 0 on success or negative error code on failure.
 */
int cafs_unlink (cafs_mount_handle_t handle, const char *path)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->unlink(ctx->fs, path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "unlink[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 * Create and/or open a file.
 *
 * @param handle the cafs mount handle to use for performing the open.
 * @param path the path of the file to open.  If the flags parameter includes O_CREAT,
 *        the file will first be created before opening.
 * @param flags a set of option masks that control how the file is created/opened.
 * @param mode the permissions to place on the file if the file does not exist and O_CREAT
 *        is specified in the flags.
 * @returns a non-negative file descriptor number on success or a negative error code on failure.
 */
int cafs_open(cafs_mount_handle_t handle, const char *path, int flags, mode_t mode)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->open(ctx->fs, path, flags, mode);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "open[%s] fail.",path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return -ENOENT;
}
/*!
 * Close the open file.
 *
 * @param handle the cafs mount handle to use for performing the close.
 * @param fd the file descriptor referring to the open file.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_close (cafs_mount_handle_t handle, int fd)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->close(ctx->fs, fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "close fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return -ENOENT;
}

/*!
 * Reposition the open file stream based on the given offset.
 *
 * @param handle the cafs mount handle to use for performing the lseek.
 * @param fd the open file descriptor referring to the open file and holding the
 *        current position of the stream.
 * @param offset the offset to set the stream to
 * @param whence the flag to indicate what type of seeking to perform:
 *	SEEK_SET: the offset is set to the given offset in the file.
 *      SEEK_CUR: the offset is set to the current location plus @e offset bytes.
 *      SEEK_END: the offset is set to the end of the file plus @e offset bytes.
 * @returns 0 on success or a negative error code on failure.
 */
int64_t cafs_lseek (cafs_mount_handle_t handle, int fd, int64_t offset,
		    int whence)
{
  	int64_t ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->lseek(ctx->fs, fd, offset, whence);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "lseek fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 * Read data from the file.
 *
 * @param handle the cafs mount handle to use for performing the read.
 * @param fd the file descriptor of the open file to read from.
 * @param buf the buffer to read data into
 * @param size the initial size of the buffer
 * @param offset the offset in the file to read from.  If this value is negative, the
 *        function reads from the current offset of the file descriptor.
 * @returns the number of bytes read into buf, or a negative error code on failure.
 */
int64_t cafs_read (cafs_mount_handle_t handle, int fd, char *buf, int64_t size,
	       int64_t offset)
{
  	int64_t ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	//CAFS_LOG_ERROR("cafs_read, size:%ld, offset:%ld", size, offset);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf, CAFS_ERR, "buf is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->read(ctx->fs, fd, buf, size, offset);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "read fail.");
	cafs_rwlock_unlock(&ctx->rwlock);

	CAFS_LOG_DEBUG("cafs_read, expact size:%ld, offset:%ld, read size:%ld", size, offset, ret);
	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return (-EIO);
}

/*!
 * Read data from the file.
 * @param handle the cafs mount handle to use for performing the read.
 * @param fd the file descriptor of the open file to read from.
 * @param iov the iov structure to read data into
 * @param iovcnt the number of items that iov includes
 * @param offset the offset in the file to read from.  If this value is negative, the
 *        function reads from the current offset of the file descriptor.
 * @returns the number of bytes read into buf, or a negative error code on failure.
 */
int64_t cafs_preadv (cafs_mount_handle_t handle, int fd, const struct iovec *iov,
		 int iovcnt, int64_t offset)
{
  CAFS_LOG_ERROR("cafs_preadv to do.");
  CAFS_LOG_ERROR("cafs_read, iovcnt:%ld, offset:%ld", iovcnt, offset);
  return -EIO;
}
/*!
 * Write data to a file.
 *
 * @param handle the cafs mount handle to use for performing the write.
 * @param fd the file descriptor of the open file to write to
 * @param buf the bytes to write to the file
 * @param size the size of the buf array
 * @param offset the offset of the file write into.  If this value is negative, the
 *        function writes to the current offset of the file descriptor.
 * @returns the number of bytes written, or a negative error code
 */
int64_t cafs_write(cafs_mount_handle_t handle, int fd, const char *buf, int64_t size, int64_t offset)
{
  	int64_t ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	//CAFS_LOG_ERROR("cafs_write, size:%ld, offset:%ld", size, offset);
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf, CAFS_ERR, "buf is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");
	
	ret = ctx->fs->ops->write(ctx->fs, fd, buf, size, offset);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "write fail.");
	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return -EIO;
}
/*!
 * Write data to a file.
 *
 * @param handle the cafs mount handle to use for performing the write.
 * @param fd the file descriptor of the open file to write to
 * @param iov the iov structure to read data into
 * @param iovcnt the number of items that iov includes
 * @param offset the offset of the file write into.  If this value is negative, the
 *        function writes to the current offset of the file descriptor.
 * @returns the number of bytes written, or a negative error code
 */
int64_t cafs_pwritev (cafs_mount_handle_t handle, int fd, const struct iovec *iov,
		  int iovcnt, int64_t offset)
{
  CAFS_LOG_ERROR("to do.");
  return -EIO;
}
/*!
 * Truncate a file to the given size.
 *
 * @param handle the cafs mount handle to use for performing the ftruncate.
 * @param fd the file descriptor of the file to truncate
 * @param size the new size of the file
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_ftruncate (cafs_mount_handle_t handle, int fd, int64_t size)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->ftruncate(ctx->fs, fd, size);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "ftruncate fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_fallocate(cafs_mount_handle_t handle, int fd, int mode, int64_t offset, int64_t length)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->fallocate(ctx->fs, fd, mode, offset, length);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "fallocate fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_fsync(cafs_mount_handle_t handle, int fd)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->fsync(ctx->fs, fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "fsync fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 * Rename a file or directory.
 *
 * @param handle the cafs mount handle to use for performing the rename.
 * @param from the path to the existing file or directory.
 * @param to the new name of the file or directory
 * @returns 0 on success or negative error code on failure.
 */
int cafs_rename (cafs_mount_handle_t handle, const char *from, const char *to)
{
  int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!from, CAFS_ERR, "from path is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!to, CAFS_ERR, "to path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->rename(ctx->fs, from, to);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "rename from[%s] to [%s] fail.", from, to);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 * Get an open file's extended statistics and attributes.
 *
 * @param handle the cafs mount handle to use for performing the stat.
 * @param fd the file descriptor of the file to get statistics of.
 * @param stx the cafs_statx struct that will be filled in with the file's statistics.
 * @param want bitfield of cafs_STATX_* flags showing designed attributes
 * @param flags bitfield that can be used to set AT_* modifier flags (only AT_NO_ATTR_SYNC and AT_SYMLINK_NOFOLLOW)
 * @returns 0 on success or negative error code on failure.
 */
int cafs_fstatx (cafs_mount_handle_t handle, int fd, struct cafs_statx *stx,
		 unsigned int want, unsigned int flags)
{
  	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(!stx, CAFS_ERR, "stx is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->fstatx(ctx->fs, fd, stx, want, flags);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "ftruncate fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
/*!
 * Get a file's extended statistics and attributes.
 *
 * @param handle the cafs mount handle to use for performing the stat.
 * @param path the file or directory to get the statistics of.
 * @param stx the cafs_statx struct that will be filled in with the file's statistics.
 * @param want bitfield of cafs_STATX_* flags showing designed attributes
 * @param flags bitfield that can be used to set AT_* modifier flags (only AT_NO_ATTR_SYNC and AT_SYMLINK_NOFOLLOW)
 * @returns 0 on success or negative error code on failure.
 */
int cafs_statx (cafs_mount_handle_t handle, const char *path,
		struct cafs_statx *stx, unsigned int want, unsigned int flags)
{
    int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->statx(ctx->fs, path, stx, want, flags);
	LOG_DEBUG_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "statx[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}
static void statx2stat(const struct cafs_statx *stx, struct stat *stbuf)
{
	stbuf->st_ino = stx->stx_ino;
	stbuf->st_gid = stx->stx_gid;
	stbuf->st_nlink = stx->stx_nlink;
	stbuf->st_size = stx->stx_size;
	stbuf->st_mode = stx->stx_mode;
	stbuf->st_uid = stx->stx_uid;
	stbuf->st_ino = stx->stx_ino;
	stbuf->st_blksize = stx->stx_blksize;
	stbuf->st_blocks = stx->stx_blocks;
	stbuf->st_ctime = stx->stx_ctime.tv_sec;
	stbuf->st_atime = stx->stx_atime.tv_sec;
	stbuf->st_mtime = stx->stx_mtime.tv_sec;
	stbuf->st_dev= 0;
	stbuf->st_rdev= 0;
}
/*!
 * Get a file's statistics and attributes.
 *
 * @param handle the cafs mount handle to use for performing the stat.
 * @param path the file or directory to get the statistics of.
 * @param stbuf the stat struct that will be filled in with the file's statistics.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_stat (cafs_mount_handle_t handle, const char *path, struct stat *stbuf)
{
    int ret = 0;
	struct cafs_statx stx;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	memset(&stx, 0, sizeof(stx));
	ret = ctx->fs->ops->statx(ctx->fs, path, &stx, 0, 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "statx[%s] fail.", path);

	statx2stat(&stx, stbuf);
	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

/*!
 * Get a file's statistics and attributes, without following symlinks.
 *
 * @param handle the cafs mount handle to use for performing the stat.
 * @param path the file or directory to get the statistics of.
 * @param stbuf the stat struct that will be filled in with the file's statistics.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_lstat (cafs_mount_handle_t handle, const char *path, struct stat *stbuf)
{
    int ret = 0;
	struct cafs_statx stx;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	memset(&stx, 0, sizeof(stx));
	ret = ctx->fs->ops->statx(ctx->fs, path, &stx, 0, 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "statx[%s] fail.", path);

	statx2stat(&stx, stbuf);
	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_setattrx(cafs_mount_handle_t handle, const char *path, struct cafs_statx *stx, int mask, int flags)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(mask&CAFS_SETATTR_SIZE, unlock, "setattrx size [%s] forbid.", path);

	ret = ctx->fs->ops->setattrx(ctx->fs, path, stx, mask, flags);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "setattrx[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_fsetattrx(cafs_mount_handle_t handle, int fd, struct cafs_statx *stx, int mask)
{
	int ret = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	ret = ctx->fs->ops->fsetattrx(ctx->fs, fd, stx, mask);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "setattrx fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_chmod(cafs_mount_handle_t handle, const char *path, mode_t mode)
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_mode = (mode&(~S_IFMT));
	mask |= CAFS_SETATTR_MODE;
	ret = ctx->fs->ops->setattrx(ctx->fs, path, &stx, mask, 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "chmod[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_fchmod(cafs_mount_handle_t handle, int fd, mode_t mode)
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_mode = (mode&(~S_IFMT));
	mask |= CAFS_SETATTR_MODE;

	ret = ctx->fs->ops->fsetattrx(ctx->fs, fd, &stx, mask);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "setattrx fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_chown(cafs_mount_handle_t handle, const char *path, int uid, int gid)
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_gid = gid;
	stx.stx_uid = uid;
	mask = CAFS_SETATTR_GID|CAFS_SETATTR_UID;
	ret = ctx->fs->ops->setattrx(ctx->fs, path, &stx, mask, 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "chown[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_fchown(cafs_mount_handle_t handle, int fd, int uid, int gid)
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_gid = gid;
	stx.stx_uid = uid;
	mask = CAFS_SETATTR_GID|CAFS_SETATTR_UID;
	ret = ctx->fs->ops->fsetattrx(ctx->fs, fd, &stx, mask);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "fchown fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_lchown(cafs_mount_handle_t handle, const char *path, int uid, int gid)
{
	CAFS_LOG_ERROR("to do");
	return CAFS_ERR;
}

int cafs_utime(cafs_mount_handle_t handle, const char *path, struct utimbuf *buf)
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf, CAFS_ERR, "buf is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_mtime.tv_sec = buf->modtime;
	stx.stx_atime.tv_sec = buf->actime;
	mask = CAFS_SETATTR_ATIME|CAFS_SETATTR_MTIME;
	ret = ctx->fs->ops->setattrx(ctx->fs, path, &stx, mask, 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "chown[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_futime(cafs_mount_handle_t handle, int fd, struct utimbuf *buf)
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf, CAFS_ERR, "buf is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_mtime.tv_sec = buf->modtime;
	stx.stx_atime.tv_sec = buf->actime;
	mask = CAFS_SETATTR_ATIME|CAFS_SETATTR_MTIME;
	ret = ctx->fs->ops->fsetattrx(ctx->fs, fd, &stx, mask);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "fchown fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_utimes(cafs_mount_handle_t handle, const char *path, struct timeval times[2])
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!times, CAFS_ERR, "times is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_atime.tv_sec = times[0].tv_sec;
	stx.stx_atime.tv_nsec = times[0].tv_usec*1000;
	stx.stx_mtime.tv_sec = times[1].tv_sec;
	stx.stx_mtime.tv_nsec = times[1].tv_usec*1000;

	mask = CAFS_SETATTR_ATIME|CAFS_SETATTR_MTIME;
	ret = ctx->fs->ops->setattrx(ctx->fs, path, &stx, mask, 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "utimes[%s] fail.", path);

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_lutimes(cafs_mount_handle_t handle, const char *path, struct timeval times[2])
{
	CAFS_LOG_ERROR("to do");
	return CAFS_ERR;
}

int cafs_futimes(cafs_mount_handle_t handle, int fd, struct timeval times[2])
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(!times, CAFS_ERR, "times is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_atime.tv_sec = times[0].tv_sec;
	stx.stx_atime.tv_nsec = times[0].tv_usec*1000;
	stx.stx_mtime.tv_sec = times[1].tv_sec;
	stx.stx_mtime.tv_nsec = times[1].tv_usec*1000;

	mask = CAFS_SETATTR_ATIME|CAFS_SETATTR_MTIME;
	ret = ctx->fs->ops->fsetattrx(ctx->fs, fd, &stx, mask);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "fchown fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}

int cafs_futimens(cafs_mount_handle_t handle, int fd, struct timespec times[2])
{
	int ret = 0;
	struct cafs_statx stx = {0};
	int mask = 0;
	MOUNT_HANDLE_CTX(ctx, handle, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, CAFS_ERR, "fd[%d] is negative.", fd);
	LOG_THEN_RETURN_VAL_IF_TRUE(!times, CAFS_ERR, "times is null.");

	cafs_rwlock_rdlock(&ctx->rwlock);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->is_inited, unlock, "it must be initialized before mounting.");

	stx.stx_atime.tv_sec = times[0].tv_sec;
	stx.stx_atime.tv_nsec = times[0].tv_sec;
	stx.stx_mtime.tv_sec = times[1].tv_sec;
	stx.stx_mtime.tv_nsec = times[1].tv_nsec;
	
	mask = CAFS_SETATTR_ATIME|CAFS_SETATTR_MTIME;
	ret = ctx->fs->ops->fsetattrx(ctx->fs, fd, &stx, mask);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "fchown fail.");

	cafs_rwlock_unlock(&ctx->rwlock);

	return ret;
unlock:
	cafs_rwlock_unlock(&ctx->rwlock);

	return CAFS_ERR;
}