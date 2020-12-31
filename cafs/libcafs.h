/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */

/*!
* \file libcafs.h
* \brief ca文件系统接口
* 
*  主要用于定义ca对外文件系统接口和数据结构
*
* \copyright 2020 Ruijie Network. All rights reserved.
* \author hongchunhua@ruijie.com.cn
* \version v1.0.0
* \date 2020.08.06
* \note none 
*/

#ifndef _LIBCAFS_H_
#define _LIBCAFS_H_

#include <utime.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef void* cafs_mount_handle_t;
struct iovec;

/*! @brief 文件系统文件名称最长字节数 */
#define FS_MAX_FILE_NAME_LIMIT  1024

/*!
 * @brief  文件系统参数信息
 *
 * @details
 *  该参数为挂载ca对外提供文件系统服务的基础参数
 *  
 */
struct cafs_mount_info {
    char *config_path;		/*! @brief 配置文件路径，字符串形式 */
	uint64_t usr_id;
    void *usr_ctx;		    /*! @brief 调用者上下文 */
};

/*!
 *  @brief  创建一个文件系统句柄，所有的文件操作需要该句柄
 *    
 *    主要是加载本地配置参数，为初始化做准备
 *  @param[in]  conf_ctx，  挂载参数,由调用者配置
 *  @param[out] out_handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_create(struct cafs_mount_info *conf_ctx, cafs_mount_handle_t *out_handle);

/*!
 *  @brief  初始化CA系统，不挂载文件
 *    初始化，主要完成远程资源获取能力。如连接配置中心建立并获取，建立session，鉴权等
 *    初始化成功后，说明已经具备文件系统操作能力，可以进行文件系统操作，如mount
 * 
 *  @param[in]  handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_init(cafs_mount_handle_t handle);

/*!
 *  @brief  清理资源，退出文件系统。需要先umount后执行
 *    
 *    
 * 
 *  @param[inout]  handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_finish(cafs_mount_handle_t handle);

/*!
 *  @brief  挂载文件系统
 *
 *  @param[in]  info  挂载参数
 *  @param[out] out_handle  文件系统句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_mount(cafs_mount_handle_t handle, const char *root);

/*!
 *  @brief  卸载文件系统
 *
 *  @param[inout] handle  文件系统句柄，卸载成功则设置为NULL
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_unmount(cafs_mount_handle_t handle);

/*!
 *  @brief  获取文件系统信息
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path    文件路径
 *  @param[out] stbuf   文件系统信息
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_statfs (cafs_mount_handle_t handle, const char *path,
		     struct statvfs *stbuf);

/* ------------------------------------------<Directory>---------------------------------- */

struct cafs_dir;

/*!
 * @brief Get the current working directory.
 *
 * @param handle the cafs mount to get the current working directory for.
 * @returns the path to the current working directory
 */
const char *cafs_getcwd(cafs_mount_handle_t handle);

/*!
 * @brief Change the current working directory.
 *
 * @param handle the cafs mount to change the current working directory for.
 * @param path the path to the working directory to change into.
 * @returns 0 on success, negative error code otherwise.
 */
int cafs_chdir(cafs_mount_handle_t handle, const char *path);

/*!
 *  @brief  打开一个目录
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  name    目录路径
 *  @param[out] dirp   目录句柄
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_opendir(cafs_mount_handle_t handle, const char *name,
		      struct cafs_dir **dirpp);

/*!
 *  @brief  关闭一个已打开的目录信息
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[inout] dirp   目录句柄,关闭成功会被置空
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 */
int cafs_closedir(cafs_mount_handle_t handle, struct cafs_dir *dirp);

/*!
 *  @brief  读取下一个目录信息
 *  注意：函数非安全情况，当目录操作符号dirp提前释放，则dirent也被释放，在访问则会段错误！
 * 
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp  目录句柄
 *  @return  struct dirent *; (<em>NULL</em>: fail ; ( <em>others</em>: succeed
 *
 */
struct dirent *cafs_readdir(cafs_mount_handle_t handle,
			     struct cafs_dir *dirp);

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
  int cafs_readdir_r(cafs_mount_handle_t handle, struct cafs_dir *dirp,
			struct dirent *de);

/*!
 *  @brief  获取当前目录索引位置（偏移量）
 *   
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp    目录句柄
 *  @return  int64_t, 目录索引偏移量; (<em>小于0</em>: fail ; ( <em>大于等于0</em>: succeed
 *
 */
  int64_t cafs_telldir(cafs_mount_handle_t handle, struct cafs_dir *dirp);

/*!
 *  @brief  根据偏移量移动到对应的目录指向位置
 *   
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp    目录句柄
 *  @param[in]  offset  偏移量，该偏移量必须是由telldir返回的值来确定
 *  @return  void;
 *
 */
  void cafs_seekdir(cafs_mount_handle_t handle, struct cafs_dir *dirp,
		   int64_t offset);

/*!
 *  @brief  回到目录索引起始位置
 *   
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  dirp    目录句柄
 *  @return  void;
 *
 */
  void cafs_rewinddir(cafs_mount_handle_t handle, struct cafs_dir *dirp);

/*!
 *  @brief  创建目录
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path the path of the directory to create.  This must be either an
 *        absolute path or a relative path off of the current working directory.
 *  @param[in]  mode the permissions the directory should have once created.
 *  @returns 0 on success or a negative return code on error.
 */
  int cafs_mkdir(cafs_mount_handle_t handle, const char *path, mode_t mode);

/*!
 *  @brief  删除目录
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path the path of the directory to remove.
 *  @returns 0 on success or a negative return code on error.
 */
  int cafs_rmdir(cafs_mount_handle_t handle, const char *path);

/* ------------------------------------------<LINK>---------------------------------- */

/*!
 * Create a link.
 *
 *  @param[in] handle  文件系统句柄
 *  @param[in] existing the path to the existing file/directory to link to.
 *  @param[in] newname the path to the new file/directory to link from.
 *  @returns 0 on success or a negative return code on error.
 */
  int cafs_link(cafs_mount_handle_t handle, const char *existing,
		   const char *newname);
/*!
 * Removes a file, link, or symbolic link.  If the file/link has multiple links to it, the
 * file will not disappear from the namespace until all references to it are removed.
 * 
 *  @param[in] handle  文件系统句柄
 *  @param[in] path the path of the file or link to unlink.
 *  @returns 0 on success or negative error code on failure.
 */
int cafs_unlink(cafs_mount_handle_t handle, const char *path);

/*!
 * Creates a symbolic link.
 *
 *  @param[in] handle  文件系统句柄
 *  @param[in] existing the path to the existing file/directory to link to.
 *  @param[in] newname the path to the new file/directory to link from.
 *  @returns 0 on success or a negative return code on failure.
 */
int cafs_symlink(cafs_mount_handle_t handle, const char *existing,
		      const char *newname);

/*!
 * Read a symbolic link.
 *
 *  @param[in]  handle  文件系统句柄
 *  @param[in]  path the path to the symlink to read
 *  @param[out] buf the buffer to hold the path of the file that the symlink points to.
 *  @param[in]  size the length of the buffer
 *  @returns number of bytes copied on success or negative error code on failure
 */
int cafs_readlink(cafs_mount_handle_t handle, const char *path, char *buf,
		       int64_t size);
/* ------------------------------------------<File>---------------------------------- */

struct cafs_statx {
	uint32_t	stx_mask;
	uint32_t	stx_blksize;
	uint32_t	stx_nlink;
	uint32_t	stx_uid;
	uint32_t	stx_gid;
	uint16_t	stx_mode;
	uint64_t	stx_ino;
	uint64_t	stx_size;
	uint64_t	stx_blocks;
	dev_t		stx_dev;
	dev_t		stx_rdev;
	struct timespec	stx_atime;
	struct timespec	stx_ctime;
	struct timespec	stx_mtime;
	struct timespec	stx_btime;
	uint64_t	stx_version;
};

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
  int cafs_open (cafs_mount_handle_t handle, const char *path, int flags,
	       mode_t mode);

/*!
 * Close the open file.
 *
 * @param handle the cafs mount handle to use for performing the close.
 * @param fd the file descriptor referring to the open file.
 * @returns 0 on success or a negative error code on failure.
 */
  int cafs_close (cafs_mount_handle_t handle, int fd);

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
  int64_t cafs_lseek(cafs_mount_handle_t handle, int fd, int64_t offset,
		    int whence);
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
  int64_t cafs_read(cafs_mount_handle_t handle, int fd, char *buf, int64_t size,
	       int64_t offset);

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
  int64_t cafs_preadv(cafs_mount_handle_t handle, int fd, const struct iovec *iov,
		 int iovcnt, int64_t offset);

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
  int64_t cafs_write(cafs_mount_handle_t handle, int fd, const char *buf, int64_t size,
		int64_t offset);

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
  int64_t cafs_pwritev(cafs_mount_handle_t handle, int fd, const struct iovec *iov,
		  int iovcnt, int64_t offset);

/*!
 * Truncate a file to the given size.
 *
 * @param handle the cafs mount handle to use for performing the ftruncate.
 * @param fd the file descriptor of the file to truncate
 * @param size the new size of the file
 * @returns 0 on success or a negative error code on failure.
 */
  int cafs_ftruncate(cafs_mount_handle_t handle, int fd, int64_t size);

/*!
 * Rename a file or directory.
 *
 * @param handle the cafs mount handle to use for performing the rename.
 * @param from the path to the existing file or directory.
 * @param to the new name of the file or directory
 * @returns 0 on success or negative error code on failure.
 */
  int cafs_rename(cafs_mount_handle_t handle, const char *from, const char *to);

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
		 unsigned int want, unsigned int flags);

/**
 * Preallocate or release disk space for the file for the byte range.
 *
 * @param handle the cafs mount handle to use for performing the fallocate.
 * @param fd the file descriptor of the file to fallocate.
 * @param mode the flags determines the operation to be performed on the given range.
 *        default operation (0) allocate and initialize to zero the file in the byte range,
 *        and the file size will be changed if offset + length is greater than
 *        the file size. if the FALLOC_FL_KEEP_SIZE flag is specified in the mode,
 *        the file size will not be changed. if the FALLOC_FL_PUNCH_HOLE flag is
 *        specified in the mode, the operation is deallocate space and zero the byte range.
 * @param offset the byte range starting.
 * @param length the length of the range.
 * @return 0 on success or a negative error code on failure.
 */
int cafs_fallocate(cafs_mount_handle_t handle, int fd, int mode, int64_t offset, int64_t length);

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
  int cafs_statxattr(cafs_mount_handle_t handle, const char *path, struct cafs_statx *stx, unsigned int want, unsigned int flags);

/*!
 * Get a file's statistics and attributes.
 *
 * @param handle the cafs mount handle to use for performing the stat.
 * @param path the file or directory to get the statistics of.
 * @param stbuf the stat struct that will be filled in with the file's statistics.
 * @returns 0 on success or negative error code on failure.
 */
  int cafs_stat(cafs_mount_handle_t handle, const char *path, struct stat *stbuf);

/*!
 * Get a file's statistics and attributes, without following symlinks.
 *
 * @param handle the cafs mount handle to use for performing the stat.
 * @param path the file or directory to get the statistics of.
 * @param stbuf the stat struct that will be filled in with the file's statistics.
 * @returns 0 on success or negative error code on failure.
 */
  int cafs_lstat(cafs_mount_handle_t handle, const char *path, struct stat *stbuf);


#define CAFS_SETATTR_MODE  	(1<<0)
#define CAFS_SETATTR_UID  	(1<<1)
#define CAFS_SETATTR_GID  	(1<<2)
#define CAFS_SETATTR_SIZE  	(1<<3)
#define CAFS_SETATTR_ATIME 	(1<<4)
#define CAFS_SETATTR_MTIME 	(1<<5)
#define CAFS_SETATTR_CTIME 	(1<<6)
/**
 * Set a file's attributes.
 *
 * @param handle the cafs mount handle to use for performing the setattr.
 * @param path the path to the file/directory to set the attributes of.
 * @param stx the statx struct that must include attribute values to set on the file.
 * @param mask a mask of all the CAFS_SETATTR_* values that have been set in the statx struct.
 * @param flags mask of AT_* flags (only AT_ATTR_NOFOLLOW is respected for now)
 * @returns 0 on success or negative error code on failure.
 */
int cafs_setattrx(cafs_mount_handle_t handle, const char *path, struct cafs_statx *stx, int mask, int flags);

/**
 * Set a file's attributes (extended version).
 * 
 * @param handle the cafs mount handle to use for performing the setattr.
 * @param fd the fd of the open file/directory to set the attributes of.
 * @param stx the statx struct that must include attribute values to set on the file.
 * @param mask a mask of all the stat values that have been set on the stat struct.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_fsetattrx(cafs_mount_handle_t handle, int fd, struct cafs_statx *stx, int mask);

/**
 * Change the mode bits (permissions) of a file/directory.
 *
 * @param handle the cafs mount handle to use for performing the chmod.
 * @param path the path to the file/directory to change the mode bits on.
 * @param mode the new permissions to set.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_chmod(cafs_mount_handle_t handle, const char *path, mode_t mode);

/**
 * Change the mode bits (permissions) of an open file.
 *
 * @param handle the cafs mount handle to use for performing the chmod.
 * @param fd the open file descriptor to change the mode bits on.
 * @param mode the new permissions to set.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_fchmod(cafs_mount_handle_t handle, int fd, mode_t mode);

/**
 * Change the ownership of a file/directory.
 * 
 * @param handle the cafs mount handle to use for performing the chown.
 * @param path the path of the file/directory to change the ownership of.
 * @param uid the user id to set on the file/directory.
 * @param gid the group id to set on the file/directory.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_chown(cafs_mount_handle_t handle, const char *path, int uid, int gid);

/**
 * Change the ownership of a file from an open file descriptor.
 *
 * @param handle the cafs mount handle to use for performing the chown.
 * @param fd the fd of the open file/directory to change the ownership of.
 * @param uid the user id to set on the file/directory.
 * @param gid the group id to set on the file/directory.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_fchown(cafs_mount_handle_t handle, int fd, int uid, int gid);

/**
 * Change the ownership of a file/directory, don't follow symlinks.
 * 
 * @param handle the cafs mount handle to use for performing the chown.
 * @param path the path of the file/directory to change the ownership of.
 * @param uid the user id to set on the file/directory.
 * @param gid the group id to set on the file/directory.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_lchown(cafs_mount_handle_t handle, const char *path, int uid, int gid);

/**
 * Change file/directory last access and modification times.
 *
 * @param handle the cafs mount handle to use for performing the utime.
 * @param path the path to the file/directory to set the time values of.
 * @param buf holding the access and modification times to set on the file.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_utime(cafs_mount_handle_t handle, const char *path, struct utimbuf *buf);

/**
 * Change file/directory last access and modification times.
 *
 * @param handle the cafs mount handle to use for performing the utime.
 * @param fd the fd of the open file/directory to set the time values of.
 * @param buf holding the access and modification times to set on the file.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_futime(cafs_mount_handle_t handle, int fd, struct utimbuf *buf);

/**
 * Change file/directory last access and modification times.
 *
 * @param handle the cafs mount handle to use for performing the utime.
 * @param path the path to the file/directory to set the time values of.
 * @param times holding the access and modification times to set on the file.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_utimes(cafs_mount_handle_t handle, const char *path, struct timeval times[2]);

/**
 * Change file/directory last access and modification times, don't follow symlinks.
 *
 * @param handle the cafs mount handle to use for performing the utime.
 * @param path the path to the file/directory to set the time values of.
 * @param times holding the access and modification times to set on the file.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_lutimes(cafs_mount_handle_t handle, const char *path, struct timeval times[2]);

/**
 * Change file/directory last access and modification times.
 *
 * @param handle the cafs mount handle to use for performing the utime.
 * @param fd the fd of the open file/directory to set the time values of.
 * @param times holding the access and modification times to set on the file.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_futimes(cafs_mount_handle_t handle, int fd, struct timeval times[2]);

/**
 * Change file/directory last access and modification times.
 *
 * @param handle the cafs mount handle to use for performing the utime.
 * @param fd the fd of the open file/directory to set the time values of.
 * @param times holding the access and modification times to set on the file.
 * @returns 0 on success or negative error code on failure.
 */
int cafs_futimens(cafs_mount_handle_t handle, int fd, struct timespec times[2]);

/* ------------------------------------------<xattr>---------------------------------- */

/**
 * Get an extended attribute.
 *
 * @param handle the cafs mount handle to use for performing the getxattr.
 * @param path the path to the file
 * @param name the name of the extended attribute to get
 * @param value a pre-allocated buffer to hold the xattr's value
 * @param size the size of the pre-allocated buffer
 * @returns the size of the value or a negative error code on failure.
 */
int cafs_getxattr(cafs_mount_handle_t handle, const char *path, const char *name, 
	void *value, size_t size);

/**
 * Get an extended attribute.
 *
 * @param handle the cafs mount handle to use for performing the getxattr.
 * @param fd the open file descriptor referring to the file to get extended attribute from.
 * @param name the name of the extended attribute to get
 * @param value a pre-allocated buffer to hold the xattr's value
 * @param size the size of the pre-allocated buffer
 * @returns the size of the value or a negative error code on failure.
 */
int cafs_fgetxattr(cafs_mount_handle_t handle, int fd, const char *name,
	void *value, size_t size);

/**
 * Get an extended attribute without following symbolic links.  This function is
 * identical to cafs_getxattr, but if the path refers to a symbolic link,
 * we get the extended attributes of the symlink rather than the attributes
 * of the link itself.
 *
 * @param handle the cafs mount handle to use for performing the lgetxattr.
 * @param path the path to the file
 * @param name the name of the extended attribute to get
 * @param value a pre-allocated buffer to hold the xattr's value
 * @param size the size of the pre-allocated buffer
 * @returns the size of the value or a negative error code on failure.
 */
int cafs_lgetxattr(cafs_mount_handle_t handle, const char *path, const char *name, 
	void *value, size_t size);

/**
 * List the extended attribute keys on a file.
 *
 * @param handle the cafs mount handle to use for performing the listxattr.
 * @param path the path to the file.
 * @param list a buffer to be filled in with the list of extended attributes keys.
 * @param size the size of the list buffer.
 * @returns the size of the resulting list filled in.
 */
int cafs_listxattr(cafs_mount_handle_t handle, const char *path, char *list, size_t size);

/**
 * List the extended attribute keys on a file.
 *
 * @param handle the cafs mount handle to use for performing the listxattr.
 * @param fd the open file descriptor referring to the file to list extended attributes on.
 * @param list a buffer to be filled in with the list of extended attributes keys.
 * @param size the size of the list buffer.
 * @returns the size of the resulting list filled in.
 */
int cafs_flistxattr(cafs_mount_handle_t handle, int fd, char *list, size_t size);

/**
 * Get the list of extended attribute keys on a file, but do not follow symbolic links.
 *
 * @param handle the cafs mount handle to use for performing the llistxattr.
 * @param path the path to the file.
 * @param list a buffer to be filled in with the list of extended attributes keys.
 * @param size the size of the list buffer.
 * @returns the size of the resulting list filled in.
 */
int cafs_llistxattr(cafs_mount_handle_t handle, const char *path, char *list, size_t size);

/**
 * Remove an extended attribute from a file.
 *
 * @param handle the cafs mount handle to use for performing the removexattr.
 * @param path the path to the file.
 * @param name the name of the extended attribute to remove.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_removexattr(cafs_mount_handle_t handle, const char *path, const char *name);

/**
 * Remove an extended attribute from a file.
 *
 * @param handle the cafs mount handle to use for performing the removexattr.
 * @param fd the open file descriptor referring to the file to remove extended attribute from.
 * @param name the name of the extended attribute to remove.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_fremovexattr(cafs_mount_handle_t handle, int fd, const char *name);

/**
 * Remove the extended attribute from a file, do not follow symbolic links.
 *
 * @param handle the cafs mount handle to use for performing the lremovexattr.
 * @param path the path to the file.
 * @param name the name of the extended attribute to remove.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_lremovexattr(cafs_mount_handle_t handle, const char *path, const char *name);

/**
 * Set an extended attribute on a file.
 *
 * @param handle the cafs mount handle to use for performing the setxattr.
 * @param path the path to the file.
 * @param name the name of the extended attribute to set.
 * @param value the bytes of the extended attribute value
 * @param size the size of the extended attribute value
 * @param flags the flags can be:
 *	cafs_XATTR_CREATE: create the extended attribute.  Must not exist.
 *      cafs_XATTR_REPLACE: replace the extended attribute, Must already exist.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_setxattr(cafs_mount_handle_t handle, const char *path, const char *name, 
	const void *value, size_t size, int flags);

/**
 * Set an extended attribute on a file.
 *
 * @param handle the cafs mount handle to use for performing the setxattr.
 * @param fd the open file descriptor referring to the file to set extended attribute on.
 * @param name the name of the extended attribute to set.
 * @param value the bytes of the extended attribute value
 * @param size the size of the extended attribute value
 * @param flags the flags can be:
 *	cafs_XATTR_CREATE: create the extended attribute.  Must not exist.
 *      cafs_XATTR_REPLACE: replace the extended attribute, Must already exist.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_fsetxattr(cafs_mount_handle_t handle, int fd, const char *name,
	const void *value, size_t size, int flags);

/**
 * Set an extended attribute on a file, do not follow symbolic links.
 *
 * @param handle the cafs mount handle to use for performing the lsetxattr.
 * @param path the path to the file.
 * @param name the name of the extended attribute to set.
 * @param value the bytes of the extended attribute value
 * @param size the size of the extended attribute value
 * @param flags the flags can be:
 *	cafs_XATTR_CREATE: create the extended attribute.  Must not exist.
 *      cafs_XATTR_REPLACE: replace the extended attribute, Must already exist.
 * @returns 0 on success or a negative error code on failure.
 */
int cafs_lsetxattr(cafs_mount_handle_t handle, const char *path, const char *name, 
	const void *value, size_t size, int flags);

#ifdef __cplusplus
}
#endif

#endif				/* _LIB_CA_FS_H */
