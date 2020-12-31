/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Brian Chrisman 2011 <bchrisman@gmail.com>
   Copyright (C) Richard Sharpe 2011 <realrichardsharpe@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * This VFS only works with the libceph.so user-space client. It is not needed
 * if you are using the kernel client or the FUSE client.
 *
 * Add the following smb.conf parameter to each share that will be hosted on
 * cafs:
 *
 *   vfs objects = cafs [any others you need go here]
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include "cafs/libcafs.h"
#include "smbprofile.h"
#include "smbd/globals.h"
#include "modules/posixacl_xattr.h"
#include "lib/util/tevent_unix.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifndef LIBCEPHFS_VERSION
#define LIBCEPHFS_VERSION(maj, min, extra) ((maj << 16) + (min << 8) + extra)
#define LIBCEPHFS_VERSION_CODE LIBCEPHFS_VERSION(0, 0, 0)
#endif

/*
 * Use %llu whenever we have a 64bit unsigned int, and cast to (long long unsigned)
 */
#define llu(_var) ((long long unsigned)_var)

/*
 * Note, libceph's return code model is to return -errno! So we have to convert
 * to what Samba expects, with is set errno to -return and return -1
 */
#define WRAP_RETURN(_res) \
	errno = 0; \
	if (_res < 0) { \
		errno = -_res; \
		return -1; \
	} \
	return _res \

#define CAFS_CTX(cafs_ctx, vfs_ctx, ret)\
cafs_mount_handle_t cafs_ctx;\
if (!vfs_ctx){DBG_ERR("[ CAFS ] vfs handle is null fail.");return ret;};\
cafs_ctx = (cafs_mount_handle_t)vfs_ctx->data;

static char *get_realpath(struct vfs_handle_struct *handle, const struct smb_filename *smb_fname)
{
	char *result = NULL;
	const char *path = smb_fname->base_name;
	const char *cwd = cafs_getcwd(handle->data);
	size_t len = strlen(path);
	int r = -1;
	if (len && (path[0] == '/')) {
		r = asprintf(&result, "%s", path);
	} else if ((len >= 2) && (path[0] == '.') && (path[1] == '/')) {
		if (len == 2) {
			r = asprintf(&result, "%s", cwd);
		} else {
			r = asprintf(&result, "%s/%s", cwd, &path[2]);
		}
	} else if ((len == 1) && (path[0] == '.')) {
		r = asprintf(&result, "%s",cwd);
	} else if (strcmp(cwd, "/") == 0) {
		r = asprintf(&result, "%s%s",cwd, path);
	}else{
		r = asprintf(&result, "%s/%s",cwd, path);
	}
	
	if (r < 0) {
		return NULL;
	}
	
	return result;
}

/*
 * We mount only one file system and then all shares are assumed to be in that.
 * FIXME: If we want to support more than one FS, then we have to deal with
 * this differently.
 *
 * So, cmount tells us if we have been this way before and whether
 * we need to mount ceph and cmount_cnt tells us how many times we have
 * connected
 */

/* Check for NULL pointer parameters in cafswrap_* functions */

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

static int cafswrap_connect(struct vfs_handle_struct *handle,  const char *service, const char *user)
{
	int ret;
	int snum = SNUM(handle->conn);
	cafs_mount_handle_t cafs_ctx = NULL;
	struct cafs_mount_info cafs_cfg;
	char *cfg_file;
	const char *user_id;
	const char *mount_path;
	const char *access_path;
	int is_add_username = 0;
	char usr_mount[512] = {0};

	cfg_file = lp_parm_const_string(snum, "cafs", "cfg_file", "/etc/cafs/cafs.conf");
	user_id = lp_parm_const_string(snum, "cafs", "user_id", "10086");
	mount_path = lp_parm_const_string(snum, "cafs", "mount_path", "/home");
	is_add_username = lp_parm_int(snum, "cafs", "add_username", 1);
	access_path = handle->conn->connectpath;

	memset(&cafs_cfg, 0, sizeof(cafs_cfg));
	cafs_cfg.config_path = (char*)cfg_file;
	cafs_cfg.usr_id = atoi(user_id);
	cafs_cfg.usr_ctx = handle;

	ret = cafs_create(&cafs_cfg, &cafs_ctx);
	if (ret) {
		DBG_ERR("[ CAFS ] cafs_create fail.");
		goto err_out;
	}

	ret = cafs_init(cafs_ctx);
	if (ret) {
		DBG_ERR("[ CAFS ] cafs_init fail.");
		goto err_out;
	}
	DBG_NOTICE("[ CAFS ] mount root:[%s]-----.\n", mount_path);
	DBG_NOTICE("[ CAFS ] user name:[%s]-----.\n", get_current_username());
	DBG_NOTICE("[ CAFS ] access_path:[%s]-----.\n", access_path);

	if(is_add_username){
		snprintf(usr_mount, sizeof(usr_mount), "%s/%s", mount_path, get_current_username());
	}else{
		snprintf(usr_mount, sizeof(usr_mount), "%s/", mount_path);
	}
	DBG_NOTICE("[ CAFS ] cafs mount path:[%s]-----.\n", usr_mount);

	ret = cafs_mount(cafs_ctx, usr_mount);// 默认根目录
	if (ret) {
		DBG_ERR("[ CAFS ] cafs_mount path:%s fail.", usr_mount);
		goto err_cm_release;
	}

	DBG_NOTICE("[ CAFS ] : mount cafs path[%s] success!\n", usr_mount);
	handle->data = cafs_ctx;

	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");

	return 0;
err_cm_release:
	(void)cafs_finish(cafs_ctx);

err_out:
	/*
	 * Handle the error correctly. Ceph returns -errno.
	 */
	DBG_DEBUG("[ CAFS ] Error return: %s\n", strerror(-ret));
	WRAP_RETURN(ret);
}

static void cafswrap_disconnect(struct vfs_handle_struct *handle)
{
	int ret;

	CAFS_CTX(cafs_ctx, handle, ;);

	ret = cafs_unmount(cafs_ctx);
	if (ret) {
		DBG_ERR("[ CAFS ] cafs_unmount fail.");
	}

	ret = cafs_finish(cafs_ctx);
	if (ret) {
		DBG_ERR("[ CAFS ] cafs_finish fail.");
	}
	handle->data = NULL;
}

/* Disk operations */

static uint64_t cafswrap_disk_free(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	struct statvfs statvfs_buf;
	int ret;
	CAFS_CTX(cafs_ctx, handle, 0);

	if (!(ret = cafs_statfs(cafs_ctx, smb_fname->base_name, &statvfs_buf))) {
		/*
		 * Provide all the correct values.
		 */
		*bsize = statvfs_buf.f_bsize;
		*dfree = statvfs_buf.f_bavail;
		*dsize = statvfs_buf.f_blocks;
		DBG_DEBUG("[ CAFS ] bsize: %llu, dfree: %llu, dsize: %llu\n",
			llu(*bsize), llu(*dfree), llu(*dsize));
		return *dfree;
	} else {
		DBG_DEBUG("[ CAFS ] cafs_statfs returned %d\n", ret);
		WRAP_RETURN(ret);
	}
}

static int cafswrap_get_quota(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt)
{
	WRAP_RETURN(-ENOSYS);
}

static int cafswrap_set_quota(struct vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt)
{
	WRAP_RETURN(-ENOSYS);
}

static int cafswrap_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				vfs_statvfs_struct *statbuf)
{
	int ret;
	struct statvfs statvfs_buf;
	CAFS_CTX(cafs_ctx, handle, -1);

	ret = cafs_statfs(cafs_ctx, smb_fname->base_name, &statvfs_buf);
	if (ret) {
		DBG_ERR("[ CAFS ] cafs_statfs fail.");
		return -1;
	}

	statbuf->OptimalTransferSize = statvfs_buf.f_frsize;
	statbuf->BlockSize = statvfs_buf.f_bsize;
	statbuf->TotalBlocks = statvfs_buf.f_blocks;
	statbuf->BlocksAvail = statvfs_buf.f_bfree;
	statbuf->UserBlocksAvail = statvfs_buf.f_bavail;
	statbuf->TotalFileNodes = statvfs_buf.f_files;
	statbuf->FreeFileNodes = statvfs_buf.f_ffree;
	statbuf->FsIdentifier = statvfs_buf.f_fsid;
	DBG_DEBUG("[ CAFS ] f_bsize: %ld, f_blocks: %ld, f_bfree: %ld, f_bavail: %ld\n",
		(long int)statvfs_buf.f_bsize, (long int)statvfs_buf.f_blocks,
		(long int)statvfs_buf.f_bfree, (long int)statvfs_buf.f_bavail);

	return 0;
}

static uint32_t cafswrap_fs_capabilities(struct vfs_handle_struct *handle,
					 enum timestamp_set_resolution *p_ts_res)
{
	uint32_t caps = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;

	*p_ts_res = TIMESTAMP_SET_NT_OR_BETTER;

	return caps;
}

/* Directory operations */

static DIR *cafswrap_opendir(struct vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname,
			     const char *mask, uint32_t attr)
{
	int ret = 0;
	struct cafs_dir *result;
	char *real_path;
	CAFS_CTX(cafs_ctx, handle, NULL);

	DBG_DEBUG("[ CAFS ] opendir(%p, %s)\n", handle, smb_fname->base_name);

	real_path = get_realpath(handle, smb_fname);
	/* Returns NULL if it does not exist or there are problems ? */
	ret = cafs_opendir(cafs_ctx, real_path, &result);
	SAFE_FREE(real_path);
	if (ret < 0) {
		result = NULL;
		errno = -ret; /* We return result which is NULL in this case */
	}

	DBG_DEBUG("[ CAFS ] opendir(...) = %d\n", ret);
	return (DIR *) result;
}

static DIR *cafswrap_fdopendir(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *mask,
			       uint32_t attributes)
{
	/* OpenDir_fsp() falls back to regular open */
	errno = ENOSYS;
	return NULL;
}

static struct dirent *cafswrap_readdir(struct vfs_handle_struct *handle,
				       DIR *dirp,
				       SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;
	CAFS_CTX(cafs_ctx, handle, NULL);

	DBG_DEBUG("[ CAFS ] readdir(%p, %p)\n", handle, dirp);
	result = cafs_readdir(cafs_ctx, (struct cafs_dir *) dirp);
	DBG_DEBUG("[ CAFS ] readdir(...) = %p\n", result);

	/* Default Posix readdir() does not give us stat info.
	 * Set to invalid to indicate we didn't return this info. */
	if (sbuf)
		SET_STAT_INVALID(*sbuf);
	return result;
}

static void cafswrap_seekdir(struct vfs_handle_struct *handle, DIR *dirp, long offset)
{
	CAFS_CTX(cafs_ctx, handle, ;);
	DBG_DEBUG("[ CAFS ] seekdir(%p, %p, %ld)\n", handle, dirp, offset);
	cafs_seekdir(cafs_ctx, (struct cafs_dir *) dirp, offset);
}

static long cafswrap_telldir(struct vfs_handle_struct *handle, DIR *dirp)
{
	long ret;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] telldir(%p, %p)\n", handle, dirp);
	ret = cafs_telldir(cafs_ctx, (struct cafs_dir *) dirp);
	DBG_DEBUG("[ CAFS ] telldir(...) = %ld\n", ret);
	WRAP_RETURN(ret);
}

static void cafswrap_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	CAFS_CTX(cafs_ctx, handle, ;);
	DBG_DEBUG("[ CAFS ] seekdir(%p, %p)\n", handle, dirp);
	cafs_rewinddir(cafs_ctx, (struct cafs_dir *) dirp);
}

static int cafswrap_mkdirat(struct vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;
	char *parent = NULL;
	const char *path = smb_fname->base_name;
	char *real_path;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] mkdir(%p, %s)\n", handle, path);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	if (lp_inherit_acls(SNUM(handle->conn))
	    && parent_dirname(talloc_tos(), path, &parent, NULL)
	    && directory_has_default_acl(handle->conn, parent)) {
		mode = 0777;
	}

	TALLOC_FREE(parent);
	real_path = get_realpath(handle, smb_fname);
	result = cafs_mkdir(cafs_ctx, real_path, mode);
	SAFE_FREE(real_path);
	return WRAP_RETURN(result);
}

static int cafswrap_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int result;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] closedir(%p, %p)\n", handle, dirp);
	result = cafs_closedir(cafs_ctx, (struct cafs_dir *) dirp);
	DBG_DEBUG("[ CAFS ] closedir(...) = %d\n", result);
	WRAP_RETURN(result);
}

/* File operations */

static int cafswrap_open(struct vfs_handle_struct *handle,
			struct smb_filename *smb_fname,
			files_struct *fsp, int flags, mode_t mode)
{
	int result = -ENOENT;
	char *real_path;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] open(%p, %s, %p, %d, %d)\n", handle,
		  smb_fname_str_dbg(smb_fname), fsp, flags, mode);

	if (is_named_stream(smb_fname)) {
		errno = ENOENT;
		goto out;
	}
	real_path = get_realpath(handle, smb_fname);

	result = cafs_open(cafs_ctx, real_path, flags, mode);
out:
	DBG_DEBUG("[ CAFS ] open(...) = %d\n", real_path);

	SAFE_FREE(real_path);

	WRAP_RETURN(result);
}

static int cafswrap_close(struct vfs_handle_struct *handle, files_struct *fsp)
{
	int result;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] close(%p, %p)\n", handle, fsp);
	result = cafs_close(cafs_ctx, fsp->fh->fd);
	DBG_DEBUG("[ CAFS ] close(...) = %d\n", result);

	WRAP_RETURN(result);
}

static ssize_t cafswrap_pread(struct vfs_handle_struct *handle, files_struct *fsp, void *data,
			size_t n, off_t offset)
{
	ssize_t result;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] pread(%p, %p, %p, %llu, %llu)\n", handle, fsp, data, llu(n), llu(offset));

	result = cafs_read(cafs_ctx, fsp->fh->fd, data, n, offset);
	DBG_DEBUG("[ CAFS ] pread(...) = %llu\n", llu(result));
	WRAP_RETURN(result);
}

struct cafswrap_pread_state {
	ssize_t ret;
	int fd;
	void *buf;
	size_t count;
	off_t offset;
	cafs_mount_handle_t cafs_ctx;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void cafs_pread_do(void *private_data);
static void cafs_pread_done(struct tevent_req *subreq);
static int cafs_pread_state_destructor(struct cafswrap_pread_state *state);

static struct tevent_req *cafswrap_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct cafswrap_pread_state *state;
	CAFS_CTX(cafs_ctx, handle, NULL);

	req = tevent_req_create(mem_ctx, &state, struct cafswrap_pread_state);
	if (req == NULL) {
		return NULL;
	}
	DBG_DEBUG("[ CAFS ] %s\n", __func__);
	state->ret = -1;
	state->fd = fsp->fh->fd;
	state->buf = data;
	state->count = n;
	state->offset = offset;
	state->cafs_ctx = cafs_ctx;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool,
		cafs_pread_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cafs_pread_done, req);

	talloc_set_destructor(state, cafs_pread_state_destructor);

	return req;
}

static void cafs_pread_do(void *private_data)
{
	struct cafswrap_pread_state *state = talloc_get_type_abort(
		private_data, struct cafswrap_pread_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);
	DBG_DEBUG("[ CAFS ] %s\n", __func__);
	state->ret = cafs_read(state->cafs_ctx, 
							state->fd, 
							state->buf, 
							state->count, 
							state->offset);
	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int cafs_pread_state_destructor(struct cafswrap_pread_state *state)
{
	return -1;
}

static void cafs_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cafswrap_pread_state *state = tevent_req_data(
		req, struct cafswrap_pread_state);
	int ret;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	talloc_set_destructor(state, NULL);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		cafs_pread_do(state);
	}

	tevent_req_done(req);
}

static ssize_t cafswrap_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct cafswrap_pread_state *state =
		tevent_req_data(req, struct cafswrap_pread_state);

	DBG_DEBUG("[ CAFS ] %s\n", __func__);
	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	DBG_DEBUG("[ CAFS ] error:%d, ret:%ld\n", state->vfs_aio_state.error, state->ret);
	return state->ret;
}

static ssize_t cafswrap_pwrite(struct vfs_handle_struct *handle, files_struct *fsp, const void *data,
			size_t n, off_t offset)
{
	ssize_t result;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] pwrite(%p, %p, %p, %llu, %llu)\n", handle, fsp, data, llu(n), llu(offset));
	result = cafs_write(cafs_ctx, fsp->fh->fd, data, n, offset);
	DBG_DEBUG("[ CAFS ] pwrite(...) = %llu\n", llu(result));
	WRAP_RETURN(result);
}


struct cafswrap_pwrite_state {
	ssize_t ret;
	int fd;
	const void *buf;
	size_t count;
	off_t offset;
	cafs_mount_handle_t cafs_ctx;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void cafs_pwrite_do(void *private_data);
static void cafs_pwrite_done(struct tevent_req *subreq);
static int cafs_pwrite_state_destructor(struct cafswrap_pwrite_state *state);

static struct tevent_req *cafswrap_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct cafswrap_pwrite_state *state;
	CAFS_CTX(cafs_ctx, handle, NULL);

	req = tevent_req_create(mem_ctx, &state, struct cafswrap_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	DBG_DEBUG("[ CAFS ] %s\n", __func__);
	state->ret = -1;
	state->fd = fsp->fh->fd;
	state->buf = data;
	state->count = n;
	state->offset = offset;
	state->cafs_ctx = cafs_ctx;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool,
		cafs_pwrite_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cafs_pwrite_done, req);

	talloc_set_destructor(state, cafs_pwrite_state_destructor);

	return req;
}

static void cafs_pwrite_do(void *private_data)
{
	struct cafswrap_pwrite_state *state = talloc_get_type_abort(
		private_data, struct cafswrap_pwrite_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);
	DBG_DEBUG("[ CAFS ] %s\n", __func__);
	state->ret = cafs_write(state->cafs_ctx,
					 state->fd,
				     state->buf,
				     state->count,
				     state->offset);

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int cafs_pwrite_state_destructor(struct cafswrap_pwrite_state *state)
{
	return -1;
}

static void cafs_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cafswrap_pwrite_state *state = tevent_req_data(
		req, struct cafswrap_pwrite_state);
	int ret;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	talloc_set_destructor(state, NULL);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		cafs_pwrite_do(state);
	}

	tevent_req_done(req);
	
}

static ssize_t cafswrap_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct cafswrap_pwrite_state *state = tevent_req_data(
		req, struct cafswrap_pwrite_state);
	DBG_DEBUG("[ CAFS ] %s\n", __func__);
	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t cafswrap_lseek(struct vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
	off_t result = 0;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] cephwrap_lseek\n");
	result = cafs_lseek(cafs_ctx, fsp->fh->fd, offset, whence);
	WRAP_RETURN(result);
}

static ssize_t cafswrap_sendfile(struct vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *hdr,
			off_t offset, size_t n)
{
	/*
	 * We cannot support sendfile because libceph is in user space.
	 */
	DBG_DEBUG("[ CAFS ] cafswrap_sendfile\n");
	errno = ENOTSUP;
	return -1;
}

static ssize_t cafswrap_recvfile(struct vfs_handle_struct *handle,
			int fromfd,
			files_struct *tofsp,
			off_t offset,
			size_t n)
{
	/*
	 * We cannot support recvfile because libceph is in user space.
	 */
	DBG_DEBUG("[ CAFS ] cafswrap_recvfile\n");
	errno=ENOTSUP;
	return -1;
}

static int cafswrap_renameat(struct vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	int result = -1;
	CAFS_CTX(cafs_ctx, handle, -1);

	DBG_DEBUG("[ CAFS ] cephwrap_renameat\n");
	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		return result;
	}

	SMB_ASSERT(srcfsp == srcfsp->conn->cwd_fsp);
	SMB_ASSERT(dstfsp == dstfsp->conn->cwd_fsp);

	result = cafs_rename(cafs_ctx, smb_fname_src->base_name, smb_fname_dst->base_name);
	WRAP_RETURN(result);
}

/*
 * Fake up an async ceph fsync by calling the synchronous API.
 */

static struct tevent_req *cafswrap_fsync_send(struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct vfs_aio_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[ CAFS ] cafswrap_fsync_send\n");

	req = tevent_req_create(mem_ctx, &state, struct vfs_aio_state);
	if (req == NULL) {
		return NULL;
	}

	/* Mark it as done. */
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static int cafswrap_fsync_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_state *state =
		tevent_req_data(req, struct vfs_aio_state);

	DBG_DEBUG("[ CAFS ] cafswrap_fsync_recv\n");

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = *state;
	return 0;
}

// todo???
#define SAMBA_STATX_ATTR_MASK	(0x1|0)

static void init_stat_ex_from_cafswrap_statx(struct stat_ex *dst, const struct cafs_statx *stx)
{
	DBG_DEBUG("[ CAFS ]\tstx = {dev = %llx, ino = %llu, mode = 0x%x, "
		  "nlink = %llu, uid = %d, gid = %d, rdev = %llx, size = %llu, "
		  "blksize = %llu, blocks = %llu, atime = %llu, mtime = %llu, "
		  "ctime = %llu, btime = %llu}\n",
		  llu(stx->stx_dev), llu(stx->stx_ino), stx->stx_mode,
		  llu(stx->stx_nlink), stx->stx_uid, stx->stx_gid,
		  llu(stx->stx_rdev), llu(stx->stx_size), llu(stx->stx_blksize),
		  llu(stx->stx_blocks), llu(stx->stx_atime.tv_sec),
		  llu(stx->stx_mtime.tv_sec), llu(stx->stx_ctime.tv_sec),
		  llu(stx->stx_btime.tv_sec));

	/*if ((stx->stx_mask & SAMBA_STATX_ATTR_MASK) != SAMBA_STATX_ATTR_MASK) {
		DBG_WARNING("%s: stx->stx_mask is incorrect (wanted %x, got %x)",
				__func__, SAMBA_STATX_ATTR_MASK, stx->stx_mask);
	}*/

	dst->st_ex_dev = stx->stx_dev;
	dst->st_ex_rdev = stx->stx_rdev;
	dst->st_ex_ino = stx->stx_ino;
	dst->st_ex_mode = stx->stx_mode;
	dst->st_ex_uid = stx->stx_uid;
	dst->st_ex_gid = stx->stx_gid;
	dst->st_ex_size = stx->stx_size;
	dst->st_ex_nlink = stx->stx_nlink;
	dst->st_ex_atime = stx->stx_atime;
	dst->st_ex_btime = stx->stx_btime;
	dst->st_ex_ctime = stx->stx_ctime;
	dst->st_ex_mtime = stx->stx_mtime;
	dst->st_ex_itime = dst->st_ex_btime;
	dst->st_ex_iflags = ST_EX_IFLAG_CALCULATED_ITIME;
	dst->st_ex_blksize = stx->stx_blksize;
	dst->st_ex_blocks = stx->stx_blocks;
	dst->st_ex_file_id = dst->st_ex_ino;
	dst->st_ex_iflags |= ST_EX_IFLAG_CALCULATED_FILE_ID;
}

static int cafswrap_stat(struct vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	int result = -1;
	struct cafs_statx stx;
	char *real_path;
	DBG_DEBUG("[ CAFS ] stat(%p, %s)\n", handle, smb_fname_str_dbg(smb_fname));

	if (is_named_stream(smb_fname)) {
		//DBG_ERR("[ CAFS ] is_named_stream(%s)\n", smb_fname_str_dbg(smb_fname));
		errno = ENOENT;
		return result;
	}

	real_path = get_realpath(handle, smb_fname);
	result = cafs_statx(handle->data, real_path, &stx,
				SAMBA_STATX_ATTR_MASK, 0);
	DBG_DEBUG("[ CAFS ] statx(...) = %d\n", result);
	SAFE_FREE(real_path);
	if (result < 0) {
		WRAP_RETURN(result);
	}

	init_stat_ex_from_cafswrap_statx(&smb_fname->st, &stx);
	DBG_DEBUG("[ CAFS ] mode = 0x%x\n", smb_fname->st.st_ex_mode);
	return result;
}

static int cafswrap_fstat(struct vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int result = -1;
	struct cafs_statx stx;

	DBG_DEBUG("[ CAFS ] fstat(%p, %d)\n", handle, fsp->fh->fd);
	result = cafs_fstatx(handle->data, fsp->fh->fd, &stx,
				SAMBA_STATX_ATTR_MASK, 0);
	DBG_DEBUG("[ CAFS ] fstat(...) = %d\n", result);
	if (result < 0) {
		WRAP_RETURN(result);
	}

	init_stat_ex_from_cafswrap_statx(sbuf, &stx);
	DBG_DEBUG("[ CAFS ] mode = 0x%x\n", sbuf->st_ex_mode);
	return result;
}

static int cafswrap_lstat(struct vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	int result = -1;
	struct cafs_statx stx;
	char *real_path;
	DBG_DEBUG("[ CAFS ] lstat(%p, %s)\n", handle, smb_fname_str_dbg(smb_fname));

	if (is_named_stream(smb_fname)) {
		DBG_ERR("[ CAFS ] is_named_stream(%s)\n", smb_fname_str_dbg(smb_fname));
		errno = ENOENT;
		return result;
	}
	real_path = get_realpath(handle, smb_fname);
	result = cafs_statx(handle->data, real_path, &stx,
				SAMBA_STATX_ATTR_MASK, AT_SYMLINK_NOFOLLOW);
	DBG_DEBUG("[ CAFS ] lstat(...) = %d\n", result);
	SAFE_FREE(real_path);
	if (result < 0) {
		WRAP_RETURN(result);
	}

	init_stat_ex_from_cafswrap_statx(&smb_fname->st, &stx);
	return result;
}

static int cafswrap_ntimes(struct vfs_handle_struct *handle,
			 const struct smb_filename *smb_fname,
			 struct smb_file_time *ft)
{
	struct cafs_statx stx = { 0 };
	int result;
	int mask = 0;
	char *real_path;

	if (!is_omit_timespec(&ft->atime)) {
		stx.stx_atime = ft->atime;
		mask |= CAFS_SETATTR_ATIME;
	}
	if (!is_omit_timespec(&ft->mtime)) {
		stx.stx_mtime = ft->mtime;
		mask |= CAFS_SETATTR_MTIME;
	}
	if (!is_omit_timespec(&ft->create_time)) {
		stx.stx_btime = ft->create_time;
		mask |= CAFS_SETATTR_CTIME;
	}

	if (!mask) {
		return 0;
	}
	real_path = get_realpath(handle, smb_fname);
	result = cafs_setattrx(handle->data, real_path, &stx, mask, 0);
	DBG_DEBUG("[ CAFS ] ntimes(%p, %s, {%ld, %ld, %ld, %ld}) = %d\n", handle, smb_fname_str_dbg(smb_fname),
				ft->mtime.tv_sec, ft->atime.tv_sec, ft->ctime.tv_sec,
				ft->create_time.tv_sec, result);
	SAFE_FREE(real_path);
	return result;
}

static int cafswrap_unlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int result = -1;
	char *real_path;
	DBG_DEBUG("[ CAFS ] unlink(%p, %s)\n",
		handle,
		smb_fname_str_dbg(smb_fname));
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	if (is_named_stream(smb_fname)) {
		DBG_ERR("[ CAFS ] is_named_stream(%s)\n", smb_fname_str_dbg(smb_fname));
		errno = ENOENT;
		return result;
	}
	real_path = get_realpath(handle, smb_fname);

	if (flags & AT_REMOVEDIR) {
		result = cafs_rmdir(handle->data, real_path);
	} else {
		result = cafs_unlink(handle->data, real_path);
	}
	DBG_DEBUG("[ CAFS ] unlink(...) = %d\n", result);
	SAFE_FREE(real_path);

	WRAP_RETURN(result);
}

static int cafswrap_chmod(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result = -1;
	char *real_path;

	DBG_DEBUG("[ CAFS ] chmod(%p, %s, %d)\n", handle, smb_fname->base_name, mode);
	real_path = get_realpath(handle, smb_fname);
	result = cafs_chmod(handle->data, real_path, mode);
	SAFE_FREE(real_path);
	DBG_DEBUG("[ CAFS ] chmod(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_fchmod(struct vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result = -1;

	DBG_DEBUG("[ CAFS ] fchmod(%p, %p, %d)\n", handle, fsp, mode);
	result = cafs_fchmod(handle->data, fsp->fh->fd, mode);
	DBG_DEBUG("[ CAFS ] fchmod(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_fchown(struct vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
	int result = -1;

	DBG_DEBUG("[ CAFS ] fchown(%p, %p, %d, %d)\n", handle, fsp, uid, gid);
	result = cafs_fchown(handle->data, fsp->fh->fd, uid, gid);
	DBG_DEBUG("[ CAFS ] fchown(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int result = 0;
	char *real_path;
	DBG_DEBUG("[ CAFS ] lchown(%p, %s, %d, %d)\n", handle, smb_fname->base_name, uid, gid);
	real_path = get_realpath(handle, smb_fname);
	result = cafs_lchown(handle->data, real_path, uid, gid);
	SAFE_FREE(real_path);
	DBG_DEBUG("[ CAFS ] lchown(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_chdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int result = -1;
	char *real_path;
	real_path = get_realpath(handle, smb_fname);
	DBG_DEBUG("[ CAFS ] chdir(%p, %s)\n", handle, smb_fname->base_name);
	result = cafs_chdir(handle->data, real_path);
	DBG_DEBUG("[ CAFS ] chdir to (%s) = %d\n", real_path, result);
	SAFE_FREE(real_path);
	WRAP_RETURN(result);
}

static struct smb_filename *cafswrap_getwd(struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx)
{
	const char *cwd = cafs_getcwd(handle->data);
	DBG_DEBUG("[ CAFS ] getwd(%p) = %s\n", handle, cwd);
	return synthetic_smb_fname(ctx,
				cwd,
				NULL,
				NULL,
				0);
}

static int strict_allocate_ftruncate(struct vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	off_t space_to_write;
	int result;
	NTSTATUS status;
	SMB_STRUCT_STAT *pst;

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	pst = &fsp->fsp_name->st;

#ifdef S_ISFIFO
	if (S_ISFIFO(pst->st_ex_mode))
		return 0;
#endif

	if (pst->st_ex_size == len)
		return 0;

	WRAP_RETURN(result);
}

static int cafswrap_ftruncate(struct vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	int result = -1;

	DBG_DEBUG("[ CAFS ] ftruncate(%p, %p, %llu\n", handle, fsp, llu(len));

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		return strict_allocate_ftruncate(handle, fsp, len);
	}

	result = cafs_ftruncate(handle->data, fsp->fh->fd, len);
	WRAP_RETURN(result);
}

static int cafswrap_fallocate(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      uint32_t mode,
			      off_t offset,
			      off_t len)
{
	int result;

	DBG_DEBUG("[ CAFS ] fallocate(%p, %p, %u, %llu, %llu\n",
		  handle, fsp, mode, llu(offset), llu(len));
	/* unsupported mode flags are rejected by libcephfs */
	result = cafs_fallocate(handle->data, fsp->fh->fd, mode, offset, len);
	DBG_DEBUG("[ CAFS ] fallocate(...) = %d\n", result);
	WRAP_RETURN(result);
}

static bool cafswrap_lock(struct vfs_handle_struct *handle, files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	DBG_DEBUG("[ CAFS ] lock\n");
	return true;
}

static int cafswrap_kernel_flock(struct vfs_handle_struct *handle,
				 files_struct *fsp,
				 uint32_t share_access,
				 uint32_t access_mask)
{
	DBG_DEBUG("[ CAFS ] flock unsupported! Consider setting "
		"\"kernel share modes = no, test\"\n");
	//errno = ENOSYS;
	return 0;
}

static int cafswrap_fcntl(vfs_handle_struct *handle,
			  files_struct *fsp, int cmd, va_list cmd_arg)
{
	/*
	 * SMB_VFS_FCNTL() is currently only called by vfs_set_blocking() to
	 * clear O_NONBLOCK, etc for LOCK_MAND and FIFOs. Ignore it.
	 */
	if (cmd == F_GETFL) {
		return 0;
	} else if (cmd == F_SETFL) {
		va_list dup_cmd_arg;
		int opt;

		va_copy(dup_cmd_arg, cmd_arg);
		opt = va_arg(dup_cmd_arg, int);
		va_end(dup_cmd_arg);
		if (opt == 0) {
			return 0;
		}
		DBG_ERR("unexpected fcntl SETFL(%d)\n", opt);
		goto err_out;
	}
	DBG_ERR("unexpected fcntl: %d\n", cmd);
err_out:
	errno = EINVAL;
	return -1;
}

static bool cafswrap_getlock(struct vfs_handle_struct *handle, files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	DBG_DEBUG("[ CAFS ] getlock returning false and errno=0\n");

	errno = 0;
	return false;
}

/*
 * We cannot let this fall through to the default, because the file might only
 * be accessible from libceph (which is a user-space client) but the fd might
 * be for some file the kernel knows about.
 */
static int cafswrap_linux_setlease(struct vfs_handle_struct *handle, files_struct *fsp,
				int leasetype)
{
	int result = -1;

	DBG_DEBUG("[ CAFS ] linux_setlease\n");
	errno = ENOSYS;
	return result;
}

static int cafswrap_symlinkat(struct vfs_handle_struct *handle,
		const char *link_target,
		struct files_struct *dirfsp,
		const struct smb_filename *new_smb_fname)
{
	int result = -1;
	char *real_path;
	real_path = get_realpath(handle, new_smb_fname);

	DBG_DEBUG("[ CAFS ] symlink(%p, %s, %s)\n", handle,
			link_target,
			new_smb_fname->base_name);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = cafs_symlink(handle->data, link_target, real_path);
	SAFE_FREE(real_path);

	DBG_DEBUG("[ CAFS ] symlink(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_readlinkat(struct vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		char *buf,
		size_t bufsiz)
{
	int result = -1;
	char *real_path;
	real_path = get_realpath(handle, smb_fname);

	DBG_DEBUG("[ CAFS ] readlink(%p, %s, %p, %llu)\n", handle,
			smb_fname->base_name, buf, llu(bufsiz));

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = cafs_readlink(handle->data, real_path, buf, bufsiz);
	SAFE_FREE(real_path);
	DBG_DEBUG("[ CAFS ] readlink(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_linkat(struct vfs_handle_struct *handle,
		files_struct *srcfsp,
		const struct smb_filename *old_smb_fname,
		files_struct *dstfsp,
		const struct smb_filename *new_smb_fname,
		int flags)
{
	int result = -1;
	DBG_DEBUG("[ CAFS ] link(%p, %s, %s)\n", handle,
			old_smb_fname->base_name,
			new_smb_fname->base_name);

	SMB_ASSERT(srcfsp == srcfsp->conn->cwd_fsp);
	SMB_ASSERT(dstfsp == dstfsp->conn->cwd_fsp);

	result = cafs_link(handle->data,
				old_smb_fname->base_name,
				new_smb_fname->base_name);
	DBG_DEBUG("[ CAFS ] link(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cafswrap_mknodat(struct vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	int result = -1;

	DBG_DEBUG("[ CAFS ] cafswrap_mknodat\n");
	errno = ENOSYS;
	return result;
}

/*
 * This is a simple version of real-path ... a better version is needed to
 * ask libceph about symbolic links.
 */
static struct smb_filename *cafswrap_realpath(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	char *result = NULL;
	const char *path = smb_fname->base_name;
	struct smb_filename *result_fname = NULL;

	result = get_realpath(handle, smb_fname);

	DBG_DEBUG("[ CAFS ] realpath(%p, %s) = %s\n", handle, path, result);
	result_fname = synthetic_smb_fname(ctx,
				result,
				NULL,
				NULL,
				0);
	SAFE_FREE(result);
	
	return result_fname;
}

static int cafswrap_chflags(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}

static int cafswrap_get_real_filename(struct vfs_handle_struct *handle,
				     const char *path,
				     const char *name,
				     TALLOC_CTX *mem_ctx,
				     char **found_name)
{
	/*
	 * Don't fall back to get_real_filename so callers can differentiate
	 * between a full directory scan and an actual case-insensitive stat.
	 */
	errno = EOPNOTSUPP;
	return -1;
}

static const char *cafswrap_connectpath(struct vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
}

/****************************************************************
 Extended attribute operations.
*****************************************************************/

static ssize_t cafswrap_getxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			void *value,
			size_t size)
{
	int ret = 0;
	DBG_DEBUG("[ CAFS ] getxattr(%p, %s, %s, %p, %llu)\n", handle,
			smb_fname->base_name, name, value, llu(size));
	//ret = cafswrap_getxattr(handle->data,
	//		smb_fname->base_name, name, value, size);
	DBG_DEBUG("[ CAFS ] getxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static ssize_t cafswrap_fgetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size)
{
	int ret = 0;
	DBG_DEBUG("[ CAFS ] fgetxattr(%p, %p, %s, %p, %llu)\n", handle, fsp, name, value, llu(size));
	//ret = cafswrap_fgetxattr(handle->data, fsp->fh->fd, name, value, size);
	DBG_DEBUG("[ CAFS ] fgetxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static ssize_t cafswrap_listxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			char *list,
			size_t size)
{
	int ret = 0;
	DBG_DEBUG("[ CAFS ] listxattr(%p, %s, %p, %llu)\n", handle,
			smb_fname->base_name, list, llu(size));
	//ret = cafswrap_listxattr(handle->data, smb_fname->base_name, list, size);
	DBG_DEBUG("[ CAFS ] listxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static ssize_t cafswrap_flistxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size)
{
	int ret = 0;
	DBG_DEBUG("[ CAFS ] flistxattr(%p, %p, %p, %llu)\n",
		  handle, fsp, list, llu(size));
	//ret = cafswrap_flistxattr(handle->data, fsp->fh->fd, list, size);
	DBG_DEBUG("[ CAFS ] flistxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static int cafswrap_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	int ret = -1;
	DBG_DEBUG("[ CAFS ] removexattr(%p, %s, %s)\n", handle,
			smb_fname->base_name, name);
	//ret = cafswrap_removexattr(handle->data, smb_fname->base_name, name);
	DBG_DEBUG("[ CAFS ] removexattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static int cafswrap_fremovexattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
	int ret = -1;
	DBG_DEBUG("[ CAFS ] fremovexattr(%p, %p, %s)\n", handle, fsp, name);
	//ret = cafswrap_fremovexattr(handle->data, fsp->fh->fd, name);
	DBG_DEBUG("[ CAFS ] fremovexattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static int cafswrap_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	int ret = 0;
	DBG_DEBUG("[ CAFS ] setxattr(%p, %s, %s, %p, %llu, %d)\n", handle,
			smb_fname->base_name, name, value, llu(size), flags);
	//ret = cafswrap_setxattr(handle->data, smb_fname->base_name,
			//name, value, size, flags);
	DBG_DEBUG("[ CAFS ] setxattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static int cafswrap_fsetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags)
{
	int ret = 0;
	DBG_DEBUG("[ CAFS ] fsetxattr(%p, %p, %s, %p, %llu, %d)\n", handle, fsp, name, value, llu(size), flags);
	//ret = cafswrap_fsetxattr(handle->data, fsp->fh->fd,
			     //name, value, size, flags);
	DBG_DEBUG("[ CAFS ] fsetxattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static bool cafswrap_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{

	/*
	 * We do not support AIO yet.
	 */

	DBG_DEBUG("[ CAFS ] cafswrap_aio_force(%p, %p) = false (errno = ENOTSUP)\n", handle, fsp);
	errno = ENOTSUP;
	return false;
}

static NTSTATUS cafswrap_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	return NT_STATUS_NO_MEMORY;
}

/*
 * Read and return the contents of a DFS redirect given a
 * pathname. A caller can pass in NULL for ppreflist and
 * preferral_count but still determine if this was a
 * DFS redirect point by getting NT_STATUS_OK back
 * without incurring the overhead of reading and parsing
 * the referral contents.
 */

static NTSTATUS cafswrap_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
    return NT_STATUS_NO_MEMORY;
}

static struct vfs_fn_pointers cafswrap_fns = {
	/* Disk operations */

	.connect_fn = cafswrap_connect,
	.disconnect_fn = cafswrap_disconnect,
	.disk_free_fn = cafswrap_disk_free,
	.get_quota_fn = cafswrap_get_quota,
	.set_quota_fn = cafswrap_set_quota,
	.statvfs_fn = cafswrap_statvfs,
	.fs_capabilities_fn = cafswrap_fs_capabilities,

	/* Directory operations */

	.opendir_fn = cafswrap_opendir,
	.fdopendir_fn = cafswrap_fdopendir,
	.readdir_fn = cafswrap_readdir,
	.seekdir_fn = cafswrap_seekdir,
	.telldir_fn = cafswrap_telldir,
	.rewind_dir_fn = cafswrap_rewinddir,
	.mkdirat_fn = cafswrap_mkdirat,
	.closedir_fn = cafswrap_closedir,

	/* File operations */

	.create_dfs_pathat_fn = cafswrap_create_dfs_pathat,
	.read_dfs_pathat_fn = cafswrap_read_dfs_pathat,
	.open_fn = cafswrap_open,
	.close_fn = cafswrap_close,
	.pread_fn = cafswrap_pread,
	.pread_send_fn = cafswrap_pread_send,
	.pread_recv_fn = cafswrap_pread_recv,
	.pwrite_fn = cafswrap_pwrite,
	.pwrite_send_fn = cafswrap_pwrite_send,
	.pwrite_recv_fn = cafswrap_pwrite_recv,
	.lseek_fn = cafswrap_lseek,
	.sendfile_fn = cafswrap_sendfile,
	.recvfile_fn = cafswrap_recvfile,
	.renameat_fn = cafswrap_renameat,
	.fsync_send_fn = cafswrap_fsync_send,
	.fsync_recv_fn = cafswrap_fsync_recv,
	.stat_fn = cafswrap_stat,
	.fstat_fn = cafswrap_fstat,
	.lstat_fn = cafswrap_lstat,
	.unlinkat_fn = cafswrap_unlinkat,
	.chmod_fn = cafswrap_chmod,
	.fchmod_fn = cafswrap_fchmod,
	.fchown_fn = cafswrap_fchown,
	.lchown_fn = cafswrap_lchown,
	.chdir_fn = cafswrap_chdir,
	.getwd_fn = cafswrap_getwd,
	.ntimes_fn = cafswrap_ntimes,
	.ftruncate_fn = cafswrap_ftruncate,
	.fallocate_fn = cafswrap_fallocate,
	.lock_fn = cafswrap_lock,
	.kernel_flock_fn = cafswrap_kernel_flock,
	.fcntl_fn = cafswrap_fcntl,
	.linux_setlease_fn = cafswrap_linux_setlease,
	.getlock_fn = cafswrap_getlock,
	.symlinkat_fn = cafswrap_symlinkat,
	.readlinkat_fn = cafswrap_readlinkat,
	.linkat_fn = cafswrap_linkat,
	.mknodat_fn = cafswrap_mknodat,
	.realpath_fn = cafswrap_realpath,
	.chflags_fn = cafswrap_chflags,
	.get_real_filename_fn = cafswrap_get_real_filename,
	.connectpath_fn = cafswrap_connectpath,

	/* EA operations. */
	.getxattr_fn = cafswrap_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = cafswrap_fgetxattr,
	.listxattr_fn = cafswrap_listxattr,
	.flistxattr_fn = cafswrap_flistxattr,
	.removexattr_fn = cafswrap_removexattr,
	.fremovexattr_fn = cafswrap_fremovexattr,
	.setxattr_fn = cafswrap_setxattr,
	.fsetxattr_fn = cafswrap_fsetxattr,

	/* Posix ACL Operations */
	.sys_acl_get_file_fn = posixacl_xattr_acl_get_file,
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = posixacl_xattr_acl_set_file,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_file_fn = posixacl_xattr_acl_delete_def_file,

	/* aio operations */
	.aio_force_fn = cafswrap_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_cafs_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"cafs", &cafswrap_fns);
}
