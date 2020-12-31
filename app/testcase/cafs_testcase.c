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
#include <sys/types.h>    
#include <sys/stat.h>
#include <unistd.h>
#include<dirent.h>

#include "cafs_testcase.h"
#include "cafs_public.h"
#include "cafs_dir.h"

static int chdir_case(cafs_mount_handle_t handle)
{
	int try = 50;
	int ret = 0;
	const char *cwd;

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");
	cwd = cafs_getcwd (handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cur path:%s", cwd);
	return 0 ;
test_out:
	return -1;
}

static int opendir_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");

	ret = cafs_opendir(handle, cwd, &dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_opendir fail.");

	ret = cafs_closedir(handle, dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");
	return 0 ;
test_out:
	return -1;
}

static int readdir_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;
	int cnt = 0;

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");

	ret = cafs_opendir(handle, cwd, &dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_opendir fail.");

	while((pde = cafs_readdir(handle, dirp)) != NULL) {
		CAFS_LOG_NOTICE("d_ino: %lu ", pde->d_ino);
		CAFS_LOG_NOTICE("d_name: %s ", pde->d_name);
		CAFS_LOG_NOTICE("d_type: %x ", pde->d_type);
		if (DT_DIR == pde->d_type) {
			CAFS_LOG_NOTICE("is direactory.");
		}else if (DT_REG == pde->d_type) {
			CAFS_LOG_NOTICE("is file.");
		}else if (DT_LNK == pde->d_type) {
			CAFS_LOG_NOTICE("is link.");
		}
		CAFS_LOG_NOTICE("-----------------\n");
		cnt++;
		if (cnt > 1000) {
			abort();
		}
	}

	ret = cafs_closedir(handle, dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");
	return 0 ;
test_out:
	return -1;
}
static int mkdir_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	struct cafs_dir *dirp = NULL;
	const char *cwd;
	struct dirent *pde;
	char path[1024] = {0};

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	sprintf(path, "%smk_test_dir", cwd);
	CAFS_LOG_NOTICE("mkdir path: %s ", path);

	ret = cafs_mkdir(handle, path, 0777);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_mkdir fail.");

	ret = cafs_opendir(handle, cwd, &dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_opendir fail.");

	while((pde = cafs_readdir(handle, dirp)) != NULL) {
		CAFS_LOG_NOTICE("d_ino: %lu ", pde->d_ino);
		CAFS_LOG_NOTICE("d_name: %s ", pde->d_name);
		CAFS_LOG_NOTICE("d_type: %x ", pde->d_type);
		CAFS_LOG_NOTICE("-----------------\n");
	}

	ret = cafs_closedir(handle, dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	ret = cafs_rmdir(handle, path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_rmdir fail.");

	return 0 ;
test_out:
	if (dirp) {
		cafs_closedir(handle, dirp);
	}
	return -1;
}

static int seekdir_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	struct cafs_dir *dirp = NULL;
	const char *cwd;
	struct dirent *pde;
	int64_t offset = 0;

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	ret = cafs_opendir(handle, cwd, &dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_opendir fail.");

	pde = cafs_readdir(handle, dirp);
	CAFS_LOG_NOTICE("cur offset: %lu ", cafs_telldir(handle, dirp));
	CAFS_LOG_NOTICE("d_ino: %lu ", pde->d_ino);
	CAFS_LOG_NOTICE("d_name: %s ", pde->d_name);
	CAFS_LOG_NOTICE("d_type: %x ", pde->d_type);
	CAFS_LOG_NOTICE("-----------------\n");

	pde = cafs_readdir(handle, dirp);
	CAFS_LOG_NOTICE("cur offset: %lu ", cafs_telldir(handle, dirp));
	CAFS_LOG_NOTICE("d_ino: %lu ", pde->d_ino);
	CAFS_LOG_NOTICE("d_name: %s ", pde->d_name);
	CAFS_LOG_NOTICE("d_type: %x ", pde->d_type);
	CAFS_LOG_NOTICE("-----------------\n");

	cafs_rewinddir(handle, dirp);
	pde = cafs_readdir(handle, dirp);
	CAFS_LOG_NOTICE("cur offset: %lu ", cafs_telldir(handle, dirp));
	CAFS_LOG_NOTICE("d_ino: %lu ", pde->d_ino);
	CAFS_LOG_NOTICE("d_name: %s ", pde->d_name);
	CAFS_LOG_NOTICE("d_type: %x ", pde->d_type);
	CAFS_LOG_NOTICE("-----------------\n");
	
	ret = cafs_closedir(handle, dirp);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	return 0 ;
test_out:
	if (dirp) {
		cafs_closedir(handle, dirp);
	}
	return -1;
}

static int open_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	const char *cwd;
	int64_t offset = 0;
	char file_path[1024] = {0};
	int file_fd;

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	sprintf(file_path, "%s_cafs_open_test.txt", cwd);
	CAFS_LOG_NOTICE("open path: %s ", file_path);

	file_fd = cafs_open(handle, file_path, O_WRONLY, 0666);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(file_fd < 0, test_out, "cafs_open fail.");
	
	ret = cafs_close(handle, file_fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	return 0 ;
test_out:
	if (file_fd) {
		cafs_close(handle, file_fd);
	}
	return -1;
}

static int create_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	const char *cwd;
	int64_t offset = 0;
	char file_path[1024] = {0};
	int file_fd;

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	sprintf(file_path, "%scafs_create_test.txt", cwd);
	CAFS_LOG_NOTICE("open path: %s ", file_path);

	file_fd = cafs_open(handle, file_path, O_CREAT|O_WRONLY, 0666);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(file_fd < 0, test_out, "cafs_open fail.");
	
	ret = cafs_close(handle, file_fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	return 0 ;
test_out:
	if (file_fd) {
		cafs_close(handle, file_fd);
	}
	return -1;
}

static const char write_data[] = "this is test file write.";

static int file_op_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	const char *cwd;
	int64_t offset = 0;
	int64_t len = 0;
	char file_path[1024] = {0};
	char read_buf[512] = {0};
	int file_fd;

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	sprintf(file_path, "%scafs_read_test.txt", cwd);
	CAFS_LOG_NOTICE("open path: %s ", file_path);

	file_fd = cafs_open(handle, file_path, O_CREAT|O_RDWR, 0666);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(file_fd < 0, test_out, "cafs_open fail.");
	
	len = cafs_write(handle, file_fd, write_data, sizeof(write_data), 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(len < 0, test_out, "cafs_write fail.");

	len = cafs_read(handle, file_fd, read_buf, sizeof(write_data), 0);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(len < 0, test_out, "cafs_read fail.");

	if (strcmp(read_buf, write_data) != 0) {
		CAFS_LOG_ERROR("write is [%s], but read is [%s]",write_data , read_buf);
		goto test_out;
	}else{
		CAFS_LOG_NOTICE("write [%s], then read [%s].",write_data , read_buf);
	}

	ret = cafs_close(handle, file_fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	return 0 ;
test_out:
	if (file_fd) {
		cafs_close(handle, file_fd);
	}
	return -1;
}

static const char big_data[] = "Whenever you need me 333333333333333333333333333333333333333!!\n";
static const int MAX_BIG_DATA_LEN = 1024*1024;
static const int SEG_NUM = 16;
static int big_file_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	const char *cwd;
	int64_t offset = 0;
	int64_t len = 0;
	char file_path[1024] = {0};
	int file_fd;
	int i;
	char *big_buf = NULL;
	char *read_buf = NULL;
	int64_t big_buf_len = MAX_BIG_DATA_LEN;

	CAFS_LOG_NOTICE("test big file size: %ld MB", MAX_BIG_DATA_LEN*SEG_NUM/1024/1024);
	big_buf = malloc(big_buf_len + 1);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!big_buf, test_out, "big_buf fail.");

	read_buf = malloc(big_buf_len + 1);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!read_buf, test_out, "read_buf fail.");

	for (i = 0; i < (int)(MAX_BIG_DATA_LEN/sizeof(big_data)); i++) {
		memcpy(big_buf + i * sizeof(big_data), big_data, sizeof(big_data));
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(len < 0, test_out, "cafs_write fail.");
	}
	big_buf[big_buf_len] = '\0';

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	sprintf(file_path, "%scafs_big_file.txt", cwd);
	CAFS_LOG_NOTICE("open path: %s ", file_path);

	file_fd = cafs_open(handle, file_path, O_CREAT|O_RDWR, 0666);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(file_fd < 0, test_out, "cafs_open fail.");
	offset = 0;
	for (i = 0; i < SEG_NUM; i++) {
		len = cafs_write(handle, file_fd, big_buf, big_buf_len, offset);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(len < 0, test_out, "cafs_write fail, big_buf_len[%ld], offset[%ld].", big_buf_len, offset);
		CAFS_LOG_NOTICE("seg sn[%d]: write[%ld], offset[%ld], left:[%ld].", i, len, offset, big_buf_len);

		len = cafs_read(handle, file_fd, read_buf, big_buf_len, offset);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(len != big_buf_len, test_out, "cafs_read len:%ld.", len);

		if(memcmp(read_buf, big_buf, big_buf_len -1) != 0){
			CAFS_LOG_ERROR("read data not with write");
			goto test_out;
		}
		offset +=len;
	}

	CAFS_LOG_NOTICE("write success!!. left len: [%ld], offset[%ld].", big_buf_len, offset);

	if (big_buf) {
		free(big_buf);
	}
	if (read_buf) {
		free(read_buf);
	}
	ret = cafs_close(handle, file_fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	return 0 ;
test_out:
	if (big_buf) {
		free(big_buf);
	}
	if (read_buf) {
		free(read_buf);
	}
	if (file_fd) {
		cafs_close(handle, file_fd);
	}
	return -1;
}

static int chmod_case(cafs_mount_handle_t handle)
{
	int ret = 0;
	const char *cwd;
	int64_t offset = 0;
	char file_path[1024] = {0};
	int file_fd;
	struct cafs_statx stx={0};

	ret = cafs_chdir(handle, "/");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_chdir fail.");

	cwd = cafs_getcwd(handle);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!cwd, test_out, "cafs_getcwd fail.");
	CAFS_LOG_NOTICE("cwd: %s ", cwd);

	sprintf(file_path, "%scafs_create_test.txt", cwd);
	CAFS_LOG_NOTICE("open path: %s ", file_path);

	file_fd = cafs_open(handle, file_path, O_CREAT|O_WRONLY, 0777);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(file_fd < 0, test_out, "cafs_open fail.");
	
	ret = cafs_fchmod(handle, file_fd, 0555);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	ret = cafs_fchown(handle, file_fd, 1003, 1004);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	ret = cafs_fstatx(handle, file_fd, &stx, 0, 0);
	CAFS_ASSERT(ret == 0, "cafs_fstatx error");
	ret = cafs_close(handle, file_fd);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, test_out, "cafs_closedir fail.");

	return 0 ;
test_out:
	if (file_fd) {
		cafs_close(handle, file_fd);
	}
	return -1;
}

static struct test_case g_map[] = {
	{"chdir getcwd", chdir_case, "chdir success.", "chdir error, check log."},
	{"opendir case", opendir_case, "opendir success.", "opendir error, check log."},
	{"readdir case", readdir_case, "readdir success.", "readdir error, check log."},
	{"mkdir case", mkdir_case, "mkdir success.", "mkdir error, check log."},
	{"seekdir case", seekdir_case, "seekdir success.", "seekdir error, check log."},
	{"open_close case", open_case, "open file success.", "open error, check log."},
	{"create case", create_case, "create file success.", "create error, check log."},
	{"file_op case", file_op_case, "operator file success.", "operator error, check log."},
	{"big file case", big_file_case, "big file success.", "big file op error, check log."},
	{"chmod_case case", chmod_case, "chmod_case success.", "chmod_case op error, check log."},
};

const struct test_case *get_case(uint32_t case_id)
{
	uint32_t i;
	uint32_t loop_num = (uint32_t)(sizeof(g_map)/sizeof(struct test_case));
	if (case_id >= loop_num){
		return &g_map[0];
	}else{
		return &g_map[case_id];
	}
}

uint32_t get_case_num()
{
	return (uint32_t)(sizeof(g_map)/sizeof(struct test_case));
}
