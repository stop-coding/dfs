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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mds_log.h"
#include "arpc_api.h"
#include "cafs_public.h"
#include "cafs_mds_msg.h"
#include "server_dispatch.h"
#include "fsdb.hpp"

using namespace cafs;
using namespace std;

struct rx_msg{
	CommonHead *header;
	struct arpc_vmsg 	rsp_iov;
	mds_req_msg_u	 *req_msg;
	mds_rsp_msg_u	 rsp_msg;
	struct arpc_iov vec[4];
};

static const char *default_storage_file = "./cafs_db/";

static void *mem_alloc(uint32_t size, void *usr_context)
{
	(void)usr_context;
	void *mem = malloc(size);
	return mem;
}
static int mem_free(void *buf_ptr, void *usr_context)
{
	(void)usr_context;
	if(buf_ptr)
		free(buf_ptr);
	return 0;
}

static int process_rx_header(struct arpc_header_msg *header, void* usr_context, uint32_t *flag)
{
	(void)header;
	(void)usr_context;
	SET_METHOD(*flag, METHOD_ALLOC_DATA_BUF);
	return 0;
}

static int new_session_start(const struct arpc_new_session_req *client, struct arpc_new_session_rsp *param, void* usr_context)
{
	(void)client;
	(void)param;
	(void)usr_context;
	return 0;
}

static int new_session_end(arpc_session_handle_t fd, struct arpc_new_session_rsp *param, void* usr_context)
{
	(void)fd;
	(void)param;
	(void)usr_context;
	return 0;
}


static int process_async(const struct arpc_vmsg *req_iov, struct arpc_rsp *rsp, void* usr_context)
{
	struct rx_msg *ctx;
	const struct dispatch_op *op = NULL;
	CommonHead header;
	int ret = 0;
	uint32_t pack_len;

	if(!usr_context) {
		MDS_LOG_ERROR("db object is null, fail");
		return 0;
	}

	LOG_THEN_RETURN_VAL_IF_TRUE(!req_iov->head || !req_iov->head_len, 0, "no head data.");
	
	ctx = (struct rx_msg *)calloc(1, sizeof(struct rx_msg ));
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx , 0, "ctx calloc fail.");

	ctx->header = (CommonHead*)fsmsg_decode_new(FSMSG_GET_OPS(common,MSG_ID_COMMON_HEAD), req_iov->head, req_iov->head_len);
	if (!ctx->header) {
		MDS_LOG_ERROR("fsmsg_decode_new fail");
		return 0;
	}

	op = get_op(ctx->header->msg_id);
	LOG_THEN_RETURN_VAL_IF_TRUE(!op , 0, "get_op[%lu] fail.", ctx->header->msg_id);

	ctx->req_msg = (mds_req_msg_u *)fsmsg_decode_new(FSMSG_GET_OPS(ca_mds_req, op->req_msg_id), req_iov->vec[0].data, req_iov->vec[0].len);
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->req_msg, 0, "fsmsg_decode_new fail.");
	if (op->op_info){
		MDS_LOG_NOTICE("-----------req:%s -----------", op->op_info);
	}

	rsp->rsp_ctx = ctx;
	rsp->rsp_iov = &ctx->rsp_iov;
	rsp->rsp_iov->vec = ctx->vec;
	rsp->rsp_iov->vec_num = 0;
	ctx->vec[0].len = 0;
	ctx->vec[0].data = NULL;
	ctx->vec[0].len = op->rsp_msg(ctx->req_msg, &ctx->vec[0].data, (fsdb *)usr_context);
	rsp->rsp_iov->total_data = ctx->vec[0].len;

	if (ctx->req_msg){
		fsmsg_decode_delete(FSMSG_GET_OPS(ca_mds_req, op->req_msg_id), ctx->req_msg);
	}
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->vec[0].len || !ctx->vec[0].data, -1, "oh ,my god !!! rsp empty.");

	fsmsg_encode_init(MSG_HEAD_HANDLE, &header, sizeof(header));
	header.msg_id = op->rsp_msg_id;
	header.entity = ENTITY_ROLE__MDS;
	header.entity_id = 10010;
	header.seg_num = 1;
	header.seg_sn = 0;
	header.seg_total = rsp->rsp_iov->total_data;
	header.type = DATA_TYPE__DATA_E_PROTO;
	header.private_id = ctx->header->private_id;
	header.private_type = DATA_TYPE__DATA_E_NONE;
	pack_len = fsmsg_get_encoded_size(MSG_HEAD_HANDLE, &header, sizeof(header));
	rsp->rsp_iov->head= CAFS_ALLOC(pack_len, NULL);
	rsp->rsp_iov->head_len = pack_len;
	ret = fsmsg_encode(MSG_HEAD_HANDLE, &header, rsp->rsp_iov->head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "fsmsg_encode fail.");
	if (ctx->header){
		fsmsg_decode_delete(MSG_HEAD_HANDLE, ctx->header);
	}
	rsp->rsp_iov->vec_num = 1;
	return 0;
}

static int release_rsp(struct arpc_vmsg *rsp_iov, void *ctx)
{
	if (rsp_iov->head) {
		CAFS_FREE(rsp_iov->head, NULL);
		rsp_iov->head =NULL;
	}
	if (rsp_iov->vec[0].data) {
		CAFS_FREE(rsp_iov->vec[0].data, NULL);
		rsp_iov->vec[0].data =NULL;
		rsp_iov->vec[0].len  = 0;
	}
	if (ctx) {
		free(ctx);
	}
	return 0;
}

static const struct arpc_session_ops ops ={
	.req_ops = {
		.alloc_cb = &mem_alloc,
		.free_cb = &mem_free,
		.proc_head_cb = &process_rx_header,
		.proc_data_cb = &process_async,
		.proc_async_cb = &process_async,
		.release_rsp_cb = &release_rsp,
	},
	.rsp_ops = {},
	.oneway_ops = {
		.alloc_cb = &mem_alloc,
		.free_cb = &mem_free,
		.proc_head_cb = NULL,
		.proc_data_cb = NULL,
		.proc_async_cb = NULL,
	}
};

int set_daemon(void) 
{ 
	int pid; 
	int i; 
 
	//忽略终端I/O信号，STOP信号
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGHUP,SIG_IGN);
	
	pid = fork();
	if(pid > 0) {
		exit(0); //结束父进程，使得子进程成为后台进程
	}
	else if(pid < 0) { 
		return -1;
	}
 
	//建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端
	setsid();
 
	//再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端
	pid=fork();
	if( pid > 0) {
		exit(0);
	}
	else if( pid< 0) {
		return -1;
	}
 
	//关闭所有从父进程继承的不再需要的文件描述符
	for(i=0;i< NOFILE;close(i++));
 
	//改变工作目录，使得进程不与任何文件系统联系
	chdir("/tmp/");
 
	//将文件当时创建屏蔽字设置为0
	umask(0);
 
	//忽略SIGCHLD信号
	signal(SIGCHLD,SIG_IGN); 
	
	return 0;
}

/*---------------------------------------------------------------------------*/
/* main									     */
/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	struct arpc_server_param param;
	arpc_session_handle_t fd = NULL;
	const char *storage_file;
	fsdb *fs_db = NULL;

	if (argc < 3) {
		MDS_LOG_ERROR("Usage: %s <host> <port> <storage path> < -d daemon>", argv[0]);
		MDS_LOG_ERROR("example: %s 0.0.0.0 2559 /tmp/cafs/ -d", argv[0]);
		return 0;
	}
	if (argv[4]) {
		if (strcmp(argv[4], "-d") == 0) {
			MDS_LOG_NOTICE(" set daemon mode to run");
			set_daemon();
		}
	}

	cafs_mds_msg_init(NULL);

	storage_file = (argv[3])?argv[3]:default_storage_file;
	MDS_LOG_NOTICE(" storage db file:%s", storage_file);

	// 数据库建立
	fs_db = new fsdb(std::string(storage_file));
	if (!fs_db->ok()) {
		MDS_LOG_ERROR("open db file[%s] fail.", storage_file);
		delete fs_db;
		return -1;
	}

	arpc_init();
	memset(&param, 0, sizeof(param));
	param.con.type = ARPC_E_TRANS_TCP;
	memcpy(param.con.ipv4.ip, argv[1], IPV4_MAX_LEN);
	param.con.ipv4.port = atoi(argv[2]);
	param.work_num = 6;
	param.default_ops = ops;
	param.new_session_start = &new_session_start;
	param.new_session_end = &new_session_end;
	param.default_ops_usr_ctx = fs_db;

	fd = arpc_server_create(&param);
	if(!fd){
		goto end;
	}
	arpc_server_loop(fd, -1);

end:
	if (fs_db) {
		delete fs_db;
		fs_db = NULL;
	}
	if(fd)
		arpc_server_destroy(&fd);
	cafs_mds_msg_exit();
	arpc_finish();
	return 0;
}

