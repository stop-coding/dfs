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
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "arpc_api.h"
#include "cafs_public.h"
#include "pfile_dispatch.h"
#include "cafs_log.h"
#include "fsmsg.h"


static const char *storage_path = NULL;

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
	(void)usr_context;
	param->ops_new_ctx = calloc(1, sizeof(struct rx_msg));
	return 0;
}

static int new_session_end(arpc_session_handle_t fd, struct arpc_new_session_rsp *param, void* usr_context)
{
	(void)usr_context;
	if (!fd) {
		free(param->ops_new_ctx);
		return 0;
	}
	struct rx_msg *ctx = (struct rx_msg*)param->ops_new_ctx;
	ctx->fd = fd;
	ctx->path = storage_path;
	CAFS_LOG_NOTICE("connect session:%p.\n", ctx->fd);
	CAFS_LOG_NOTICE("storage path:%s.\n", ctx->path);
	return 0;
}

static int new_session_teardown(const arpc_session_handle_t fd, void *usr_server_ctx, void *usr_session_ctx)
{
	(void)fd;
	(void)usr_server_ctx;
	struct rx_msg *ctx = (struct rx_msg*)usr_session_ctx;
	if (ctx) {
		free(ctx);
	}
	return 0;
}


static int process_req_async(const struct arpc_vmsg *req_iov, struct arpc_rsp *rsp, void* usr_context)
{
	(void)req_iov;
	(void)rsp;
	(void)usr_context;
	return 0;
}

static int process_async(const struct arpc_vmsg *req_iov, uint32_t *flag, void* usr_context)
{
	(void)flag;

	struct rx_msg *ctx = (struct rx_msg*)usr_context;
	const struct dispatch_op *op = NULL;
	pfile_req_msg_u	 *req_msg = NULL;
	CommonHead *header =NULL;

	header = (CommonHead *)fsmsg_decode_new(FSMSG_GET_OPS(common,MSG_ID_COMMON_HEAD), req_iov->head, req_iov->head_len);
	if (!header) {
		CAFS_LOG_ERROR("fsmsg_decode_new fail, head:%p, len:%u", req_iov->head, req_iov->head_len);
		return 0;
	}

	LOG_THEN_RETURN_VAL_IF_TRUE( !header->private_head.data, 0, "no private data.");

	op = get_op(header->msg_id);
	LOG_THEN_RETURN_VAL_IF_TRUE(!op , 0, "get_op[%lu] fail.", header->msg_id);

	req_msg = (pfile_req_msg_u *)fsmsg_decode_new(FSMSG_GET_OPS(ca_pfile_req, op->req_msg_id), header->private_head.data, header->private_head.len);
	LOG_THEN_RETURN_VAL_IF_TRUE(!req_msg, 0, "fsmsg_decode_new fail.");
	if (op->op_info){
		CAFS_LOG_NOTICE("-----------req:%s -----------", op->op_info);
	}
	//cafs_mutex_lock(&ctx->lock);
	op->rsp_msg(req_msg, (struct arpc_vmsg *)req_iov, ctx);
	//cafs_mutex_unlock(&ctx->lock);

	if (req_msg){
		fsmsg_decode_delete(FSMSG_GET_OPS(ca_pfile_req, op->req_msg_id), req_msg);
		req_msg= NULL;
	}

	if (header){
		fsmsg_decode_delete(FSMSG_GET_OPS(common,MSG_ID_COMMON_HEAD), header);
		header= NULL;
	}
	
	return 0;
}

static int release_rsp(struct arpc_vmsg *rsp_iov, void *usr_context)
{
	(void)usr_context;
	uint32_t i;
	if (!rsp_iov){
		return 0;
	}
	SAFE_CAFS_FREE(rsp_iov->head);
	for (i = 0; i < rsp_iov->vec_num; i++) {
		SAFE_CAFS_FREE(rsp_iov->vec[i].data);
	}
	return 0;
}

static const struct arpc_session_ops ops ={
	.req_ops = {
		.alloc_cb = &mem_alloc,
		.free_cb = &mem_free,
		.proc_head_cb = process_rx_header,
		.proc_data_cb = process_req_async,
		.proc_async_cb = process_req_async,
		.release_rsp_cb = release_rsp,
	},
	.rsp_ops = {},
	.oneway_ops = {
		.alloc_cb = &mem_alloc,
		.free_cb = &mem_free,
		.proc_head_cb = &process_rx_header,
		.proc_data_cb = &process_async,
		.proc_async_cb = &process_async,
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
	chdir("/mnt/hgfs/lalala/test");
 
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
	struct aprc_option opt;
	if (argc < 4) {
		CAFS_LOG_NOTICE("Usage: %s <host> <port> <storage path> <-d>", argv[0]);
		return 0;
	}
	if (argv[4]) {
		if (strcmp(argv[4], "-d") == 0) {
			CAFS_LOG_NOTICE(" set daemon mode to run");
			set_daemon();
		}
	}

	storage_path = argv[3];
	if (access(storage_path, F_OK) != 0) {
		mkdir(storage_path, 0777);
		if (access(storage_path, F_OK) != 0){
			CAFS_LOG_ERROR("create obj file dir:%s fail", storage_path);
			return 0;
		}
	}
	
	FSMSG_BOX_INIT(ca_pfile_req, NULL);
	FSMSG_BOX_INIT(ca_pfile_rsp, NULL);
	FSMSG_BOX_INIT(common, NULL);
	opt.thread_max_num = 16;
	arpc_init_r(&opt);
	memset(&param, 0, sizeof(param));
	param.con.type = ARPC_E_TRANS_TCP;
	memcpy(param.con.ipv4.ip, argv[1], IPV4_MAX_LEN);
	param.con.ipv4.port = atoi(argv[2]);

	param.work_num = 10;
	param.default_ops = ops;
	param.new_session_start = &new_session_start;
	param.new_session_end = &new_session_end;
	param.session_teardown = &new_session_teardown;
	param.default_ops_usr_ctx = NULL;

	fd = arpc_server_create(&param);
	if(!fd){
		goto end;
	}
	arpc_server_loop(fd, -1);

end:
	if(fd)
		arpc_server_destroy(&fd);
	FSMSG_BOX_EXIT(ca_pfile_req);
	FSMSG_BOX_EXIT(ca_pfile_rsp);
	FSMSG_BOX_EXIT(common);
	arpc_finish();
	return 0;
}

