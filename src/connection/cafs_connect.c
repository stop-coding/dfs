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

#include "cafs_connect.h"

#include "klist.h"

#include <unistd.h>


#define MAX_IOV_NUM  3

static const  uint64_t ARPC_TREAD_MAX_NUM = 16;
static const  uint64_t ARPC_BING_CPU_MAX_NUM =  16;

static int g_connect_init_flag = 0;
static int process_oneway_async(const struct arpc_vmsg *req_iov, uint32_t *flags, void* usr_context);
static int process_rx_header(struct arpc_header_msg *header, void* usr_context, uint32_t *flag);
static void *mem_alloc(uint32_t size, void *usr_context);
static int mem_free(void *buf_ptr, void *usr_context);
static struct cafs_vmsg *cafs_get_oneway_vmsg(struct arpc_vmsg *req_iov);

struct con_private_obj {
   	arpc_session_handle_t 	session_fd;
	int (*rx_oneway_cb)(struct cafs_vmsg *vmsg, void *usr_ctx);
	void					*usr_ctx;
	struct cafs_rwlock 		rwlock;
	struct arpc_client_session_param param;
};

struct con_private_msg {
   	struct arpc_msg 		*io_msg;
};

static struct arpc_session_ops con_ops ={
		.req_ops = {
			.alloc_cb = NULL,
			.free_cb = NULL,
			.proc_head_cb =NULL,
			.proc_data_cb = NULL,
			.proc_async_cb = NULL,
			.release_rsp_cb = NULL,
		},
		.oneway_ops = {
			.alloc_cb = &mem_alloc,
			.free_cb = &mem_free,
			.proc_head_cb = &process_rx_header,
			.proc_data_cb = &process_oneway_async,
			.proc_async_cb = &process_oneway_async,
		}
	};

/*!
 *  @brief  创建一个消息请求对象
 *
 *  @param[in]  conf  创建消息请求对象的参数
 *  @return  struct connect_obj * 请求消息的操作对象; (<em>NULL</em>: fail ; ( <em>非NULL</em>: succeed
 *
 */
struct connect_obj *cafs_create_connect_obj(const struct cafs_connect_cfg *conf)
{
	struct connect_obj *obj_out = NULL;
	struct con_private_obj *pri_obj = NULL;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE(!conf, NULL, "request_entity is null");

	obj_out = (struct connect_obj *)CAFS_ALLOC(sizeof(struct connect_obj) + 
										sizeof(struct con_private_obj), NULL);
	
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj_out, NULL, "CAFS_ALLOC connect_obj fail.");
	memset(obj_out, 0, sizeof(struct connect_obj) + sizeof(struct con_private_obj));

	pri_obj = (struct con_private_obj *)obj_out->private;

	// 建立session
	memcpy(pri_obj->param.con.ipv4.ip, conf->entity_addr, strlen(conf->entity_addr));
	pri_obj->param.con.ipv4.port = conf->port;
	pri_obj->param.ops_usr_ctx = pri_obj;
	pri_obj->param.con_num = conf->conn_num;
	pri_obj->param.rx_con_num = conf->rx_con_num;
	pri_obj->param.ops = &con_ops;
	pri_obj->param.opt.msg_data_max_len = conf->msg_data_max_len;
	pri_obj->param.opt.msg_head_max_len = conf->msg_head_max_len;
	pri_obj->param.opt.msg_iov_max_len = conf->msg_iov_max_len;
	pri_obj->param.timeout_ms = conf->timeout_ms;

	pri_obj->rx_oneway_cb = conf->rx_oneway_cb;
	pri_obj->usr_ctx = conf->usr_ctx;

	pri_obj->session_fd = arpc_client_create_session(&pri_obj->param);// todo 新建的session回复参数没有传出来
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pri_obj->session_fd, error, "arpc_client_create_session fail.");

	ret = cafs_rwlock_init(&pri_obj->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_ses, "cafs_rwlock_init fail.");

	return obj_out;
free_ses:
	if (pri_obj->session_fd) {
		arpc_client_destroy_session(pri_obj->session_fd);
		pri_obj->session_fd = NULL;
	}
error:
	cafs_rwlock_destroy(&pri_obj->rwlock);

	if (obj_out){
		CAFS_FREE(obj_out, NULL);
		obj_out = NULL;
	}
	return NULL;
}

/*!
 *  @brief  销毁一个消息请求对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_connect_obj(struct connect_obj *obj)
{
	struct con_private_obj *pri_obj;
	const struct msg_operater *op;
	int ret;
	int try_time = 3;

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "connect_obj is null.");
	pri_obj = (struct con_private_obj *)obj->private;

	ret = cafs_rwlock_wrlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock[%p] fail.", pri_obj);

	if (pri_obj->session_fd) {
		arpc_client_destroy_session(&pri_obj->session_fd);
		pri_obj->session_fd = NULL;
	}
	cafs_rwlock_unlock(&pri_obj->rwlock);

	cafs_usleep(100);
	cafs_rwlock_destroy(&pri_obj->rwlock);
	CAFS_FREE(obj, NULL);

	return 0;
}

void cafs_connect_obj_status(struct connect_obj *obj)
{
	struct con_private_obj *pri_obj;
	int ret;
	pri_obj = (struct con_private_obj *)obj->private;

	ret = cafs_rwlock_rdlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, ;, "cafs_rwlock_wrlock[%p] fail.", pri_obj);

	if (pri_obj->session_fd) {
		arpc_session_info(pri_obj->session_fd);
	}
	cafs_rwlock_unlock(&pri_obj->rwlock);
}

int cafs_connect_islive(struct connect_obj *obj)
{
	struct con_private_obj *pri_obj;
	int ret = 0;
	pri_obj = (struct con_private_obj *)obj->private;

	ret = cafs_rwlock_rdlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "cafs_rwlock_wrlock[%p] fail.", pri_obj);

	if (pri_obj->session_fd) {
		ret = (ARPC_SES_STA_ACTIVE == arpc_get_session_status(pri_obj->session_fd));
	}
	cafs_rwlock_unlock(&pri_obj->rwlock);
	return ret;
}

int cafs_connect_restart(const struct connect_obj *obj)
{
	struct con_private_obj *pri_obj;
	int ret = 0;
	pri_obj = (struct con_private_obj *)obj->private;
	ret = cafs_rwlock_wrlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock[%p] fail.", pri_obj);

	// 二次确认检查，避免别其它线程重启过了
	if (pri_obj->session_fd && ARPC_SES_STA_ACTIVE != arpc_get_session_status(pri_obj->session_fd)) {
		ret = arpc_client_destroy_session(pri_obj->session_fd);
		LOG_ERROR_IF_VAL_TRUE(ret, "arpc_client_destroy_session[%p] fail.", pri_obj->session_fd);
		pri_obj->session_fd = arpc_client_create_session(&pri_obj->param);
		LOG_ERROR_IF_VAL_TRUE(!pri_obj->session_fd, "arpc_client_create_session uri[tcp://%s:%u] fail.", 
							pri_obj->param.con.ipv4.ip, pri_obj->param.con.ipv4.port);
	}
	cafs_rwlock_unlock(&pri_obj->rwlock);
	return (pri_obj->session_fd)?0:(CAFS_ERR);
}
/*!
 *  @brief  初始化连接模块
 *
 *  @param[in]  p  初始化参数
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_connect_init(struct connect_init_param *p)
{
	struct aprc_option opt;
	if (g_connect_init_flag == 0){
		opt.thread_max_num = ARPC_TREAD_MAX_NUM;
		opt.cpu_max_num = ARPC_BING_CPU_MAX_NUM;
		if(p){
			opt.thread_max_num = p->thread_max_num;
			opt.tx_queue_max_depth = 512;
			opt.tx_queue_max_size = 64*1024*1024;
			opt.rx_queue_max_depth = 512;
			opt.rx_queue_max_size = 64*1024*1024;
			opt.msg_data_max_len = 512*1024;
		}
		arpc_init_r(&opt);
		g_connect_init_flag = 1;
	}else{
		g_connect_init_flag++;
		CAFS_LOG_NOTICE("cafs_connect_init done, not do it again, init cnt:%d.", g_connect_init_flag);
	}
	return 0;
}

/*!
 *  @brief  关闭连接模块
 *
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_connect_shutdown()
{
	if (g_connect_init_flag == 1) {
		arpc_finish();
		CAFS_LOG_NOTICE("cafs_connect shutdown.");
		g_connect_init_flag = 0;
	}else if (g_connect_init_flag > 1) {
		CAFS_LOG_NOTICE("cafs_connect is running , not shutdown.");
		g_connect_init_flag--;
	}else{
		CAFS_LOG_NOTICE("cafs_connect_shutdown done, not do it again.");
		g_connect_init_flag = 0;
	}
	return 0;
}

struct cafs_request_msg *cafs_new_request()
{
	struct cafs_request_msg *msg;
	struct con_private_msg *pri_msg;
	msg = (struct cafs_request_msg *)CAFS_ALLOC(sizeof(struct cafs_request_msg) + 
										sizeof(struct con_private_msg), NULL);
	
	LOG_THEN_RETURN_VAL_IF_TRUE(!msg, NULL, "CAFS_ALLOC connect_obj fail.");
	memset(msg, 0, sizeof(struct cafs_request_msg) + sizeof(struct con_private_msg));

	pri_msg = (struct con_private_msg *)msg->ctx;
	pri_msg->io_msg = arpc_new_msg(NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pri_msg->io_msg, free_obj, "arpc_new_msg fail.");
	return msg;
free_obj:
	SAFE_CAFS_FREE(msg);
	return NULL;
}

void cafs_delete_request(struct cafs_request_msg *req)
{
	struct con_private_msg *pri_msg;
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, ;, "req is null.");

	pri_msg = (struct con_private_msg *)req->ctx;

	if (pri_msg->io_msg) {
		arpc_delete_msg(&pri_msg->io_msg);
	}
	SAFE_CAFS_FREE(req);
}

void cafs_reset_request(struct cafs_request_msg *req)
{
	struct con_private_msg *pri_msg;
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, ;, "req is null.");

	pri_msg = (struct con_private_msg *)req->ctx;
	if (pri_msg->io_msg) {
		arpc_reset_msg(pri_msg->io_msg);
	}
}
/*!
 *  @brief  请求一个消息获取回复
 *
 *  @param[in]  obj          请求消息的操作对象
 *  @param[in] timeout_ms    请求等待超时时间，-1阻塞等待，0不等待，消息回复时，可以通过cafs_get_mds_rsp获取。
 *  @param[inout] req        请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_do_request(const struct connect_obj *obj, struct cafs_request_msg *req, int32_t timeout_ms)
{
	struct con_private_obj *pri_obj;
	int ret = 0;
	struct arpc_msg *arpc_msg;
	struct con_private_msg *pri_msg;
	struct cafs_vmsg *in;
	struct cafs_vmsg *out;
	uint32_t i;
	int try_time = 2;

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "connect_obj is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, CAFS_ERR, "in or out is null.");

	in = &req->req;
	out = &req->rsp;
	pri_obj = (struct con_private_obj *)obj->private;

	pri_msg = (struct con_private_msg *)req->ctx;
	LOG_THEN_RETURN_VAL_IF_TRUE(!pri_msg, CAFS_ERR, "pri_msg is null.");

	arpc_msg = pri_msg->io_msg;
	LOG_THEN_RETURN_VAL_IF_TRUE(!arpc_msg, CAFS_ERR, "arpc_msg is null.");
	
	arpc_msg->clean_send_cb = NULL;
	arpc_msg->send.head = in->head;
	arpc_msg->send.head_len = in->head_len;
	if (in->type == CAFS_VEC_E_PTR) {
		arpc_msg->send.vec = (struct arpc_iov *)in->vecptr;
	}else if(in->type == CAFS_VEC_E_IOV){
		arpc_msg->send.vec = (struct arpc_iov *)in->vec;
	}
	arpc_msg->send.vec_num = in->vec_num;
	arpc_msg->send.total_data = 0;
	for (i = 0; i < arpc_msg->send.vec_num; i++) {
		arpc_msg->send.total_data += arpc_msg->send.vec[i].len;
	}

	ret = cafs_rwlock_rdlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock[%p] fail.", pri_obj);

	while(try_time-- && pri_obj->session_fd){
		if (timeout_ms == 0) {
			arpc_msg->proc_rsp_cb = NULL;
			ret = arpc_do_request(pri_obj->session_fd, arpc_msg, 1000);//to call back
		} else {
			arpc_msg->proc_rsp_cb = NULL;
			ret = arpc_do_request(pri_obj->session_fd, arpc_msg, timeout_ms);
		}
		if(ret && ARPC_SES_STA_ACTIVE != arpc_get_session_status(pri_obj->session_fd)){
			cafs_rwlock_unlock(&pri_obj->rwlock);
			cafs_connect_restart(obj);
			cafs_rwlock_rdlock(&pri_obj->rwlock);
			continue;
		}
		break;
	}
	cafs_rwlock_unlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "arpc_do_request fail.");
	out->head = arpc_msg->receive.head;
	out->head_len = arpc_msg->receive.head_len;
	if(arpc_msg->receive.vec_num){
		out->vecptr = (struct iovec *)arpc_msg->receive.vec;
		out->type = CAFS_VEC_E_PTR;
	}else{
		out->type = CAFS_VEC_E_NULL;
	}
	out->vec_num = arpc_msg->receive.vec_num;
	return ret;
}

int cafs_send_oneway(const struct connect_obj *obj, struct cafs_vmsg *in)
{
	struct con_private_obj *pri_obj;
	int ret = 0;
	uint32_t i;
	struct arpc_vmsg send_msg;
	int try_time = 2;

	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, CAFS_ERR, "connect_obj is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!in, CAFS_ERR, "in or out is null.");
	pri_obj = (struct con_private_obj *)obj->private;

	memset(&send_msg, 0, sizeof(send_msg));
	send_msg.head = in->head;
	send_msg.head_len = in->head_len;
	send_msg.total_data = 0;
	if (in->type == CAFS_VEC_E_PTR) {
		send_msg.vec = (struct arpc_iov *)in->vecptr;
	}else if (in->type == CAFS_VEC_E_IOV) {
		send_msg.vec = (struct arpc_iov *)in->vec;
	}
	send_msg.vec_num = in->vec_num;
	for (i = 0; i < in->vec_num; i++) {
		send_msg.total_data += send_msg.vec[i].len;
	}

	ret = cafs_rwlock_rdlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock[%p] fail.", pri_obj);

	while(try_time-- && pri_obj->session_fd){
		ret = arpc_send_oneway_msg(pri_obj->session_fd, &send_msg, NULL, NULL);
		if(ret && ARPC_SES_STA_ACTIVE != arpc_get_session_status(pri_obj->session_fd)) {
			cafs_rwlock_unlock(&pri_obj->rwlock);
			cafs_connect_restart(obj);
			cafs_rwlock_rdlock(&pri_obj->rwlock);
			continue;
		}
		break;
	}
	cafs_rwlock_unlock(&pri_obj->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "arpc_send_oneway_msg fail.");
	return 0;
}

static void *mem_alloc(uint32_t size, void *usr_context)
{
	return CAFS_ALLOC(size, NULL);
}
static int mem_free(void *buf_ptr, void *usr_context)
{
	SAFE_CAFS_FREE(buf_ptr);
	return 0;
}

#define CAFS_MINI_IO_DATA_MAX_LEN (16*1024)

static int process_rx_header(struct arpc_header_msg *header, void* usr_context, uint32_t *flags)
{
	SET_METHOD(*flags, METHOD_ALLOC_DATA_BUF);
	if (header->data_len < CAFS_MINI_IO_DATA_MAX_LEN) {
		SET_METHOD(*flags, METHOD_ARPC_PROC_SYNC);
	}
	return 0;
}

static int process_oneway_async(const struct arpc_vmsg *req_iov, uint32_t *flags, void* usr_context)
{
	struct con_private_obj *pri_obj;
	struct cafs_vmsg *oneway;
	struct cafs_vmsg **p_oneway = NULL;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE(!req_iov, CAFS_ERR, "req_iov is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!flags, CAFS_ERR, "flags is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!usr_context, CAFS_ERR, "usr_context is null.");

	pri_obj = (struct con_private_obj *)usr_context;

	LOG_THEN_RETURN_VAL_IF_TRUE(!pri_obj->rx_oneway_cb, CAFS_ERR, "rx_oneway_cb is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!pri_obj->usr_ctx, CAFS_ERR, "rx_oneway_cb context is null.");

	oneway = cafs_get_oneway_vmsg((struct arpc_vmsg *)req_iov);
	LOG_THEN_RETURN_VAL_IF_TRUE(!oneway, CAFS_ERR, "CAFS_ALLOC FAIL.");

	SET_METHOD(*flags, METHOD_CALLER_HIJACK_RX_DATA);

	CAFS_LOG_DEBUG("rx oneway, head:%u, data:%lu, vec:%u.", req_iov->head_len, req_iov->total_data, req_iov->vec_num);
	ret = pri_obj->rx_oneway_cb(oneway, pri_obj->usr_ctx);
	if (ret) {
		CAFS_LOG_ERROR("rx_oneway_cb fail, head:%u, data:%lu, vec:%u.", req_iov->head_len, req_iov->total_data, req_iov->vec_num);
		cafs_put_oneway_vmsg(oneway);
	}

	return 0;
}

static struct cafs_vmsg *cafs_get_oneway_vmsg(struct arpc_vmsg *req_iov)
{
	struct cafs_vmsg *oneway;
	uint32_t i;
	struct iovec *vecptr;

	oneway = CAFS_ALLOC(sizeof(struct cafs_vmsg), NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!oneway, free_buf, "CAFS_ALLOC FAIL.");
	memset(oneway, 0 , sizeof(struct cafs_vmsg));

	oneway->head = CAFS_ALLOC(req_iov->head_len, NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!oneway->head, free_buf, "CAFS_ALLOC FAIL.");
	memcpy(oneway->head, req_iov->head, req_iov->head_len);
	oneway->head_len = req_iov->head_len;

	if (req_iov->vec_num > CAFS_IOV_NUM) {
		oneway->vecptr = CAFS_ALLOC(req_iov->vec_num * sizeof(struct iovec), NULL);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!oneway->vec, free_buf, "CAFS_ALLOC FAIL.");
		oneway->type = CAFS_VEC_E_PTR;
		vecptr = oneway->vecptr;
	}else if (req_iov->vec_num > 0){
		oneway->type = CAFS_VEC_E_IOV;
		vecptr = oneway->vec;
	}else{
		oneway->type = CAFS_VEC_E_NULL;
	}
	oneway->vec_num = req_iov->vec_num;
	for (i = 0; i < oneway->vec_num; i++) {
		vecptr[i].iov_base = req_iov->vec[i].data;
		vecptr[i].iov_len = req_iov->vec[i].len;
	}
	return oneway;
free_buf:
	SAFE_CAFS_FREE(oneway->head);
	return NULL;
}

int cafs_put_oneway_vmsg(struct cafs_vmsg *oneway)
{
	uint32_t i;
	struct iovec *vecptr;
	LOG_THEN_RETURN_VAL_IF_TRUE(!oneway, CAFS_ERR, "oneway is null.");

	SAFE_CAFS_FREE(oneway->head);

	if (oneway->type == CAFS_VEC_E_PTR) {
		vecptr = oneway->vecptr;
	}else{
		vecptr = oneway->vec;
	}

	for (i = 0; i < oneway->vec_num; i++) {
		SAFE_CAFS_FREE(vecptr[i].iov_base);
	}

	if (oneway->type == CAFS_VEC_E_PTR) {
		SAFE_CAFS_FREE(vecptr);
	}

	SAFE_CAFS_FREE(oneway);
	return 0;
}
