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
#include "cafs_connect.h"

#include "cafs_mds_node.h"
#include "khash.h"

#include <unistd.h>

static const  EntityRole _SELF_ROLE  = ENTITY_ROLE__CA;
static const  uint64_t _SELF_ROLE_ID = 0x6734;

static const  uint16_t CONNECTION_MAX_NUM = 4;
static const  uint16_t CONNECTION_RX_NUM =  1;

#define QUEQUE_PER_ADD_MAX_NUM   64

#define MDS_NODE_CTX(ctx_name, obj, ret)\
struct _mds_node_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _mds_node_ctx *)obj->ctx;

struct node_request_msg{
	QUEUE q;
	struct cafs_request_msg *req_msg;
	void			*head_buf;
	uint32_t		head_buf_len;
	void			*pack_buf;
	uint32_t		pack_buf_len;
	enum msg_op_type op_id;
	void 		 	*unpack_head;
	void 		 	*unpack_buf;
	void 			*ctx;
};

struct _mds_node_ctx {
   	struct connect_obj *con;
	struct cafs_mutex lock;
	QUEUE q_idle;
	QUEUE q_work;
};

static struct node_request_msg *mds_create_request();
static void mds_destroy_request(struct node_request_msg *req);

static int pack_request_message(const struct mds_req_msg *req, struct node_request_msg *mds_req);
static int unpack_respone_message(struct node_request_msg *mds_req, struct mds_rsp_msg *rsp);

struct mds_node_obj *cafs_create_mds_node(const struct mds_node_cfg *cfg)
{
	struct mds_node_obj *obj = NULL;
	int ret;
	struct cafs_connect_cfg con_cfg;
	struct _mds_node_ctx *ctx;

	LOG_THEN_RETURN_VAL_IF_TRUE(!cfg, NULL, "cfg is null");

	obj = (struct mds_node_obj *)CAFS_ALLOC(sizeof(struct mds_node_obj) + sizeof(struct _mds_node_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC connect_obj fail.");
	memset(obj, 0, sizeof(struct mds_node_obj) + sizeof(struct _mds_node_ctx));
	ctx = (struct _mds_node_ctx *)obj->ctx;

	cafs_mutex_init(&ctx->lock);

	memset(&con_cfg, 0, sizeof(con_cfg));
	con_cfg.entity_addr = cfg->node->addr;
	con_cfg.port = cfg->node->port;
	con_cfg.conn_num = (cfg->node->connection)?cfg->node->connection:CONNECTION_MAX_NUM;
	con_cfg.msg_data_max_len = cfg->node->msg_data_max_len;
	con_cfg.msg_head_max_len = cfg->node->msg_head_max_len;
	con_cfg.msg_iov_max_len  = cfg->node->msg_iov_max_len;
	con_cfg.timeout_ms = cfg->timeout_ms;
	ctx->con = cafs_create_connect_obj(&con_cfg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->con, free_obj, "cafs_create_connect_obj fail, ip[%s], port[%d]", 
									con_cfg.entity_addr, con_cfg.port);
	QUEUE_INIT(&ctx->q_idle);
	QUEUE_INIT(&ctx->q_work);
	obj->id = cfg->node->id;

	return obj;

free_obj:
	cafs_mutex_destroy(&ctx->lock);
	SAFE_CAFS_FREE(obj);

	return NULL;
}

int cafs_destroy_mds_node(struct mds_node_obj *obj)
{
	int ret;
	struct node_request_msg *req;
	QUEUE* iter;
	MDS_NODE_CTX(ctx, obj, CAFS_ERR);

	cafs_mutex_lock(&ctx->lock);

	ret = cafs_destroy_connect_obj(ctx->con);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "cafs_destroy_connect_obj is null");

	while(!QUEUE_EMPTY(&ctx->q_idle)){
		iter = QUEUE_HEAD(&ctx->q_idle);
		req = QUEUE_DATA(iter, struct node_request_msg, q);
		QUEUE_REMOVE(iter);
		mds_destroy_request(req);
	}

	while(!QUEUE_EMPTY(&ctx->q_work)){
		iter = QUEUE_HEAD(&ctx->q_work);
		req = QUEUE_DATA(iter, struct node_request_msg, q);
		QUEUE_REMOVE(iter);
		mds_destroy_request(req);
	}

	cafs_mutex_unlock(&ctx->lock);

	cafs_mutex_destroy(&ctx->lock);
	SAFE_CAFS_FREE(obj);

	return 0;
unlock:
	cafs_mutex_unlock(&ctx->lock);
	return CAFS_ERR;
}

static struct node_request_msg *mds_create_request()
{
	struct node_request_msg *req;
	int ret;

	req = (struct node_request_msg *)CAFS_ALLOC(sizeof(struct node_request_msg), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, NULL, "msg null fail.");
	memset(req, 0, sizeof(struct node_request_msg));
	req->req_msg = cafs_new_request();
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!req->req_msg, free_msg, "cafs_new_request fail.");
	QUEUE_INIT(&req->q);
	return req;
free_msg:
	SAFE_CAFS_FREE(req);
	return NULL;
}


static void mds_destroy_request(struct node_request_msg *req)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, ;, "msg null.");
	if (req->req_msg) {
		cafs_delete_request(req->req_msg);
	}

	if (req->head_buf) {
		CAFS_FREE(req->head_buf, NULL);
	}

	if (req->pack_buf) {
		CAFS_FREE(req->pack_buf, NULL);
	}

	if (req->unpack_head) {
		fsmsg_decode_delete(MSG_HEAD_HANDLE, req->unpack_head);
	}

	if (req->unpack_buf) {
		fsmsg_decode_delete(GET_RSP_HANDLE(req->op_id), req->unpack_buf);
	}

	SAFE_CAFS_FREE(req);
	return;
}

static struct node_request_msg *get_mds_request(struct _mds_node_ctx *ctx)
{
	struct node_request_msg *req;
	int ret;
	int i ;
	QUEUE* iter;

	ret = cafs_mutex_lock(&ctx->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_mutex_lock fail.");

	if (QUEUE_EMPTY(&ctx->q_idle)) {
		for (i = 0; i < QUEQUE_PER_ADD_MAX_NUM; i++) {
			req = mds_create_request();
			LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!req, unlock, "mds_create_request fail.");
			QUEUE_INSERT_TAIL(&ctx->q_idle, &req->q);
		}
	}
	iter = QUEUE_HEAD(&ctx->q_idle);
	QUEUE_REMOVE(iter);
	QUEUE_INIT(iter);
	QUEUE_INSERT_TAIL(&ctx->q_work, iter);
	cafs_mutex_unlock(&ctx->lock);
	req = QUEUE_DATA(iter, struct node_request_msg, q);
	cafs_reset_request(req->req_msg);
	req->ctx = ctx;
	return req;

unlock:
	cafs_mutex_unlock(&ctx->lock);
	return NULL;
}

static void put_mds_request(struct node_request_msg *req)
{
	int ret;
	struct _mds_node_ctx *ctx;

	LOG_THEN_RETURN_VAL_IF_TRUE(!req, ;, "req null.");

	ctx = (struct _mds_node_ctx *)req->ctx;
	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx, ;, "ctx null.");

	ret = cafs_mutex_lock(&ctx->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, ;, "cafs_mutex_lock fail.");

	QUEUE_REMOVE(&req->q);
	QUEUE_INIT(&req->q);
	QUEUE_INSERT_TAIL(&ctx->q_idle, &req->q);
	req->ctx = NULL;
	cafs_mutex_unlock(&ctx->lock);

	return;
}

int cafs_mds_request(const struct mds_node_obj *mds, struct mds_req_msg *req, struct mds_rsp_msg *rsp, int32_t timeout_ms)
{
	int ret = 0;
	int retry = 3;
	struct node_request_msg *mds_req;
	MDS_NODE_CTX(ctx, mds, CAFS_ERR);

	rsp->ctx =NULL;
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, CAFS_ERR, "mds_req_msg is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp, CAFS_ERR, "mds_rsp_msg is null.");

	mds_req = get_mds_request(ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_req, CAFS_ERR, "get_mds_request fail.");

	ret = pack_request_message(req, mds_req);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, put_request, "pack_request_message fail.");

	while(retry--){
		ret = cafs_do_request(ctx->con, mds_req->req_msg, timeout_ms);
		if(ret){
			CAFS_LOG_ERROR("cafs_request timeout ,retry again.");
			// todo重建链路
			continue;
		}
		ret = unpack_respone_message(mds_req, rsp);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, put_request, "unpack_respone_message fail.");
		break;
	}
	rsp->ctx = mds_req;
	return 0;
put_request:
	put_mds_request(mds_req);
	return ret;
}

void cafs_mds_put_rsp(struct mds_rsp_msg *rsp)
{
	struct node_request_msg *mds_req;
	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp, ;, "rsp is null.");
	if(rsp->ctx) {
		mds_req = (struct node_request_msg *)rsp->ctx;
		put_mds_request(mds_req);
		rsp->ctx =NULL;
	}
}

static int pack_request_message(const struct mds_req_msg *req, struct node_request_msg *mds_req)
{
	const struct msg_operater *op;
	CommonHead 		 header;
	int 				 ret;
	uint32_t			 pack_len;
	struct cafs_vmsg	*send;
	

	op = cafs_get_msg_op(req->op_id);
	LOG_THEN_RETURN_VAL_IF_TRUE(!op, CAFS_ERR, "cafs_get_msg_op fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!op->req.handle, CAFS_ERR, "op_id[%d] req.handle is null.",req->op_id);

	fsmsg_encode_init(MSG_HEAD_HANDLE, &header, sizeof(header));
	header.msg_id = op->req.msg_id;
	header.entity = _SELF_ROLE;
	header.entity_id = 10086;
	header.seg_num = 1;
	header.seg_sn = 0;
	header.seg_total = op->req.msg_len;
	header.type = DATA_TYPE__DATA_E_PROTO;
	header.private_id = req->op_id;
	header.private_type = DATA_TYPE__DATA_E_NONE;
	pack_len = fsmsg_get_encoded_size(MSG_HEAD_HANDLE, &header, sizeof(header));
	if (pack_len > mds_req->head_buf_len || !mds_req->head_buf) {
		if (mds_req->head_buf) {
			CAFS_FREE(mds_req->head_buf, NULL);
		}
		mds_req->head_buf = CAFS_ALLOC(pack_len, NULL);
		LOG_THEN_RETURN_VAL_IF_TRUE(!mds_req->head_buf, CAFS_ERR, "CAFS_ALLOC fail.");
		mds_req->head_buf_len = pack_len;
	}
	
	ret = fsmsg_encode(MSG_HEAD_HANDLE, &header, mds_req->head_buf);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "fsmsg_encode fail.");
	send = &(mds_req->req_msg->req);
	send->head = mds_req->head_buf;
	send->head_len = pack_len;

	//fsmsg_encode_init(op->req.handle(), &req->req, op->req.msg_len);
	pack_len = fsmsg_get_encoded_size(op->req.handle(), (void*)&req->msg, op->req.msg_len);
	
	if (pack_len > mds_req->pack_buf_len || !mds_req->pack_buf) {
		if (mds_req->pack_buf) {
			CAFS_FREE(mds_req->pack_buf, NULL);
		}
		mds_req->pack_buf = CAFS_ALLOC(pack_len, NULL);
		LOG_THEN_RETURN_VAL_IF_TRUE(!mds_req->pack_buf, CAFS_ERR, "CAFS_ALLOC fail.");
		mds_req->pack_buf_len = pack_len;
	}

	ret = fsmsg_encode(op->req.handle(), (void*)&req->msg, mds_req->pack_buf);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "fsmsg_encode fail.");

	send->vec_num = 1;
	send->type = CAFS_VEC_E_IOV;
	send->vec[0].iov_base = mds_req->pack_buf;
	send->vec[0].iov_len = pack_len;
	
	if (mds_req->unpack_head) {
		fsmsg_decode_delete(MSG_HEAD_HANDLE, mds_req->unpack_head);
		mds_req->unpack_head = NULL;
	}

	if (mds_req->unpack_buf) {
		fsmsg_decode_delete(GET_RSP_HANDLE(mds_req->op_id), mds_req->unpack_buf);
		mds_req->unpack_buf = NULL;
	}

	mds_req->op_id = req->op_id; // 更新op id

	return 0;
}

static int unpack_respone_message(struct node_request_msg *mds_req, struct mds_rsp_msg *rsp)
{
	const struct msg_operater *op;
	CommonHead 		 *header;
	uint32_t			 pack_head_len;
	uint32_t			 pack_data_len;
	int 				 ret;
	struct cafs_vmsg *recive;
	struct iovec    *vecptr;

	op = cafs_get_msg_op(mds_req->op_id);
	LOG_THEN_RETURN_VAL_IF_TRUE(!op, CAFS_ERR, "cafs_get_msg_op op-id[%d] fail.", mds_req->op_id);

	// 都存在，说明是再次读取，不需要重复解析
	if (mds_req->unpack_buf) {
		rsp->msg = (mds_rsp_msg_u *)mds_req->unpack_buf;
		return 0;
	}
	recive = &mds_req->req_msg->rsp;
	if (mds_req->unpack_head) {
		fsmsg_decode_delete(MSG_HEAD_HANDLE, mds_req->unpack_head);
	}
	mds_req->unpack_head = fsmsg_decode_new(MSG_HEAD_HANDLE, recive->head, recive->head_len);
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_req->unpack_head, CAFS_ERR, "_unpack_header fail.");
	header = (CommonHead *)mds_req->unpack_head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(header->msg_id != op->rsp.msg_id, error, "rx msg_id[%lu] not match expect[%u].", 
									header->msg_id, op->rsp.msg_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(header->type != DATA_TYPE__DATA_E_PROTO, error, "rx type must proto format.");

	LOG_THEN_RETURN_VAL_IF_TRUE(recive->vec_num != 1, CAFS_ERR, "recive data invalid fail, vec num:%u.", recive->vec_num);

	vecptr = get_cafsvmsg_vec(recive);
	LOG_THEN_RETURN_VAL_IF_TRUE(!vecptr, CAFS_ERR, "recive vec is null, vec type:%d.", recive->type);

	if (mds_req->unpack_buf) {
		fsmsg_decode_delete(op->rsp.handle(), mds_req->unpack_buf);
	}
	mds_req->unpack_buf = fsmsg_decode_new(op->rsp.handle(), vecptr[0].iov_base, vecptr[0].iov_len);
	LOG_THEN_RETURN_VAL_IF_TRUE(!mds_req->unpack_buf, CAFS_ERR, "_unpack_body fail, data:%p, len:%u.", vecptr[0].iov_base, vecptr[0].iov_len);
	rsp->op_id = mds_req->op_id;
	rsp->msg = (mds_rsp_msg_u *)mds_req->unpack_buf;
	return 0;
error:
	if (mds_req->unpack_head) {
		fsmsg_decode_delete(MSG_HEAD_HANDLE, mds_req->unpack_head);
		mds_req->unpack_head = NULL;
	}
	return CAFS_ERR;
}

