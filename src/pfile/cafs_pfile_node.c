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
#include "cafs_pfile_node.h"
#include "fsmsg.h"

#include "khash.h"
#include "queue.h"
#include <unistd.h>

static const  EntityRole _SELF_ROLE  = ENTITY_ROLE__CA;
static const  uint64_t _SELF_ROLE_ID = 0x6734;

static const  uint64_t SEND_MSG_MAX_INTERVAL = 5;

static const  uint64_t  WAIT_OW_RSP_MSG_MAT_TIMEOUT_S = 30;

static const  uint64_t CONNECTION_MAX_NUM = 4;
static const  uint64_t CONNECTION_RX_NUM =  2;

#define MAX_SN_NUM (512)

#define CAFS_PFILE_EXIT (1<<0)

struct pfile_message {
	QUEUE q;
	uint32_t req_id;
	uint32_t msg_id;
	union{
		CaPfileRspRead *read;
		CaPfileRspWrite *write;
	};
	struct cafs_vmsg *vmsg;
};

struct pfile_request;
KHASH_MAP_INIT_INT(h_rxmsg, struct pfile_request *);

#define PFILE_NODE_CTX(ctx_name, obj, ret)\
struct _pfile_obj_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _pfile_obj_ctx *)obj->ctx;

struct _pfile_obj_ctx{
	uint32_t pfile_id;
	uint64_t client_id;
	uint64_t w_seg;
	uint64_t w_offset;
	uint64_t magic;
	struct connect_obj *con;
	struct cafs_mutex lock;
	uint32_t rxmsg_max_num;
	QUEUE q_idle;
	uint32_t idle_cnt;
	QUEUE q_work;
	khash_t(h_rxmsg)  *rxmsg;
	uint64_t  msg_data_max_len;
    uint32_t  msg_head_max_len;
    uint32_t  msg_iov_max_len;
	uint64_t tx_cnt;
	uint64_t rx_cnt;
	uint32_t flags;
};
struct pfile_request{
	QUEUE q;
	uint32_t req_id;
	uint32_t msg_id;
	uint32_t pfile_id;
	uint64_t offset;
	struct cafs_cond cond;
	uint32_t tx_num;
	uint32_t bits[(MAX_SN_NUM/32)];
	uint32_t rx_num;
	uint32_t flags;
	struct _pfile_obj_ctx *ctx;
	QUEUE q_msg;
};

//common
static int cafs_pfile_msg_init(struct fsmsg_allocator *ops);
static void cafs_pfile_msg_exit();

static struct pfile_request *pfile_create_request(uint32_t req_id);
static void pfile_destroy_request(struct pfile_request *req);
static struct pfile_request *get_pfile_request(struct _pfile_obj_ctx *pentity);
static void put_pfile_request(struct _pfile_obj_ctx *pentity, struct pfile_request *req);
static struct pfile_message *pfile_create_message(struct cafs_vmsg *oneway);
static void pfile_destroy_message(struct pfile_message *msg);

static int oneway_callback(struct cafs_vmsg *oneway, void *usr_context);

// write/read common
static int send_data(struct _pfile_obj_ctx *pentity, const void *head, uint64_t head_len, const void *data, uint64_t data_len);
static uint32_t pack_msg_common(void *private, uint32_t private_len, void **pack_out, uint64_t msg_id);
static CommonHead *unpack_msg_common(void *head, uint32_t head_len);

// wirte
static int do_write_request(struct _pfile_obj_ctx *pentity, 
							CaPfileReqHead *header,
							uint64_t w_offset,
							struct pfile_request *req,
							const void *buf, 
							uint64_t count);
static uint32_t pack_write_req_msg(CaPfileReqWrite *write_req, void **pack_buf);
static int wait_write_finish(struct pfile_request *req);
static CaPfileRspWrite *get_write_rsp_head(void *head, uint64_t head_len);
static int32_t get_write_rsp_sn(struct pfile_request *req, uint64_t timeout_ms);

// read
static uint32_t pack_read_req_msg(CaPfileReqRead *read_req, void **pack_buf);
static int do_read_request(struct _pfile_obj_ctx *pentity, 
							CaPfileReqHead *header,
							struct pfile_request *req,
							int64_t size);
static CaPfileRspRead *get_read_rsp_head(void *head, uint64_t head_len);
static int32_t get_read_data(struct _pfile_obj_ctx *pentity, 
							struct pfile_request *req, 
							void *buf, 
							int64_t count, 
							uint64_t timeout_ms);
static int64_t wait_read_finish(struct _pfile_obj_ctx *pentity, struct pfile_request *req, void *buf, int64_t count);

static int64_t pfile_write(const struct pfile_node_obj *pfile, const struct pfile_w_msg *w_msg, const void *buf, int64_t count);
static int64_t pfile_write_out(const struct pfile_node_obj *node_obj, const struct pfile_w_msg *w_msg, const void *buf, int64_t count);

static int64_t pfile_read(const struct pfile_node_obj *pfile, const struct pfile_r_msg *r_msg, void *buf, int64_t count);
static int64_t pfile_read_out(const struct pfile_node_obj *node_obj, const struct pfile_r_msg *r_msg, void *buf, int64_t count);


static struct pfile_node_ops pfile_ops = {
	.write = &pfile_write_out,
	.read  = &pfile_read_out,
};

struct pfile_node_obj *cafs_create_pfile_node(const struct pfile_node_cfg *cfg)
{
	struct pfile_node_obj *obj = NULL;
	int ret;
	struct cafs_connect_cfg con_cfg;
	struct _pfile_obj_ctx *ctx;

	LOG_THEN_RETURN_VAL_IF_TRUE(!cfg, NULL, "cfg is null");

	obj = (struct pfile_node_obj *)CAFS_ALLOC(sizeof(struct pfile_node_obj) + sizeof(struct _pfile_obj_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC connect_obj fail.");
	memset(obj, 0, sizeof(struct pfile_node_obj) + sizeof(struct _pfile_obj_ctx));
	ctx = (struct _pfile_obj_ctx *)obj->ctx;

	obj->ops = &pfile_ops;
	
	ret = cafs_mutex_init(&ctx->lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_mutex_init fail.");

	ctx->rxmsg = kh_init(h_rxmsg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->rxmsg, free_obj, "kh_init fail.");

	QUEUE_INIT(&ctx->q_idle);
	QUEUE_INIT(&ctx->q_work);

	memset(&con_cfg, 0, sizeof(con_cfg));
	con_cfg.entity_addr = cfg->node->addr;
	con_cfg.port = cfg->node->port;
	con_cfg.conn_num =  cfg->node->connection;
	con_cfg.msg_data_max_len = cfg->node->msg_data_max_len;
	con_cfg.msg_head_max_len = cfg->node->msg_head_max_len;
	con_cfg.msg_iov_max_len  = cfg->node->msg_iov_max_len;
	con_cfg.timeout_ms = cfg->timeout_ms;

	//注册回调
	con_cfg.rx_oneway_cb = &oneway_callback;
	con_cfg.usr_ctx = ctx;

	CAFS_LOG_DEBUG("conn_num: %u", con_cfg.conn_num);
	CAFS_LOG_DEBUG("msg_data_max_len: %lu", con_cfg.msg_data_max_len);
	CAFS_LOG_DEBUG("msg_head_max_len: %u", con_cfg.msg_head_max_len);
	CAFS_LOG_DEBUG("msg_iov_max_len: %u", con_cfg.msg_iov_max_len);
	CAFS_LOG_DEBUG("timeout_ms: %ld", con_cfg.timeout_ms);

	ctx->con = cafs_create_connect_obj(&con_cfg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->con, free_obj, "cafs_create_connect_obj fail, ip[%s], port[%d]", 
									con_cfg.entity_addr, con_cfg.port);
	ctx->pfile_id = cfg->node->id;
	obj->id = cfg->node->id;
	ctx->msg_data_max_len = con_cfg.msg_data_max_len;
	ctx->msg_head_max_len = con_cfg.msg_head_max_len;
	ctx->msg_iov_max_len = con_cfg.msg_iov_max_len;

	return obj;
free_obj:
	
	cafs_mutex_destroy(&ctx->lock);

	SAFE_CAFS_FREE(obj);
	return NULL;
}

int cafs_destroy_pfile_node(struct pfile_node_obj *obj)
{
	int ret;
	QUEUE* iter;
	struct pfile_request *req;
	PFILE_NODE_CTX(ctx, obj, CAFS_ERR);

	ret = cafs_mutex_lock(&ctx->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_mutex_lock fail.");
	SET_FLAG(ctx->flags, CAFS_PFILE_EXIT);
	cafs_mutex_unlock(&ctx->lock);

	cafs_usleep(500);

	cafs_mutex_lock(&ctx->lock);
	ret = cafs_destroy_connect_obj(ctx->con);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "cafs_destroy_connect_obj is null");
	ctx->con = NULL;

	while(!QUEUE_EMPTY(&ctx->q_idle)){
		iter = QUEUE_HEAD(&ctx->q_idle);
		req = QUEUE_DATA(iter, struct pfile_request, q);
		QUEUE_REMOVE(iter);
		pfile_destroy_request(req);
	}

	while(!QUEUE_EMPTY(&ctx->q_work)){
		iter = QUEUE_HEAD(&ctx->q_work);
		req = QUEUE_DATA(iter, struct pfile_request, q);
		QUEUE_REMOVE(iter);
		pfile_destroy_request(req);
	}

	if (ctx->rxmsg){
		kh_clear(h_rxmsg, ctx->rxmsg);
		kh_destroy(h_rxmsg, ctx->rxmsg);
		ctx->rxmsg = NULL;
	}

	cafs_mutex_unlock(&ctx->lock);

	cafs_mutex_destroy(&ctx->lock);
	SAFE_CAFS_FREE(obj);
	return 0;
unlock:
	cafs_mutex_unlock(&ctx->lock);
	return CAFS_ERR;
}

static int pfile_connect_islive(struct _pfile_obj_ctx *pentity)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!pentity, -1, "pentity null fail.");
	return cafs_connect_islive(pentity->con);
}

static struct pfile_request *pfile_create_request(uint32_t req_id)
{
	struct pfile_request *req;
	int ret;

	req = (struct pfile_request *)CAFS_ALLOC(sizeof(struct pfile_request), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!req, NULL, "msg null fail.");
	memset(req, 0, sizeof(struct pfile_request));

	ret = cafs_cond_init(&req->cond);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_msg, "cafs_cond_init fail.");
	QUEUE_INIT(&req->q);
	QUEUE_INIT(&req->q_msg);
	req->req_id = req_id;
	return req;
free_msg:
	SAFE_CAFS_FREE(req);
	return NULL;
}


static void pfile_destroy_request(struct pfile_request *req)
{
	int ret;
	QUEUE* iter;
	struct pfile_message *rx_msg;

	LOG_THEN_RETURN_VAL_IF_TRUE(!req, ;, "msg null.");

	ret = cafs_cond_lock(&req->cond);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, ;, "req:%p is released.", req);
	SET_FLAG(req->flags, CAFS_PFILE_EXIT);

	if(req->ctx) {
		cafs_cond_notify_all(&req->cond);
		cafs_cond_unlock(&req->cond);
		cafs_usleep(100);
		cafs_cond_lock(&req->cond);
	}
	
	while(!QUEUE_EMPTY(&req->q_msg)){
		iter = QUEUE_HEAD(&req->q_msg);
		rx_msg = QUEUE_DATA(iter, struct pfile_message, q);
		QUEUE_REMOVE(iter);
		pfile_destroy_message(rx_msg);
	}
	cafs_cond_unlock(&req->cond);
	cafs_cond_destroy(&req->cond);
	SAFE_CAFS_FREE(req);
	return;
}

static struct pfile_message *pfile_create_message(struct cafs_vmsg *oneway)
{
	struct pfile_message *msg;
	int ret;
	CommonHead *rsp_head;

	rsp_head = unpack_msg_common(oneway->head, oneway->head_len);
	LOG_THEN_RETURN_VAL_IF_TRUE(!rsp_head, NULL, "unpack_msg_common fail, head_len:%u.", oneway->head_len);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!rsp_head->private_head.data, del_head, "private_head null.");
	
	msg = (struct pfile_message *)CAFS_ALLOC(sizeof(struct pfile_message), NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!msg, del_head, "msg null fail.");
	memset(msg, 0, sizeof(struct pfile_message));
	QUEUE_INIT(&msg->q);

	msg->msg_id = (uint32_t)rsp_head->msg_id;
	switch (msg->msg_id)
	{
	case (uint32_t)MSG_ID_CA_PFILE_RSP_WRITE:
		msg->write =  (CaPfileRspWrite *)fsmsg_decode_new(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_WRITE),
												 rsp_head->private_head.data, rsp_head->private_head.len);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!msg->write, free_msg, "fsmsg decode write fail, private_head_len:%u.", rsp_head->private_head.len);
		msg->req_id = msg->write->w_magic;
		break;
	case (uint32_t)MSG_ID_CA_PFILE_RSP_READ:
		msg->read =  (CaPfileRspRead *)fsmsg_decode_new(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_READ),
												 rsp_head->private_head.data, rsp_head->private_head.len);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!msg->read, free_msg, "fsmsg decode write fail, private_head_len:%u.", rsp_head->private_head.len);
		msg->req_id = msg->read->r_magic;
		break;
	default:
		CAFS_LOG_ERROR("unknown msg id[%u]", msg->msg_id);
		goto free_msg;
		break;
	}
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!msg->req_id, free_msg, "msg->req_id invalid.");

	fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), rsp_head);
	msg->vmsg = oneway;

	return msg;
free_msg:
	SAFE_CAFS_FREE(msg);
del_head:
	fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), rsp_head);
	return NULL;
}


static void pfile_destroy_message(struct pfile_message *msg)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!msg, ;, "msg null.");
	switch (msg->msg_id)
	{
	case (uint32_t)MSG_ID_CA_PFILE_RSP_WRITE:
		if(msg->write)
			fsmsg_decode_delete(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_WRITE), msg->write);
		msg->write = NULL;
		break;
	case (uint32_t)MSG_ID_CA_PFILE_RSP_READ:
		if(msg->read){
			fsmsg_decode_delete(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_READ), msg->read);
		}
		msg->read = NULL;
		break;
	default:
		CAFS_LOG_ERROR("unknown");
		break;
	}
	if (msg->vmsg){
		cafs_put_oneway_vmsg(msg->vmsg);
		msg->vmsg = NULL;
	}
	SAFE_CAFS_FREE(msg);
	return;
}


static struct pfile_request *get_pfile_request(struct _pfile_obj_ctx *pentity)
{
	struct pfile_request *req;
	int ret;
	int i ;
	QUEUE* iter;
	khiter_t kh_iter = 0; //iter
	
	ret = cafs_mutex_lock(&pentity->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_mutex_lock fail.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(IS_SET(pentity->flags, CAFS_PFILE_EXIT), unlock, " node[%p] exit.", pentity);

	if (QUEUE_EMPTY(&pentity->q_idle)) {
		for (i = 0; i < 64; i++) {
			pentity->rxmsg_max_num++;
			req = pfile_create_request(pentity->rxmsg_max_num);
			LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!req, unlock, "pfile_create_request fail.");
			req->pfile_id = pentity->pfile_id;
			QUEUE_INSERT_TAIL(&pentity->q_idle, &req->q);
			req->req_id = kh_put(h_rxmsg, pentity->rxmsg, pentity->rxmsg_max_num, &ret);
			LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret < 0, unlock, "kh_put node id [%u] fail.", pentity->rxmsg_max_num);
		}
		pentity->idle_cnt += 64;
	}
	iter = QUEUE_HEAD(&pentity->q_idle);
	QUEUE_REMOVE(iter);
	QUEUE_INIT(iter);
	pentity->idle_cnt--;
	QUEUE_INSERT_TAIL(&pentity->q_work, iter);
	req = QUEUE_DATA(iter, struct pfile_request, q);
	req->ctx = pentity;
	kh_val(pentity->rxmsg, (khiter_t)req->req_id) = req;
	cafs_mutex_unlock(&pentity->lock);
	QUEUE_INIT(&req->q_msg);
	return req;

unlock:
	cafs_mutex_unlock(&pentity->lock);
	return NULL;
}

static void put_pfile_request(struct _pfile_obj_ctx *pentity, struct pfile_request *req)
{
	int ret;
	int i;
	QUEUE* iter;
	struct pfile_message *rx_msg;
	khiter_t kh_iter = 0; //iter

	while(!QUEUE_EMPTY(&req->q_msg)){
		iter = QUEUE_HEAD(&req->q_msg);
		QUEUE_REMOVE(iter);
		QUEUE_INIT(iter);
		rx_msg = QUEUE_DATA(iter, struct pfile_message, q);
		pfile_destroy_message(rx_msg);
	}
	QUEUE_INIT(&req->q_msg);

	req->rx_num = 0;
	req->tx_num = 0;
	req->offset = 0;
	req->msg_id = 0;

	ret = cafs_mutex_lock(&pentity->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, ;, "cafs_mutex_lock fail.");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(IS_SET(pentity->flags, CAFS_PFILE_EXIT), unlock, " node[%p] exit.", pentity);
	QUEUE_REMOVE(&req->q);
	QUEUE_INIT(&req->q);
	pentity->idle_cnt++;
	QUEUE_INSERT_TAIL(&pentity->q_idle, &req->q);
	kh_val(pentity->rxmsg, (khiter_t)req->req_id) = NULL;
	req->ctx = NULL;
	cafs_mutex_unlock(&pentity->lock);

	return;
unlock:
	cafs_mutex_unlock(&pentity->lock);
	return;
}

static int oneway_callback(struct cafs_vmsg *oneway, void *usr_context)
{
	int ret;
	khiter_t iter = 0; //iter
	struct pfile_message *rx_msg;
	struct pfile_request *req = NULL;
	struct _pfile_obj_ctx *pentity = (struct _pfile_obj_ctx *)usr_context;

	rx_msg = pfile_create_message(oneway);
	LOG_THEN_RETURN_VAL_IF_TRUE(!rx_msg, CAFS_ERR, "pfile_create_message with oneway[%p] fail.", oneway);

	ret = cafs_mutex_lock(&pentity->lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_message, "cafs_mutex_lock fail.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE((IS_SET(pentity->flags, CAFS_PFILE_EXIT)), free_message, "node exit.");

	pentity->rx_cnt++;
	if (kh_exist(pentity->rxmsg, (khiter_t)rx_msg->req_id)) {

		req = kh_val(pentity->rxmsg, (khiter_t)rx_msg->req_id);
		cafs_mutex_unlock(&pentity->lock);

		LOG_THEN_RETURN_VAL_IF_TRUE(!req, CAFS_ERR, "req id[%u] is reclaim, msg_id:%u.", 
									rx_msg->req_id, rx_msg->msg_id);
		LOG_THEN_RETURN_VAL_IF_TRUE(rx_msg->msg_id != req->msg_id, CAFS_ERR, 
								"req msg id[%u] , but req msg-id[%u].", rx_msg->msg_id, req->msg_id);

		ret = cafs_cond_lock(&req->cond);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_message, "cafs_cond_lock fail.");
		QUEUE_INSERT_TAIL(&req->q_msg, &rx_msg->q);
		cafs_cond_notify(&req->cond);
		cafs_cond_unlock(&req->cond);
	}else{
		cafs_mutex_unlock(&pentity->lock);
		CAFS_LOG_ERROR("it can't find req id [%u] on pentity[%p].", rx_msg->req_id, pentity);
		pfile_destroy_message(rx_msg);
	}
	
	return CAFS_OK;

free_message:
	pfile_destroy_message(rx_msg);
	return -1;
}


static int send_data(struct _pfile_obj_ctx *pentity, const void *head, uint64_t head_len, const void *data, uint64_t data_len)
{
	struct connect_obj *con;
	void *msg_head = NULL;
	struct cafs_vmsg msg_send;
	struct iovec *vecptr;
	uint32_t i;
	int ret ;
	uint64_t last_num;

	memset(&msg_send, 0, sizeof(msg_send));
	msg_send.head_len = head_len;
	msg_send.head = (void *)head;
	LOG_THEN_RETURN_VAL_IF_TRUE(!msg_send.head_len, CAFS_ERR, "msg_head_len  is 0.");

	last_num = (data_len % pentity->msg_iov_max_len);
	msg_send.vec_num = (last_num)? 1: 0 ;
	msg_send.vec_num += data_len / pentity->msg_iov_max_len;
	last_num = (last_num)?last_num:pentity->msg_iov_max_len;
	if (msg_send.vec_num> CAFS_IOV_NUM) {
		msg_send.vecptr = CAFS_ALLOC(msg_send.vec_num * sizeof(struct iovec), NULL);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!msg_send.vec, free_buf, "CAFS_ALLOC fail.");
		msg_send.type = CAFS_VEC_E_PTR;
		vecptr = msg_send.vecptr;
	}else{
		msg_send.type = CAFS_VEC_E_IOV;
		vecptr = msg_send.vec;
	}
	for (i = 0 ; i < msg_send.vec_num; i++) {
		vecptr[i].iov_base = (char *)data + (i * pentity->msg_iov_max_len);
		vecptr[i].iov_len = (i == msg_send.vec_num -1)? last_num: pentity->msg_iov_max_len;
	}

	ret = cafs_send_oneway(pentity->con, &msg_send);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "cafs_send_oneway fail.");
	pentity->tx_cnt++;

	if (msg_send.type == CAFS_VEC_E_PTR) {
		SAFE_CAFS_FREE(msg_send.vecptr);
	}

	return 0;

free_buf:
	if (msg_send.type == CAFS_VEC_E_PTR) {
		SAFE_CAFS_FREE(msg_send.vecptr);
	}
	return -1;
}

static uint32_t pack_msg_common(void *private, uint32_t private_len, void **pack_out, uint64_t msg_id)
{
	CommonHead header;
	uint32_t pack_len;
	int ret;

	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), &header, sizeof(header));
	header.msg_id = msg_id;
	header.entity = _SELF_ROLE;
	header.entity_id = 10086;
	header.seg_num = 1;
	header.seg_sn = 0;
	header.seg_total = 0;
	header.type = DATA_TYPE__DATA_E_BIN;
	header.private_id = msg_id;
	header.private_type = DATA_TYPE__DATA_E_PROTO;
	header.private_head.data = private;
	header.private_head.len = private_len;
	pack_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), &header, sizeof(header));
	*pack_out = CAFS_ALLOC(pack_len, NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!*pack_out, CAFS_ERR, "CAFS_ALLOC fail.");
	
	ret = fsmsg_encode(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), &header, *pack_out);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "fsmsg_encode fail.");

	return pack_len;
free_buf:
	SAFE_CAFS_FREE(*pack_out);
	return 0;
}

static CommonHead *unpack_msg_common(void *head, uint32_t head_len)
{
	CommonHead *header;
	header = (CommonHead *)fsmsg_decode_new(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), head, head_len);
	LOG_THEN_RETURN_VAL_IF_TRUE(!header, NULL, "fsmsg_decode_new common head fail.");
	// to do check head
	return header;
}

// function
static int do_write_request(struct _pfile_obj_ctx *pentity, 
							CaPfileReqHead *header,
							uint64_t w_offset,
							struct pfile_request *req,
							const void *buf, uint64_t count)
{
	int ret = 0;
	uint64_t slices_num = 0;
	uint64_t i;
	uint64_t last_slices_size;
	CaPfileReqWrite write_req;
	void *pack_buf = NULL;
	uint64_t pack_len = 0;
	
	last_slices_size = count%pentity->msg_data_max_len;
	slices_num = (last_slices_size)?1:0;
	slices_num +=  (count/pentity->msg_data_max_len);
	last_slices_size = (last_slices_size)?last_slices_size:pentity->msg_data_max_len;
	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_WRITE), &write_req, sizeof(write_req));
	write_req.w_magic = req->req_id;
	write_req.w_seg_num = slices_num;
	write_req.head = header;
	req->tx_num = slices_num;
	for (i = 0; i < (MAX_SN_NUM/32); i++) {
		req->bits[i] = 0;
	}
	LOG_THEN_RETURN_VAL_IF_TRUE(slices_num >  MAX_SN_NUM, -1, "slices_num is over max %u.", MAX_SN_NUM);
	// 分片发送
	for (i = 0; i < slices_num; i++) {
		write_req.w_offset =  w_offset + i * pentity->msg_data_max_len;
		write_req.w_seg_sn = i;
		write_req.w_seg_size =  (i == (slices_num -1))?last_slices_size: pentity->msg_data_max_len;
		req->bits[i/32] |= (1<<(i%32));
		pack_len = pack_write_req_msg(&write_req, &pack_buf);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pack_len, free_buf, "pack_len is 0 fail.");

		CAFS_LOG_DEBUG("send_data, magic:%lu", write_req.w_magic);
		CAFS_LOG_DEBUG("send_data, w_seg_sn:%lu", write_req.w_seg_sn);
		CAFS_LOG_DEBUG("send_data, w_offset:%lu", write_req.w_offset);
		CAFS_LOG_DEBUG("send_data, w_seg_size:%lu", write_req.w_seg_size);

		ret = send_data(pentity, pack_buf, pack_len, (uint8_t*)buf + (i * pentity->msg_data_max_len), write_req.w_seg_size);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "send_data fail.");
		SAFE_CAFS_FREE(pack_buf);
	}
	
	return 0;

free_buf:
	SAFE_CAFS_FREE(pack_buf);
	return -1;
}

static uint32_t pack_write_req_msg(CaPfileReqWrite *write_req, void **pack_buf)
{
	void *private;
	int ret;
	uint64_t pack_len, private_len;

	private_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_WRITE), write_req, sizeof(CaPfileReqWrite));
	LOG_THEN_RETURN_VAL_IF_TRUE(!private_len, CAFS_ERR, "private_len is 0.");

	private = CAFS_ALLOC(private_len, NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!private, CAFS_ERR, "private is null.");

	ret = fsmsg_encode(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_WRITE), write_req, private);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "fsmsg_encode fail.");

	pack_len = pack_msg_common(private, private_len, pack_buf, MSG_ID_CA_PFILE_REQ_WRITE);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pack_len, free_buf, "pack_msg_common pack_len is 0, fail.");

	SAFE_CAFS_FREE(private);

	return pack_len;

free_buf:
	SAFE_CAFS_FREE(private);
	return 0;
}

static int wait_write_finish(struct pfile_request *req)
{
	int ret;
	int32_t sn = 0;
	uint32_t i;
	int timeout_cnt = WAIT_OW_RSP_MSG_MAT_TIMEOUT_S/2;
	while((req->rx_num != req->tx_num) && timeout_cnt){
		sn = get_write_rsp_sn(req, 2*1000);
		if(sn < 0 || sn > MAX_SN_NUM){
			CAFS_LOG_ERROR("get write rsp fail, sn:%d, reqid:%u, tx:%u, rx:%u, timeout cnt:%d pfile:%p", 
				sn, req->req_id, req->tx_num, req->rx_num, timeout_cnt, req->ctx);
			LOG_THEN_RETURN_VAL_IF_TRUE(IS_SET(req->flags, CAFS_PFILE_EXIT), -1, "req[%u] exit", req->req_id);
			ret = pfile_connect_islive(req->ctx);
			LOG_THEN_RETURN_VAL_IF_TRUE(!ret, -1, "connection down, req[%u] exit", req->req_id);
			timeout_cnt--;
			continue;
		}
		if((req->bits[sn/32]) | (1 << (sn%32))){
			req->rx_num++;
			req->bits[sn/32] &= ~((1<<(sn%32)));
		}else{
			CAFS_LOG_ERROR("get read data time out, req offset:%lu, rx_sn:%d, pfile:%p.", req->offset, sn, req->ctx);
		}
	}
	if (req->rx_num != req->tx_num) {
		for(i = 0; i < req->tx_num; i++) {
			if((req->bits[i/32]) & (1 << (i%32))){
				CAFS_LOG_ERROR("get write sn[%u] rsp fail", i);
			}
		}
		return -1;
	}
	return 0;
}

static int32_t get_write_rsp_sn(struct pfile_request *req, uint64_t timeout_ms)
{
	struct pfile_message *rsp;
	int ret;
	QUEUE* iter;
	CaPfileRspWrite *rsp_msg =NULL;
	int32_t seg_sn  = -1;

	ret = cafs_cond_lock(&req->cond);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, -1, "cafs_cond_lock fail.");

	while(QUEUE_EMPTY(&req->q_msg)) {
		ret = cafs_cond_wait_timeout(&req->cond, timeout_ms);
		if(ret){
			CAFS_LOG_ERROR("wait write rsp timeout[%lu ms] fail.", timeout_ms);
			cafs_cond_unlock(&req->cond);
			return -1;
		}
		if (IS_SET(req->flags, CAFS_PFILE_EXIT)) {
			CAFS_LOG_ERROR("write req[%u] exit.", req->req_id);
			cafs_cond_unlock(&req->cond);
			return -1;
		}
	}

	iter = QUEUE_HEAD(&req->q_msg);
	QUEUE_REMOVE(iter);
	QUEUE_INIT(iter);
	rsp = QUEUE_DATA(iter, struct pfile_message, q);
	cafs_cond_unlock(&req->cond);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!rsp->write, free_unpack, "write msg is null.");

	rsp_msg = rsp->write;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp->req_id != req->req_id, 
									free_unpack, 
									"msg id fail, rsp[%lu], but expect[%lu].", 
									rsp->req_id,
									req->req_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp->msg_id != MSG_ID_CA_PFILE_RSP_WRITE, 
									free_unpack, 
									"msg id fail, rsp[%lu], but expect[%lu].", 
									rsp->msg_id,
									MSG_ID_CA_PFILE_RSP_WRITE);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_msg->w_seg_num != req->tx_num, 
									free_unpack, 
									"seg_num fail, rsp[%lu], but expect[%lu].", 
									rsp_msg->w_seg_num,
									req->tx_num);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_msg->head->cnode_id != req->pfile_id, 
									free_unpack, 
									"pfile_id fail, rsp[%lu], but expect[%u].", 
									rsp_msg->head->cnode_id,
									req->pfile_id);
	seg_sn = rsp_msg->w_seg_sn;
	CAFS_LOG_DEBUG("write rx sn:%d, bits[%u]:%lx", seg_sn, seg_sn/32, req->bits[seg_sn/32]);
	pfile_destroy_message(rsp);

	return seg_sn;
free_unpack:
	if (rsp) {
		pfile_destroy_message(rsp);
	}
	return -1;
}

static int64_t pfile_write_out(const struct pfile_node_obj *node_obj, const struct pfile_w_msg *w_msg, const void *buf, int64_t count)
{
	/*int ret;
	struct pfile_w_msg w_info;
	int64_t write_size = 0;
	int64_t tmp = 0;
	int64_t wanted_write_size = 0;
	PFILE_NODE_CTX(pentity, node_obj, CAFS_ERR);

	w_info = *w_msg;
	while(count > 0){
		wanted_write_size = (count/pentity->msg_data_max_len)?(int64_t)pentity->msg_data_max_len:count;
		tmp = pfile_write(node_obj, &w_info, (uint8_t*)buf + write_size, wanted_write_size);
		if(tmp < 0){
			CAFS_LOG_ERROR("pfile_write fail, offset:%ld, write size:%ld.", w_info.w_offset, wanted_write_size);
			break;
		}
		write_size += tmp;
		if(count >= tmp){
			count -= tmp;
		}else{
			count = 0;
		}
		w_info.w_offset += tmp;
	}*/

	return pfile_write(node_obj, w_msg, buf, count);
}

static int64_t pfile_write(const struct pfile_node_obj *node_obj, const struct pfile_w_msg *w_msg, const void *buf, int64_t count)
{
	int ret = 0;
	CaPfileReqHead header;
	int retry_cnt = 1;
	int64_t write_cnt = 0;
	struct pfile_request *req_msg;
	PFILE_NODE_CTX(pentity, node_obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!node_obj, CAFS_ERR, "node_obj is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!w_msg, CAFS_ERR, "w_msg is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf, CAFS_ERR, "write buf is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!count, CAFS_ERR, "write count is 0.");
	LOG_THEN_RETURN_VAL_IF_TRUE(count > (int64_t)w_msg->w_max_size, CAFS_ERR,
								 "write count is over max limit for write.");

	req_msg = get_pfile_request(pentity);
	LOG_THEN_RETURN_VAL_IF_TRUE(!req_msg, CAFS_ERR, "get_pfile_request null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_HEAD), &header, sizeof(CaPfileReqHead));
	header.client_id = w_msg->client_id;
	header.cnode_id = pentity->pfile_id;
	header.obj_id = w_msg->obj_id;
	header.gid = w_msg->gid;
	header.uid = w_msg->uid;

	req_msg->msg_id = MSG_ID_CA_PFILE_REQ_WRITE;
	while(retry_cnt--){
		ret = do_write_request(pentity, &header, w_msg->w_offset, req_msg, buf, count);
		if (ret) {
			CAFS_LOG_ERROR("do_write_request fail.");
			break;
		}

		ret = wait_write_finish(req_msg);
		if (ret) {
			CAFS_LOG_ERROR("wait write finish fail, tx cnt[%lu], rx cnt[%lu]", pentity->tx_cnt, pentity->rx_cnt);
			cafs_connect_obj_status(pentity->con);
			continue;
		}
		break;
	}
	put_pfile_request(pentity, req_msg);
	return ret?(-1):(int64_t)count;
}

static uint32_t pack_read_req_msg(CaPfileReqRead *read_req, void **pack_buf)
{
	void *private;
	int ret;
	uint64_t pack_len, private_len;
	CommonHead *header =NULL;

	private_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_READ), read_req, sizeof(CaPfileReqRead));
	LOG_THEN_RETURN_VAL_IF_TRUE(!private_len, CAFS_ERR, "private_len is 0.");

	private = CAFS_ALLOC(private_len, NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!private, CAFS_ERR, "private is null.");

	ret = fsmsg_encode(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_READ), read_req, private);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "fsmsg_encode fail.");

	pack_len = pack_msg_common(private, private_len, pack_buf, MSG_ID_CA_PFILE_REQ_READ);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pack_len, free_buf, "pack_msg_common pack_len is 0, fail.");

	SAFE_CAFS_FREE(private);

	return pack_len;

free_buf:
	SAFE_CAFS_FREE(private);
	return 0;

}

static int do_read_request(struct _pfile_obj_ctx *pentity, CaPfileReqHead *header, struct pfile_request *req, int64_t size)
{
	int ret = 0;
	uint64_t slices_num;
	uint64_t i;
	uint64_t last_slices_size;
	CaPfileReqRead read_req;
	void *pack_buf;
	uint64_t pack_len;

	last_slices_size = size%pentity->msg_data_max_len;
	slices_num = (last_slices_size)?1:0;
	slices_num +=  (size/pentity->msg_data_max_len);
	last_slices_size = (last_slices_size)?last_slices_size:pentity->msg_data_max_len;

	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_READ), &read_req, sizeof(read_req));
	read_req.r_magic = req->req_id;
	read_req.head = header;
	read_req.r_seg_max_num = 1;
	read_req.r_seg_max_size = pentity->msg_data_max_len;
	req->tx_num = slices_num;
	for (i = 0; i < (MAX_SN_NUM/32); i++) {
		req->bits[i] = 0;
	}
	LOG_THEN_RETURN_VAL_IF_TRUE(slices_num >  MAX_SN_NUM, -1, "slices_num is over max %u.", MAX_SN_NUM);
	// 分片请求
	for (i = 0; i < slices_num; i++) {
		read_req.r_offset = req->offset + i * pentity->msg_data_max_len;
		read_req.r_size = (i == (slices_num -1))?last_slices_size: pentity->msg_data_max_len;
		read_req.r_seg_max_num = i;

		req->bits[i/32] |= (1<<(i%32));
		pack_len = pack_read_req_msg(&read_req, &pack_buf);
		LOG_THEN_RETURN_VAL_IF_TRUE(!pack_buf, CAFS_ERR, "pack_read_req_msg is null.");

		CAFS_LOG_DEBUG("read, magic:%lu", read_req.r_magic);
		CAFS_LOG_DEBUG("read, r_seg_max_num:%u", read_req.r_seg_max_num);
		CAFS_LOG_DEBUG("send, r_offset:%lu", read_req.r_offset);
		CAFS_LOG_DEBUG("read, r_size:%lu", read_req.r_size);

		ret = send_data(pentity, pack_buf, pack_len, NULL, 0);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "send_data  fail.");
		SAFE_CAFS_FREE(pack_buf);
	}

	return 0;
free_buf:
	SAFE_CAFS_FREE(pack_buf);
	return 0;
}

static int32_t get_read_data(struct _pfile_obj_ctx *pentity, struct pfile_request *req, void *buf, int64_t count, uint64_t timeout_ms)
{
	struct pfile_message *rsp;
	struct cafs_vmsg *rsp_vmsg;
	int ret;
	uint32_t i;
	CaPfileRspRead *rsp_msg =NULL;
	int64_t buf_w_offset = 0;
	QUEUE* iter;
	int32_t sn;
	struct iovec    *vecptr;

	ret = cafs_cond_lock(&req->cond);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, -1, "cafs_cond_lock fail.");//todo

	while(QUEUE_EMPTY(&req->q_msg)) {
		ret = cafs_cond_wait_timeout(&req->cond, timeout_ms);
		if(ret){
			CAFS_LOG_ERROR("wait read rsp timeout fail, [%lu ms].", timeout_ms);
			cafs_cond_unlock(&req->cond);
			return -1;
		}
		if (IS_SET(req->flags, CAFS_PFILE_EXIT)) {
			CAFS_LOG_ERROR("req[%u] exit.", req->req_id);
			cafs_cond_unlock(&req->cond);
			return -1;
		}
	}

	iter = QUEUE_HEAD(&req->q_msg);
	QUEUE_REMOVE(iter);
	QUEUE_INIT(iter);
	rsp = QUEUE_DATA(iter, struct pfile_message, q);
	cafs_cond_unlock(&req->cond);

	rsp_msg = rsp->read;
	rsp_vmsg = rsp->vmsg;

	CAFS_LOG_DEBUG("req obj_start:%lu", req->offset);
	CAFS_LOG_DEBUG("req count:%lu", count);

	CAFS_LOG_DEBUG("rsp r_magic:%lu", rsp_msg->r_magic);
	CAFS_LOG_DEBUG("rsp r_offset:%lu", rsp_msg->r_offset);
	CAFS_LOG_DEBUG("rsp r_seg_size:%lu", rsp_msg->r_seg_size);
	CAFS_LOG_DEBUG("rsp r_seg_sn:%lu", rsp_msg->r_seg_sn);
	CAFS_LOG_DEBUG("rsp cnode_id:%lu", rsp_msg->head->cnode_id);
	CAFS_LOG_DEBUG("rsp r_seg_num:%lu", rsp_msg->r_seg_num);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp->req_id != req->req_id, 
									put_rsp, 
									"req id fail, rsp[%lu], but expect[%lu].", 
									rsp->req_id,
									req->req_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp->msg_id != MSG_ID_CA_PFILE_RSP_READ, 
									put_rsp, 
									"msg fail, rsp[%lu], but expect[%lu].", 
									rsp->msg_id,
									MSG_ID_CA_PFILE_RSP_READ);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_msg->r_offset < req->offset, 
									put_rsp, 
									"r_offset fail, rsp[%lu], but expect over[%lu].", 
									rsp_msg->r_offset,
									req->offset);

	buf_w_offset = (rsp_msg->r_offset - req->offset);
	CAFS_LOG_DEBUG("buf_w_offset:%ld", buf_w_offset);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(buf_w_offset > count, 
									put_rsp, 
									"buf_w_offset fail, rsp[%ld], but expect it low then [%ld].", 
									buf_w_offset,
									count);
	assert((buf_w_offset +  (int64_t)rsp_msg->r_seg_size) <= count);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE((buf_w_offset +  (int64_t)rsp_msg->r_seg_size) > count, 
									put_rsp, 
									"r_seg_size fail, rsp[%lu], count [%ld], buf_w_offset[%ld].", 
									rsp_msg->r_seg_size, count,
									buf_w_offset);
	vecptr = get_cafsvmsg_vec(rsp_vmsg);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!vecptr, put_rsp, "vecptr is null.");

	for (i = 0; i< rsp_vmsg->vec_num; i++) {
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!vecptr[i].iov_base, put_rsp, "vecptr[%u] is null.", i);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE((vecptr[i].iov_len + (uint64_t)buf_w_offset) > (uint64_t)count, 
									put_rsp, "offset[%lu] is over max buf len[%ld].",
									(uint64_t)(vecptr[i].iov_len + buf_w_offset),
									count);
		memcpy((uint8_t *)buf + buf_w_offset, vecptr[i].iov_base, vecptr[i].iov_len);
		buf_w_offset +=vecptr[i].iov_len;
	}
	sn = (int32_t)((rsp_msg->r_offset - req->offset)/pentity->msg_data_max_len);
	CAFS_LOG_DEBUG("rsp sn:%d", sn);
	pfile_destroy_message(rsp);
	
	return sn;

put_rsp:
	if (rsp) {
		pfile_destroy_message(rsp);
		rsp = NULL;
	}
	return -1;
}

static int64_t wait_read_finish(struct _pfile_obj_ctx *pentity, struct pfile_request *req, void *buf, int64_t count)
{
	uint32_t i;
	int64_t rx_sn;
	int ret;
	int timeout_cnt = WAIT_OW_RSP_MSG_MAT_TIMEOUT_S/2; //超时时间等于timeout_s*WAIT_OW_RSP_MSG_MAT_TIMEOUT_MS
	while((req->rx_num != req->tx_num) && timeout_cnt){
		rx_sn =get_read_data(pentity, req, buf, count, 2*1000);
		if(rx_sn < 0 || rx_sn > MAX_SN_NUM){
			CAFS_LOG_ERROR("get read data time out, req-id:%u, offset:%lu,tx-num:%u, rx-num:%u, timeout_cnt:%d, pfile:%p.", 
							req->req_id, req->offset, req->tx_num, req->rx_num, timeout_cnt, req->ctx);
			LOG_THEN_RETURN_VAL_IF_TRUE(IS_SET(req->flags, CAFS_PFILE_EXIT), -1, "req[%u] exit", req->req_id);
			ret = pfile_connect_islive(req->ctx);
			LOG_THEN_RETURN_VAL_IF_TRUE(!ret, -1, "connection down, req[%u] exit", req->req_id);
			timeout_cnt--;
			continue;
		}
		if((req->bits[rx_sn/32]) | (1 << (rx_sn%32))){
			req->rx_num++;
			req->bits[rx_sn/32] &= ~((1<<(rx_sn%32)));
		}else{
			CAFS_LOG_ERROR("get read data time out, req offset:%lu, rx_sn:%d, pfile:%p.", req->offset, rx_sn, req->ctx);
		}
	}
	if (req->rx_num != req->tx_num) {
		for(i = 0; i < req->tx_num; i++) {
			if((req->bits[i/32]) & (1 << (i%32))){
				CAFS_LOG_ERROR("get write sn[%u] rsp fail", i);
			}
		}
		return -1;
	}

	return count;
}

static int64_t pfile_read_out(const struct pfile_node_obj *node_obj, const struct pfile_r_msg *r_msg, void *buf, int64_t count)
{
	/*int ret;
	struct pfile_r_msg r_info;
	int64_t read_size = 0;
	int64_t tmp = 0;
	int64_t wanted_read_size = 0;
	PFILE_NODE_CTX(pentity, node_obj, CAFS_ERR);

	r_info = *r_msg;
	while(count){
		wanted_read_size = (count/pentity->msg_data_max_len)?(int64_t)pentity->msg_data_max_len:count;
		tmp = pfile_read(node_obj, &r_info, (uint8_t *)buf + read_size, wanted_read_size);
		if(tmp < 0){
			CAFS_LOG_ERROR("pfile_read fail.");
			break;
		}
		read_size += tmp;
		if(count >= tmp){
			count -= tmp;
		}else{
			count = 0;
		}
	
		r_info.r_offset += tmp;
	}*/

	return pfile_read(node_obj, r_msg, buf, count);
}

static int64_t pfile_read(const struct pfile_node_obj *node_obj, const struct pfile_r_msg *r_msg, void *buf, int64_t count)
{
	struct _pfile_entity_ctx *ctx;
	int ret = 0;
	CaPfileReqHead header;
	int64_t read_cnt = 0;
	int retry = 1;
	struct pfile_request *req_msg;
	PFILE_NODE_CTX(pentity, node_obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!node_obj, CAFS_ERR, "node_obj is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!r_msg, CAFS_ERR, "r_msg is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf, CAFS_ERR, "read buf is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(count < 0, CAFS_ERR, "read count is low 0.");
	LOG_THEN_RETURN_VAL_IF_TRUE(count > (int64_t)r_msg->r_max_size, CAFS_ERR,
								 "read count is over max limit on read.");
	req_msg = get_pfile_request(pentity);
	LOG_THEN_RETURN_VAL_IF_TRUE(!req_msg, CAFS_ERR, "get_pfile_request is null.");

	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_req, MSG_ID_CA_PFILE_REQ_HEAD), &header, sizeof(CaPfileReqHead));
	header.client_id = r_msg->client_id;
	header.cnode_id = pentity->pfile_id;
	header.obj_id = r_msg->obj_id;
	header.gid = r_msg->gid;
	header.uid = r_msg->uid;
	req_msg->offset = r_msg->r_offset;

	req_msg->msg_id = MSG_ID_CA_PFILE_REQ_READ;
	while(retry--){
		ret = do_read_request(pentity, &header, req_msg, count);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "do_read_request fail.");
		if (ret) {
			CAFS_LOG_ERROR("do_read_request fail, offset:%lu, count:%ld.", req_msg->offset, count);
			break;
		}

		read_cnt = wait_read_finish(pentity, req_msg, buf, count);
		if (read_cnt < 0) {
			CAFS_LOG_ERROR("wait read rsp fail, tx cnt[%lu], rx cnt[%lu]", pentity->tx_cnt, pentity->rx_cnt);
			cafs_connect_obj_status(pentity->con);
			continue;
		}
		break;
	}
	put_pfile_request(pentity, req_msg);
	return read_cnt;
}
