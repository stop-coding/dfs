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
#include "cafs_pfile.h"
#include "fsmsg.h"

#include "khash.h"

#include <unistd.h>

static const  EntityRole _SELF_ROLE  = ENTITY_ROLE__CA;
static const  uint64_t _SELF_ROLE_ID = 0x6734;

#define MINI_IO_CONN_NUM         2
#define MINI_IO_MAX_DATA		(128*1024)
#define MINI_IO_MAX_IOV_LEN		(4*1024)

#define MINI_IO_KEEP_LIVE_TIMES_MS    (5*60*1000)
//大IO链路保持时间
#define BIG_IO_KEEP_ALIVE_TIME_MS	  (60*1000)

#define PFILE_CTX(ctx_name, obj, ret)\
struct _pfile_obj_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _pfile_obj_ctx *)obj->ctx;

struct _pfile_node{
	int32_t _ref;
	uint32_t pfile_id;
	time_t access_time;
	struct vnode_cfg node_cfg;
	struct pfile_node_obj *node;
	struct pfile_node_obj *bigio_node;
};

/*! @brief   定义哈希表所用的方法 */
KHASH_MAP_INIT_INT64(h_pfile, struct _pfile_node*);

struct _pfile_obj_ctx{
   	khash_t(h_pfile) *map;
	struct cafs_mutex lock;
	const struct cafs_cfg_obj *cfg;
};

//common
static int cafs_pfile_msg_init(struct fsmsg_allocator *ops);
static void cafs_pfile_msg_exit();

static struct _pfile_node *create_pfile_node(const struct vnode_cfg *node);
static int destroy_pfile_node(struct _pfile_node *entity);

static int create_node(struct _pfile_node *entity);
static int destroy_node(struct _pfile_node *entity);

static int create_bigio_node(struct _pfile_node *entity);
static int destroy_bigio_node(struct _pfile_node *entity);

static const struct pfile_node_obj *get_pfile_node(struct pfile_obj *obj, uint32_t pfile_id);
static int put_pfile_node(struct pfile_obj *obj, uint32_t pfile_id);

static const struct pfile_node_obj *get_bigio_node(struct pfile_obj *obj, uint32_t pfile_id);

static struct pfile_ops pfile_ops = {
	.get = &get_pfile_node,
	.put  = &put_pfile_node,
	.get_bigio = &get_bigio_node,
};

struct pfile_obj *cafs_create_pfile(const struct pfile_cfg *cfg)
{
	struct pfile_obj *obj = NULL;
	int ret;
	struct _pfile_obj_ctx *ctx;
	struct connect_init_param conn_para = {0};

	LOG_THEN_RETURN_VAL_IF_TRUE(!cfg, NULL, "cfg is null");

	// 初始化
	conn_para.connect_id = cfg->cfg->usr_id;
	conn_para.thread_max_num = cfg->cfg->thread_num;

	ret = cafs_connect_init(&conn_para);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_connect_init fail.");

	ret = cafs_pfile_msg_init(NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_msg_init fail.");

	obj = (struct pfile_obj *)CAFS_ALLOC(sizeof(struct pfile_obj) + sizeof(struct _pfile_obj_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC connect_obj fail.");
	memset(obj, 0, sizeof(struct pfile_obj) + sizeof(struct _pfile_obj_ctx));
	ctx = (struct _pfile_obj_ctx *)obj->ctx;

	obj->ops = &pfile_ops;
	ctx->map = kh_init(h_pfile);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->map, free_obj, "kh_init fail.");
	
	ret = cafs_mutex_init(&ctx->lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");

	ctx->cfg = cfg->cfg;

	return obj;
free_obj:
	if (ctx->map) {
		kh_clear(h_pfile, ctx->map);
		kh_destroy(h_pfile, ctx->map);
		ctx->map = NULL;
	}
	cafs_mutex_destroy(&ctx->lock);
	SAFE_CAFS_FREE(obj);
	return NULL;
}

int cafs_destroy_pfile(struct pfile_obj *obj)
{
	int ret;
	struct _pfile_node *pfile;
	PFILE_CTX(ctx, obj, CAFS_ERR);

	ret = cafs_mutex_lock(&ctx->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	if (ctx->map){
		kh_foreach_value(ctx->map, pfile, destroy_pfile_node(pfile));
		kh_clear(h_pfile, ctx->map);
		kh_destroy(h_pfile, ctx->map);
	}

	cafs_mutex_unlock(&ctx->lock);

	cafs_mutex_destroy(&ctx->lock);

	cafs_pfile_msg_exit();
	cafs_connect_shutdown();
	SAFE_CAFS_FREE(obj);
	return 0;
}

static int cafs_pfile_msg_init(struct fsmsg_allocator *ops)
{
    FSMSG_BOX_INIT(ca_pfile_req, ops);
	FSMSG_BOX_INIT(ca_pfile_rsp, ops);
	FSMSG_BOX_INIT(common, ops);
    return 0;
}

static void cafs_pfile_msg_exit()
{
    FSMSG_BOX_EXIT(ca_pfile_req);
	FSMSG_BOX_EXIT(ca_pfile_rsp);
	FSMSG_BOX_EXIT(common);
    return;
}

// TODO加写锁
static inline struct _pfile_node *insert_pfile_node(const struct vnode_cfg *node, khash_t(h_pfile) *map)
{
	khiter_t iter = 0; //iter
	int ret;
	struct _pfile_node *pentity;

	pentity = create_pfile_node(node);
	if (!pentity) {
		CAFS_LOG_ERROR("create_pfile_node [%s] fail.", node->addr);
		return NULL;
	}

	iter = kh_get(h_pfile, map, pentity->pfile_id);
	if (iter == kh_end(map)){
		iter = kh_put(h_pfile, map, pentity->pfile_id, &ret);
		if ( ret < 0){
			CAFS_LOG_ERROR("kh_put pfile id [%u] fail.", pentity->pfile_id);
			destroy_pfile_node(pentity);
			return NULL;
		}
		CAFS_LOG_DEBUG("kh_put mds id [%u] success.", pentity->pfile_id);
	}else{
		CAFS_LOG_NOTICE("get pfile entity by id[%u] on map list, replace it.", pentity->pfile_id);
	}
	kh_val(map, iter) = pentity;
	
	return pentity;
}

static inline int update_pfile_cfg(const struct vnode_cfg *node, struct _pfile_node *pfile)
{
	int ret;
	if (strcmp(node->addr, pfile->node_cfg.addr) != 0) {
		goto update;
	}

	if (node->port != pfile->node_cfg.port) {
		goto update;
	}

	if (node->connection != pfile->node_cfg.connection) {
		goto update;
	}

	return 0;
update:
	CAFS_LOG_NOTICE("pfile_id[%u] parameter change, ip[%s],port[%d] ", pfile->pfile_id, pfile->node_cfg.addr, pfile->node_cfg.port);
	pfile->node_cfg = *node;
	ret = destroy_node(pfile);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "destroy_node fail.");
	ret = destroy_bigio_node(pfile);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "destroy_bigio_node fail.");

	return 0;
}

static inline struct _pfile_node *create_pfile_node(const struct vnode_cfg *node)
{
	int ret;
	struct _pfile_node *entity;

	LOG_THEN_RETURN_VAL_IF_TRUE(!node, NULL, "vnode_cfg node is null");

	entity = CAFS_ALLOC(sizeof(struct _pfile_node), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity, NULL, "entity is null");

	memset(entity, 0, sizeof(struct _pfile_node));
	entity->node_cfg = *node;
	entity->pfile_id = entity->node_cfg.id;
	return entity;
}

static inline int destroy_pfile_node(struct _pfile_node *entity)
{
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity, CAFS_ERR, "entity is null");

	entity->_ref = 0;

	ret = destroy_node(entity);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "destroy_node fail.");

	ret = destroy_bigio_node(entity);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "destroy_bigio_node fail.");

	SAFE_CAFS_FREE(entity);

	return 0;
}

static inline int create_node(struct _pfile_node *entity)
{
	struct pfile_node_cfg cfg;
	int ret;
	struct vnode_cfg little_io_cfg;

	memset(&cfg, 0, sizeof(cfg));
	little_io_cfg = entity->node_cfg;
	little_io_cfg.connection = MINI_IO_CONN_NUM;
	little_io_cfg.msg_data_max_len = MINI_IO_MAX_DATA;
	little_io_cfg.msg_iov_max_len = MINI_IO_MAX_IOV_LEN;
	cfg.node = &little_io_cfg;
	cfg.timeout_ms = MINI_IO_KEEP_LIVE_TIMES_MS;
	entity->node = cafs_create_pfile_node(&cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity->node, CAFS_ERR, 
								"cafs_create_connect_obj fail, ip[%s], port[%d]", 
								entity->node_cfg.addr,
								entity->node_cfg.port);
	entity->node->type = PFILE_NODE_TYPE_MINI_IO;
	return 0;
}

static inline int destroy_node(struct _pfile_node *entity)
{
	int ret;

	if (entity->node) {
		ret = cafs_destroy_pfile_node(entity->node);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_destroy_pfile_node fail.");
		entity->node = NULL;
	}

	return 0;
}

static inline int create_bigio_node(struct _pfile_node *entity)
{
	struct pfile_node_cfg cfg;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	cfg.node = &entity->node_cfg;
	cfg.timeout_ms = BIG_IO_KEEP_ALIVE_TIME_MS;
	entity->bigio_node = cafs_create_pfile_node(&cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity->bigio_node, CAFS_ERR, 
								"cafs_create big node obj fail, ip[%s], port[%d]", 
								entity->node_cfg.addr,
								entity->node_cfg.port);
	entity->bigio_node->type = PFILE_NODE_TYPE_BIG_IO;
	return 0;
}

static inline int destroy_bigio_node(struct _pfile_node *entity)
{
	int ret;

	if (entity->bigio_node) {
		ret = cafs_destroy_pfile_node(entity->bigio_node);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_destroy_pfile_node fail.");
		entity->bigio_node = NULL;
	}

	return 0;
}

static inline const struct pfile_node_obj *get_node(struct pfile_obj *obj, uint32_t pfile_id, uint8_t isbigio)
{
	int ret;
	struct _pfile_node *entity;
	khiter_t iter = 0; //iter
	struct pfile_node_obj *node;
	struct vnode_cfg node_cfg = {0};

	PFILE_CTX(ctx, obj, NULL);

	// 配置获取
	ret = ctx->cfg->ops->get_pfile(ctx->cfg, pfile_id, &node_cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "get_mds[%u] form cfg fail", pfile_id);

	ret = cafs_mutex_lock(&ctx->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_rwlock_rdlock fail.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->map, unlock, "ctx->map is null");

	iter = kh_get(h_pfile, ctx->map, pfile_id);
	if(iter == kh_end(ctx->map)){
		entity = insert_pfile_node(&node_cfg, ctx->map);
		LOG_THEN_RETURN_VAL_IF_TRUE(!entity, NULL, "insert new pfile[%u] node fail.", pfile_id);
	}else{
		entity = kh_val(ctx->map, iter);
		ret = update_pfile_cfg(&node_cfg, entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "update pfile[%u] fail.", pfile_id);
	}

	if (isbigio) {
		if (!entity->bigio_node) {
			ret = create_bigio_node(entity);
			LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "create_pfile_node pfile id[%u] fail.", pfile_id);
		}
		node = entity->bigio_node;
	}else{
		if (!entity->node) {
			ret = create_node(entity);
			LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "create_pfile_node pfile id[%u] fail.", pfile_id);
		}
		node = entity->node;
	}
	cafs_mutex_unlock(&ctx->lock);
	return node;
unlock:
	cafs_mutex_unlock(&ctx->lock);
	return NULL;
}

static const struct pfile_node_obj *get_bigio_node(struct pfile_obj *obj, uint32_t pfile_id)
{
	return get_node(obj, pfile_id, 1);
}

static const struct pfile_node_obj *get_pfile_node(struct pfile_obj *obj, uint32_t pfile_id)
{
	return get_node(obj, pfile_id, 0);
}

static int put_pfile_node(struct pfile_obj *obj, uint32_t pfile_id)
{
/*	int ret;
	struct _pfile_node *entity;
	khiter_t iter = 0; //iter

	PFILE_CTX(ctx, obj, CAFS_ERR);

	ret = cafs_rwlock_rdlock(&ctx->lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_rdlock fail.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->map, unlock, "ctx->map is null");

	iter = kh_get(h_pfile, ctx->map, pfile_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(iter == kh_end(ctx->map), unlock, "can't find pfile id[%u] on map.", pfile_id);

	entity = kh_val(ctx->map, iter);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!entity, unlock, "can't find pfile id[%u] node obj on map.", pfile_id);
	if (entity->bigio_node) {
		ret = destroy_bigio_node(entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "destroy_node pfile id[%u] fail.", pfile_id);
		entity->bigio_node = NULL;
	}
	
	cafs_mutex_unlock(&ctx->lock);*/

	return 0;

/*unlock:
	cafs_mutex_unlock(&ctx->lock);
	return CAFS_ERR;*/
}
