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

#include "cafs_mds.h"
#include "khash.h"

#include <unistd.h>

static const  EntityRole _SELF_ROLE  = ENTITY_ROLE__CA;
static const  uint64_t _SELF_ROLE_ID = 0x6734;

#define MDS_CTX(ctx_name, obj, ret)\
struct _mds_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _mds_ctx *)obj->ctx;

#define MDS_KEEP_ALIVE_MAX_TIME_MS			(5*60*1000)

/*! @brief   定义哈希表所用的方法 */
KHASH_MAP_INIT_INT64(h_mds_node, struct _mds_node*);

struct _mds_ctx{
   	khash_t(h_mds_node) *map;
	const struct cafs_cfg_obj *cfg;
	struct cafs_rwlock rwlock;
};

struct _mds_node{
	int32_t _ref;
	struct vnode_cfg node_cfg;
	struct mds_node_obj *node;
};

static struct _mds_node *create_mds_node(const struct vnode_cfg *node);
static int destroy_mds_node(struct _mds_node *entity);
static int create_node(struct _mds_node *entity);
static int destroy_node(struct _mds_node *entity);

static const struct mds_node_obj *get_mds_node(struct mds_obj *obj, const char *path);
static const struct mds_node_obj *get_mds_node_by_vmds(struct mds_obj *obj, uint32_t vmds_id);
static int put_mds_node(struct mds_obj *obj, const struct mds_node_obj *node);

static struct mds_ops mds_ops = {
	.get = &get_mds_node,
	.get_by_vmds = &get_mds_node_by_vmds,
	.put = &put_mds_node,
};

struct mds_obj *cafs_create_mds(const struct mds_cfg *cfg)
{
	struct mds_obj *obj = NULL;
	int ret;
	struct _mds_ctx *ctx;
	struct connect_init_param conn_para = {0};

	LOG_THEN_RETURN_VAL_IF_TRUE(!cfg, NULL, "cfg is null");

	// 初始化
	conn_para.connect_id = cfg->cfg->usr_id;
	conn_para.thread_max_num = cfg->cfg->thread_num;
	ret = cafs_connect_init(&conn_para);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_connect_init fail.");

	ret = cafs_mds_msg_init(NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_msg_init fail.");

	obj = (struct mds_obj *)CAFS_ALLOC(sizeof(struct mds_obj) + sizeof(struct _mds_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC connect_obj fail.");
	memset(obj, 0, sizeof(struct mds_obj) + sizeof(struct _mds_ctx));
	ctx = (struct _mds_ctx *)obj->ctx;

	obj->ops = &mds_ops;
	ctx->map = kh_init(h_mds_node);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->map, free_obj, "kh_init fail.");

	ctx->cfg = cfg->cfg;

	ret = cafs_rwlock_init(&ctx->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");

	return obj;
free_obj:
	if (ctx->map) {
		kh_clear(h_mds_node, ctx->map);
		kh_destroy(h_mds_node, ctx->map);
		ctx->map = NULL;
	}
	cafs_rwlock_destroy(&ctx->rwlock);
	SAFE_CAFS_FREE(obj);
	return NULL;
}

int cafs_destroy_mds(struct mds_obj *obj)
{
	int ret;
	struct _mds_node *node;

	MDS_CTX(ctx, obj, CAFS_ERR);

	ret = cafs_rwlock_wrlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	if (ctx->map){
		kh_foreach_value(ctx->map, node, destroy_mds_node(node));
		kh_clear(h_mds_node, ctx->map);
		kh_destroy(h_mds_node, ctx->map);
	}

	cafs_rwlock_unlock(&ctx->rwlock);

	cafs_rwlock_destroy(&ctx->rwlock);

	cafs_mds_msg_exit();
	cafs_connect_shutdown();

	SAFE_CAFS_FREE(obj);
	return 0;
}

static inline struct _mds_node *insert_mds_node(const struct vnode_cfg *node, khash_t(h_mds_node) *map)
{
	int ret;
	khiter_t iter = 0; //iter
	struct _mds_node *node_entity;

	LOG_THEN_RETURN_VAL_IF_TRUE(!node, NULL, "node is null");
	LOG_THEN_RETURN_VAL_IF_TRUE(!map, NULL, "map is null");

	node_entity = create_mds_node(node);
	if (!node_entity) {
		CAFS_LOG_ERROR("create_mds_node [%s] fail.", node->addr);
		return NULL;
	}
	iter = kh_get(h_mds_node, map, node_entity->node_cfg.id);
	if (iter == kh_end(map)) {
		iter = kh_put(h_mds_node, map, node_entity->node_cfg.id, &ret);
		if ( ret < 0){
			CAFS_LOG_ERROR("kh_put mds id [%u] fail.", node_entity->node_cfg.id);
			destroy_mds_node(node_entity);
			return NULL;
		}
		CAFS_LOG_DEBUG("kh_put mds id [%u] success.", node_entity->node_cfg.id);
	}else{
		CAFS_LOG_NOTICE("mds id [%u] exitsed, reaplace it.", node_entity->node_cfg.id);
		SAFE_CAFS_FREE(kh_val(map, iter));
	}
	kh_val(map, iter) = node_entity;

	return node_entity;
}

static inline int update_mds_cfg(const struct vnode_cfg *node, struct _mds_node *mds)
{
	int ret;
	if (strcmp(node->addr, mds->node_cfg.addr) != 0) {
		goto update;
	}

	if (node->port != mds->node_cfg.port) {
		goto update;
	}

	if (node->connection != mds->node_cfg.connection) {
		goto update;
	}

	return 0;
update:
	mds->node_cfg = *node;
	ret = destroy_node(mds);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_destroy_mds_node fail.");
	return 0;
}

static inline struct _mds_node *create_mds_node(const struct vnode_cfg *node)
{
	int ret;
	struct _mds_node *entity;

	LOG_THEN_RETURN_VAL_IF_TRUE(!node, NULL, "vnode_cfg node is null");

	entity = CAFS_ALLOC(sizeof(struct _mds_node), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity, NULL, "entity is null");

	memset(entity, 0, sizeof(struct _mds_node));
	entity->node_cfg = *node;
	return entity;
}

static inline int destroy_mds_node(struct _mds_node *entity)
{
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity, CAFS_ERR, "entity is null");

	entity->_ref = 0;

	ret = destroy_node(entity);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_destroy_mds_node fail.");

	SAFE_CAFS_FREE(entity);

	return 0;
}

static inline int create_node(struct _mds_node *entity)
{
	struct mds_node_cfg cfg;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	cfg.node = &entity->node_cfg;
	cfg.timeout_ms = MDS_KEEP_ALIVE_MAX_TIME_MS;
	entity->node = cafs_create_mds_node(&cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(!entity->node, CAFS_ERR, 
								"cafs_create_connect_obj fail, ip[%s], port[%d]", 
								entity->node_cfg.addr,
								entity->node_cfg.port);
	return 0;
}

static inline int destroy_node(struct _mds_node *entity)
{
	int ret;

	if (entity->node) {
		ret = cafs_destroy_mds_node(entity->node);
		LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_destroy_mds_node fail.");
		entity->node = NULL;
	}

	return 0;
}

static const struct mds_node_obj *get_mds_node(struct mds_obj *obj, const char *path)
{
	int ret;
	struct _mds_node *entity;
	khiter_t iter = 0; //iter
	uint32_t mds_id = 0;
	struct vnode_cfg node_cfg;
	MDS_CTX(ctx, obj, NULL);

	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->cfg, NULL, "ctx->cfg is null");

	ret = ctx->cfg->ops->get_mds(ctx->cfg, path, &node_cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "get mds with id[%u] fail", mds_id);

	ret = cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_rwlock_rdlock fail.");

	mds_id = node_cfg.id;

	iter = kh_get(h_mds_node, ctx->map, mds_id);
	if(iter == kh_end(ctx->map)){
		// 新建节点
		cafs_rwlock_unlock(&ctx->rwlock);
		entity = insert_mds_node(&node_cfg, ctx->map);
		LOG_THEN_RETURN_VAL_IF_TRUE(!entity, NULL, "insert new mds[%u] node fail.", mds_id);
		cafs_rwlock_rdlock(&ctx->rwlock); //重新加锁
	}else{
		entity = kh_val(ctx->map, iter);
		ret = update_mds_cfg(&node_cfg, entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "update mds[%u] fail.", mds_id);
	}
	
	if (!entity->node) {
		ret = create_node(entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "create_mds_node mds id[%u] fail.", mds_id);
	}

	entity->_ref++;

	cafs_rwlock_unlock(&ctx->rwlock);

	return entity->node;

unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return NULL;
}

static const struct mds_node_obj *get_mds_node_by_vmds(struct mds_obj *obj, uint32_t vmds_id)
{
	int ret;
	struct _mds_node *entity;
	khiter_t iter = 0; //iter
	uint32_t mds_id = 0;
	struct vnode_cfg node_cfg;
	MDS_CTX(ctx, obj, NULL);

	LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->cfg, NULL, "ctx->cfg is null");

	ret = ctx->cfg->ops->get_mds_on_vmds(ctx->cfg, vmds_id, &node_cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "get mds with id[%u] fail", mds_id);

	ret = cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "cafs_rwlock_rdlock fail.");

	mds_id = node_cfg.id;

	iter = kh_get(h_mds_node, ctx->map, mds_id);
	if(iter == kh_end(ctx->map)){
		// 新建节点
		cafs_rwlock_unlock(&ctx->rwlock);
		entity = insert_mds_node(&node_cfg, ctx->map);
		LOG_THEN_RETURN_VAL_IF_TRUE(!entity, NULL, "insert new mds[%u] node fail.", mds_id);
		cafs_rwlock_rdlock(&ctx->rwlock); //重新加锁
	}else{
		entity = kh_val(ctx->map, iter);
		ret = update_mds_cfg(&node_cfg, entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "update mds[%u] fail.", mds_id);
	}
	
	if (!entity->node) {
		ret = create_node(entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "create_mds_node mds id[%u] fail.", mds_id);
	}

	entity->_ref++;

	cafs_rwlock_unlock(&ctx->rwlock);

	return entity->node;

unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return NULL;
	
}
static int put_mds_node(struct mds_obj *obj, const struct mds_node_obj *node)
{
	int ret;
	struct _mds_node *entity;
	khiter_t iter = 0; //iter
	uint32_t mds_id;

	MDS_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!node, CAFS_ERR, "node is null");

	ret = cafs_rwlock_rdlock(&ctx->rwlock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_rdlock fail.");

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->map, unlock, "ctx->map is null");

	iter = kh_get(h_mds_node, ctx->map, node->id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(iter == kh_end(ctx->map), unlock, "can't find mds id[%u] on map.", node->id);

	entity = kh_val(ctx->map, iter);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!entity, unlock, "can't find mds id[%u] node obj on map.", node->id);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(entity->_ref <= 0, unlock, "not need put again.");

	entity->_ref--;
	if (entity->_ref <= 0) {
		/*ret = destroy_node(entity);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, unlock, "destroy_node mds id[%u] fail.", node->id);
		entity->node = NULL;*/
		//CAFS_LOG_NOTICE("the mds[%u] is free, entity->_ref[%d].", node->id, entity->_ref);
	}
	
	cafs_rwlock_unlock(&ctx->rwlock);

	return 0;

unlock:
	cafs_rwlock_unlock(&ctx->rwlock);
	return CAFS_ERR;
}