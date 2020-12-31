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
#include "cafs_config.h"
#include "cafs_tree.h"

#include "khash.h"
#include "iniparser.h"

#include "etcd-client.hpp"

#define CFG_CTX(ctx_name, obj, ret)\
struct cfg_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct cfg_ctx *)obj->cfg_ctx;

#define MAX_MSG_BUFF_LEN  512

static const char *G_ETCD_PRT_KEY = "/dfs/prt";
static const char *G_ETCD_PRT_PATH = "path";
static const char *G_ETCD_PRT_POLICY = "dir_stripe_policy";
static const char *G_ETCD_PRT_NUM = "target_num";
static const char *G_ETCD_PRT_NODE = "targets";
static const char *G_ETCD_PRT_VMDS_ID = "vmds_id";
static const char *G_ETCD_PRT_SUBTREE_ID = "subtree_id";

static const char *G_ETCD_MDS_KEY = "/dfs/config/mds/";
static const char *G_ETCD_MDS_VMDS_NUM = "vmds_nums";
static const char *G_ETCD_MDS_VMDS_ARR = "vmds_ids";

static const char *G_ETCD_PFILE_KEY = "/dfs/config/pfile/";

static const char *G_ETCD_VNODE_URI = "uri";
static const char *G_ETCD_VNODE_CONN_NUM = "conn_num";
static const char *G_ETCD_VNODE_DATA_LEN = "data_max_len";
static const char *G_ETCD_VNODE_HEAD_LEN = "head_max_len";
static const char *G_ETCD_VNODE_IOV_LEN  = "iov_max_len";


uint64_t  msg_data_max_len;
    uint32_t  msg_head_max_len;
    uint32_t  msg_iov_max_len;

struct cfg_node_msg{
	uint32_t node_num;
	struct vnode_cfg *node;
};

// pfile_node
struct pfile_node_cfg {
    struct vnode_cfg node;
};

// mds_node
struct mds_node_cfg {
	uint32_t  vmds_num;
	uint32_t *vmds;
	struct vnode_cfg node;
};

enum vmds_policy{
	VMDS_POLICY_E_MAP = 0,
};

// vmds_node
struct vmds_node_cfg {
	uint32_t  vmds_id;
    uint32_t subtree_id;
};

// prt_node
struct prt_node_cfg {
	uint32_t  key;
	enum vmds_policy policy;
	char *path;
	uint32_t  vmds_num;
	union{
		struct vmds_node_cfg vmds;   // vmds等于一个时
		struct vmds_node_cfg *pvmds; // 大于一个，需要申请资源
	};
};

KHASH_MAP_INIT_INT64(h_prt, struct prt_node_cfg *);
KHASH_MAP_INIT_INT64(h_vmds, uint32_t);
KHASH_MAP_INIT_INT64(h_mds, struct mds_node_cfg *);
KHASH_MAP_INIT_INT64(h_pfile, struct pfile_node_cfg *);

struct cfg_ctx{
	uint32_t fs_id;
    int32_t     _ref;      // ref count.
	char 	*cfg_path;
	struct etcd_client_obj *etcd;
	struct prt_tree_node *fstree;
	struct cafs_rwlock prt_lock;
	khash_t(h_prt)   *prt;
	struct cafs_rwlock vmds_lock;
	khash_t(h_vmds)  *vmds;
	struct cafs_rwlock mds_lock;
	khash_t(h_mds)   *mds;
	struct cafs_rwlock pfile_lock;
	khash_t(h_pfile) *pfile;
};

static int load_base_cfg(dictionary *ini_fd, struct cafs_cfg_obj *base);
static int load_prt_cfg(dictionary *ini_fd, struct cfg_ctx *ctx);
static int load_mds_cfg(dictionary *ini_fd, struct cfg_ctx *ctx);
static int load_pfile_cfg(dictionary *ini_fd, struct cfg_ctx *ctx);
static int load_vmds_cfg(dictionary *ini_fd, struct cfg_ctx *ctx);

static inline void destroy_prt_node(struct prt_node_cfg *node);
static inline void destroy_mds_node(struct mds_node_cfg *node);
static inline void destroy_pfile_node(struct pfile_node_cfg *node);

static inline int load_etcd_prt(struct etcd_client_obj *etcd, struct cfg_ctx *ctx);
static inline int load_etcd_mds(struct etcd_client_obj *etcd, struct cfg_ctx *ctx);
static inline int load_etcd_pfile(struct etcd_client_obj *etcd, struct cfg_ctx *ctx);

static int load_cfg_with_etcd(struct etcd_client_obj *etcd, struct cafs_cfg_obj *obj);
static int load_cfg_with_ini(dictionary *ini_fd, struct cafs_cfg_obj *obj);

static int get_prt(const struct cafs_cfg_obj *cfg, const char *path, struct cafs_prt_cfg *prt);
static int get_mds_on_vmds(const struct cafs_cfg_obj *obj, uint32_t vmds_id, struct vnode_cfg *mds);

static int get_mds(const struct cafs_cfg_obj *obj, const char *path, struct vnode_cfg *mds);
static int get_pfile(const struct cafs_cfg_obj *obj, const uint32_t pfile_id, struct vnode_cfg *pfile);

static struct cafs_cfg_ops cfg_ops = {
	.get_prt = &get_prt,
	.get_mds_on_vmds = &get_mds_on_vmds,
	.get_mds = &get_mds,
	.get_pfile = &get_pfile,
};

struct cafs_cfg_obj *create_cfg_obj(const char *cfg_path)
{
    struct cafs_cfg_obj *obj = NULL;
	int ret;
	struct cfg_ctx *ctx;
    uint32_t path_len;
	struct etcd_client_param etcd_param = {0};
	dictionary *ini_fd = NULL;

	LOG_THEN_RETURN_VAL_IF_TRUE(!cfg_path, NULL, "the file_path of this dentry is null");

	ret = is_file_not_existed(cfg_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "config file[%s] is not existed.", cfg_path);

	ini_fd = iniparser_load(cfg_path);
	LOG_THEN_RETURN_VAL_IF_TRUE(!ini_fd, NULL, "iniparser_load file[%s] fail.", cfg_path);

	obj = (struct cafs_cfg_obj *)CAFS_ALLOC(sizeof(struct cafs_cfg_obj) + sizeof(struct cfg_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC cafs_dentry fail.");
	memset(obj, 0, sizeof(struct cafs_cfg_obj) + sizeof(struct cfg_ctx));

	obj->ops = &cfg_ops;

	ctx = (struct cfg_ctx *)obj->cfg_ctx;
	ctx->_ref = 0;

	ret = cafs_rwlock_init(&ctx->prt_lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_rwlock_init fail.");
	ctx->prt = kh_init(h_prt);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->prt, free_obj, "kh_init fail.");

	ret = cafs_rwlock_init(&ctx->vmds_lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_rwlock_init fail.");
	ctx->vmds = kh_init(h_vmds);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->vmds, free_obj, "kh_init fail.");

	ret = cafs_rwlock_init(&ctx->mds_lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_rwlock_init fail.");
	ctx->mds = kh_init(h_mds);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->mds, free_obj, "kh_init fail.");

	ret = cafs_rwlock_init(&ctx->pfile_lock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_rwlock_init fail.");
	ctx->pfile = kh_init(h_pfile);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->pfile, free_obj, "kh_init fail.");

	ret = load_base_cfg(ini_fd, obj);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "load_base_cfg parameter fail.");

	ret = load_cfg_with_ini(ini_fd, obj);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "load cfg with ini[%s] fail.", cfg_path);

	//etcd-client加载
	etcd_param.uri = iniparser_getstring(ini_fd, "cfgm:uri", "http://127.0.0.1:2379");
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!etcd_param.uri, free_obj, "load_base_cfg parameter fail.");
	ctx->etcd = create_etcd_client(&etcd_param);
	if (ctx->etcd) {
		ret = load_cfg_with_etcd(ctx->etcd, obj);
		if (ret) {
			CAFS_LOG_ERROR("etcd load fail, maybe not in server!!!");
		}else{
			CAFS_LOG_NOTICE("etcd load success!!!");
		}
	}else{
		CAFS_LOG_ERROR("etcd don't in server");
	}

	path_len = strlen(cfg_path);
	ctx->cfg_path = CAFS_ALLOC(path_len + 2, NULL);
	memcpy(ctx->cfg_path, cfg_path, path_len);

	if (ini_fd) {
    	iniparser_freedict(ini_fd);
  	}
	
	return obj;

free_obj:
	if (ctx->etcd) {
		destroy_etcd_client(ctx->etcd);
		ctx->etcd = NULL;
	}
	if (ini_fd) {
    	iniparser_freedict(ini_fd);
  	}
	cafs_rwlock_destroy(&ctx->prt_lock);
	cafs_rwlock_destroy(&ctx->mds_lock);
	cafs_rwlock_destroy(&ctx->vmds_lock);
	cafs_rwlock_destroy(&ctx->pfile_lock);
	SAFE_CAFS_FREE(obj);

	return NULL;
}

int destroy_cfg_obj(struct cafs_cfg_obj *cfg)
{
    int ret;
	struct prt_node_cfg *prt_node;
	struct mds_node_cfg *mds_node;
	struct pfile_node_cfg *pfile_node;
    CFG_CTX(ctx, cfg, CAFS_ERR);

	if (ctx->etcd) {
		destroy_etcd_client(ctx->etcd);
		ctx->etcd = NULL;
	}

	cafs_rwlock_wrlock(&ctx->prt_lock);
	if (ctx->prt){
		kh_foreach_value(ctx->prt, prt_node, destroy_prt_node(prt_node));
		kh_clear(h_prt, ctx->prt);
		kh_destroy(h_prt, ctx->prt);
		ctx->prt = NULL;
	}
	cafs_rwlock_unlock(&ctx->prt_lock);
	cafs_rwlock_destroy(&ctx->prt_lock);

	cafs_rwlock_wrlock(&ctx->mds_lock);
	if (ctx->mds){
		kh_foreach_value(ctx->mds, mds_node, destroy_mds_node(mds_node));
		kh_clear(h_mds, ctx->mds);
		kh_destroy(h_mds, ctx->mds);
		ctx->mds = NULL;
	}
	cafs_rwlock_unlock(&ctx->mds_lock);
	cafs_rwlock_destroy(&ctx->mds_lock);

	cafs_rwlock_wrlock(&ctx->pfile_lock);
	if (ctx->pfile){
		kh_foreach_value(ctx->pfile, pfile_node, destroy_pfile_node(pfile_node));
		kh_clear(h_pfile, ctx->pfile);
		kh_destroy(h_pfile, ctx->pfile);
		ctx->pfile = NULL;
	}
	cafs_rwlock_unlock(&ctx->pfile_lock);
	cafs_rwlock_destroy(&ctx->pfile_lock);

	cafs_rwlock_wrlock(&ctx->vmds_lock);
	if (ctx->vmds){
		kh_clear(h_vmds, ctx->vmds);
		kh_destroy(h_vmds, ctx->vmds);
		ctx->vmds = NULL;
	}
	cafs_rwlock_unlock(&ctx->vmds_lock);
	cafs_rwlock_destroy(&ctx->vmds_lock);

	SAFE_CAFS_FREE(ctx->cfg_path);
	SAFE_CAFS_FREE(cfg);
    return 0;
}
static inline const struct vmds_node_cfg *get_vmds_with_policy(const struct prt_node_cfg *prt)
{
	return (prt->vmds_num > 1) ?&(prt->pvmds[0]):&(prt->vmds);
}

static int get_prt(const struct cafs_cfg_obj *obj, const char *path, struct cafs_prt_cfg *prt)
{
	int ret;
	khiter_t iter = 0; //iter
	const struct prt_tree_node *prt_node;
	const struct prt_node_cfg *prt_cfs_node;
	const struct vmds_node_cfg *vmds_cfg;
	CFG_CTX(ctx, obj, CAFS_ERR);

	LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path is null.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!prt, CAFS_ERR, "prt is null.");

	ret = cafs_rwlock_rdlock(&ctx->prt_lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	prt_node = prt_search(ctx->fstree, path);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!prt, unlock, "prt_search path[%s] fail.", path);

	iter = kh_get(h_prt, ctx->prt, prt_node->node_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(iter == kh_end(ctx->prt), unlock, "can't find prt id[%lu].", prt_node->node_id);
	
	prt_cfs_node = kh_val(ctx->prt, iter);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!prt_cfs_node, unlock, "prt_cfs_node is null.");

	prt->prt_id = prt_cfs_node->key;
	vmds_cfg = get_vmds_with_policy(prt_cfs_node);//根据策略选择vmds
	prt->subtree_id = vmds_cfg->subtree_id;
	prt->vmds_id = vmds_cfg->vmds_id;

	cafs_rwlock_unlock(&ctx->prt_lock);
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->prt_lock);
	return CAFS_ERR;
}

static int get_mds_on_vmds(const struct cafs_cfg_obj *obj, uint32_t vmds_id, struct vnode_cfg *mds)
{
	int ret;
	uint32_t mds_id;
	khiter_t iter = 0; //iter
	struct mds_node_cfg *mds_node;
	CFG_CTX(ctx, obj, CAFS_ERR);

	ret = cafs_rwlock_rdlock(&ctx->mds_lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	iter = kh_get(h_vmds, ctx->vmds, vmds_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(iter == kh_end(ctx->vmds), unlock, "can't find vmds id[%u].", vmds_id);

	mds_id = kh_val(ctx->vmds, iter);

	iter = kh_get(h_mds, ctx->mds, mds_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(iter == kh_end(ctx->mds), unlock, "can't find mds id[%u].", mds_id);

	mds_node = kh_val(ctx->mds, iter);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!mds, unlock, "mds node[%u] is null.", mds_id);

	*mds = mds_node->node;
	cafs_rwlock_unlock(&ctx->mds_lock);
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->mds_lock);
	return CAFS_ERR;
}

// 已加锁
static int get_mds(const struct cafs_cfg_obj *obj, const char *path, struct vnode_cfg *mds)
{
	int ret;
	struct cafs_prt_cfg prt_cfg = {0};

	ret = get_prt(obj, path, &prt_cfg);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "get prt by path[%s].", path);

	ret = get_mds_on_vmds(obj, prt_cfg.vmds_id, mds);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "can't find mds by path[%s] on vmds id[%u].", path, prt_cfg.vmds_id);
	
	return 0;
}

static int get_pfile(const struct cafs_cfg_obj *obj, const uint32_t pfile_id, struct vnode_cfg *pfile)
{
	int ret;
	khiter_t iter = 0; //iter
	struct pfile_node_cfg *pfile_node;
	CFG_CTX(ctx, obj, CAFS_ERR);

	ret = cafs_rwlock_rdlock(&ctx->pfile_lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	iter = kh_get(h_pfile, ctx->pfile, pfile_id);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(iter == kh_end(ctx->pfile), unlock, "can't find pfile by id[%u].", pfile_id);

	pfile_node = kh_val(ctx->pfile, iter);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pfile_node, unlock, "pfile node[%u] is null.", pfile_id);

	*pfile = pfile_node->node;
	cafs_rwlock_unlock(&ctx->pfile_lock);
	return 0;
unlock:
	cafs_rwlock_unlock(&ctx->pfile_lock);
	return CAFS_ERR;
}


static int load_cfg_with_ini(dictionary *ini_fd, struct cafs_cfg_obj *obj)
{
	int ret;
	CFG_CTX(ctx, obj, CAFS_ERR);

	ret = load_prt_cfg(ini_fd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_prt_cfg fail.");

	ret = load_mds_cfg(ini_fd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_mds_cfg fail.");

	ret = load_pfile_cfg(ini_fd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_pfile_cfg fail.");

	ret = load_vmds_cfg(ini_fd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_vmds_cfg fail.");

	return 0;
}

static int watch_prt(const char *msg, void *usr_ctx)
{
	int ret;
	struct cfg_ctx *ctx = (struct cfg_ctx *)usr_ctx;

	ret = load_etcd_prt(ctx->etcd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_etcd_prt fail.");
	return 0;
}

static int watch_mds(const char *msg, void *usr_ctx)
{
	int ret;
	struct cfg_ctx *ctx = (struct cfg_ctx *)usr_ctx;
	ret = load_etcd_mds(ctx->etcd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_etcd_prt fail.");
	return 0;
}

static int watch_pfile(const char *msg, void *usr_ctx)
{
	int ret;
	struct cfg_ctx *ctx = (struct cfg_ctx *)usr_ctx;
	ret = load_etcd_pfile(ctx->etcd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_etcd_prt fail.");
	return 0;
}

// etcd
static int load_cfg_with_etcd(struct etcd_client_obj *etcd, struct cafs_cfg_obj *obj)
{
	int ret;
	char prt_key[128] = {0};
	CFG_CTX(ctx, obj, CAFS_ERR);

	ret = load_etcd_prt(etcd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_etcd_prt fail.");

	ret = load_etcd_mds(etcd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_etcd_mds fail.");

	ret = load_etcd_pfile(etcd, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "load_etcd_pfile fail.");

	snprintf(prt_key, MAX_MSG_BUFF_LEN, "%s/%u", G_ETCD_PRT_KEY, ctx->fs_id);
	ret = etcd_watch(etcd, prt_key, watch_prt, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "etcd_watch  prt fail.");

	ret = etcd_watch(etcd, G_ETCD_MDS_KEY, watch_mds, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "etcd_watch mds fail.");

	ret = etcd_watch(etcd, G_ETCD_PFILE_KEY, watch_pfile, ctx);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "etcd_watch pfile fail.");

	return 0;
}

static inline struct prt_node_cfg *create_prt_node(uint32_t key, const char *json)
{
	int ret;
	uint32_t i;
	struct prt_node_cfg *node =NULL;
	struct json_obj json_obj = {0};
	struct vmds_node_cfg *pvmds =NULL;
	char strbuff[MAX_MSG_BUFF_LEN] = {0};

	ret = json_parse(json, &json_obj);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "json_parse <%s> fail.", json);

	ret = json_getstring(&json_obj, G_ETCD_PRT_PATH, strbuff, sizeof(strbuff));
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "json_getstring <path> fail.");

	node = CAFS_ALLOC(sizeof(struct prt_node_cfg), NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!node, free_node, "CAFS_ALLOC node fail.");
	memset(node, 0, sizeof(struct prt_node_cfg));

	node->key = key;
	node->path = strdup(strbuff);

	ret = json_getuint(&json_obj, G_ETCD_PRT_NUM, &node->vmds_num);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "json_getstring <path> fail.");

	CAFS_LOG_DEBUG("node [ path:%s, target_num:%u ]", node->path, node->vmds_num);

	if(node->vmds_num > 1){
		node->pvmds = pvmds = CAFS_ALLOC(node->vmds_num * sizeof(struct vmds_node_cfg), NULL);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pvmds, free_node, "CAFS_ALLOC <vmds_node_cfg> fail.");
	}else{
		pvmds = &(node->vmds);
	}
	for (i = 0; i < node->vmds_num; i++) {
		snprintf(strbuff, sizeof(strbuff), "%s|%u|%s",G_ETCD_PRT_NODE, i, G_ETCD_PRT_VMDS_ID);
		ret = json_getuint(&json_obj, strbuff, &pvmds[i].vmds_id);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "get <%s> fail.", strbuff);
		CAFS_LOG_DEBUG("vmds_id [ %u ]", pvmds[i].vmds_id);
		
		snprintf(strbuff, sizeof(strbuff), "%s|%u|%s", G_ETCD_PRT_NODE, i, G_ETCD_PRT_SUBTREE_ID);
		ret = json_getuint(&json_obj, strbuff, &pvmds[i].subtree_id);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "get <%s> fail.", strbuff);
		CAFS_LOG_DEBUG("subtree_id [ %u ]", pvmds[i].subtree_id);
	}
	free_json_obj(&json_obj);

	return node;

free_node:
	free_json_obj(&json_obj);
	if(node){
		if (node->vmds_num > 1) {
			SAFE_CAFS_FREE(node->pvmds);
		}
		free(node->path);
		SAFE_CAFS_FREE(node);
	}
	return NULL;
}

static inline void destroy_prt_node(struct prt_node_cfg *node)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!node, ;, "node is null.");
	if (node->vmds_num > 1) {
		SAFE_CAFS_FREE(node->pvmds);
	}
	free(node->path);
	SAFE_CAFS_FREE(node);
	return;
}

static inline int get_elem_id(const char *elem, uint32_t *id)
{
	int i= 0;
	int len = strlen(elem);
	for (i = len; i > 0; i--) {
		if(*(elem + i - 1) == '/'){
			*id = atol(elem + i);
			return 0;
		}
	}
	return -1;
}

static inline int insert_prt_node(struct prt_node_cfg *node, khash_t(h_prt) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_prt, map, node->key);
	if (iter == kh_end(map)) {
		iter = kh_put(h_prt, map, node->key, &ret);
		if ( ret < 0){
			CAFS_LOG_ERROR("kh_put node id [%u] fail.", node->key);
			return CAFS_ERR;
		}
	}else{
		CAFS_LOG_NOTICE("node id [%u] exitsed, reaplace it.", node->key);
		destroy_prt_node(kh_val(map, iter));
	}
	kh_val(map, iter) = node;
	return 0;
}

static inline void remove_prt_node(struct prt_node_cfg *node, khash_t(h_prt) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_prt, map, node->key);
	if (iter != kh_end(map)) {
		kh_val(map, iter) = NULL;
		kh_del(h_prt, map, node->key);
	}
	return;
}

static inline int load_etcd_prt(struct etcd_client_obj *etcd, struct cfg_ctx *ctx)
{
	int ret = 0;
	size_t i;
	const char *elem;
	uint32_t prt_id = 0;
	char strbuff[MAX_MSG_BUFF_LEN] = {0};
	struct etcd_vector vector = {0};
	struct prt_node_cfg *prt_node;

	snprintf(strbuff, MAX_MSG_BUFF_LEN, "%s/%u", G_ETCD_PRT_KEY, ctx->fs_id);
	ret = etcd_list(etcd, strbuff, &vector);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "etcd ls fail.");
	
	ret = cafs_rwlock_wrlock(&ctx->prt_lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	CAFS_LOG_NOTICE("get vector size:%lu.", vector.size);

	for(i = 0; i < vector.size; i++){
		elem = get_element(&vector, i);

		CAFS_LOG_NOTICE("get element:%s.", elem);

		ret = get_elem_id(elem, &prt_id);
		if(ret){
			CAFS_LOG_ERROR("get prt id with [%s] fail", elem);
			continue;
		}

		CAFS_LOG_NOTICE("get prt_id:%u.", prt_id);

		ret = etcd_request(etcd,  elem, strbuff, sizeof(strbuff));
		if(ret){
			CAFS_LOG_ERROR("etcd_request with key [%s] fail", elem);
			continue;
		}

		prt_node = create_prt_node(prt_id, strbuff);
		if(!prt_node){
			CAFS_LOG_ERROR("create_prt_node with json [%s] fail", strbuff);
			continue;
		}

		ret = insert_prt_node(prt_node, ctx->prt);
		if(ret){
			CAFS_LOG_ERROR("insert prt_node to map [%p] fail", ctx->prt);
			destroy_prt_node(prt_node);
			continue;
		}

		if(!ctx->fstree){
			ctx->fstree = prt_create_tree(0);//添加根目录
			if(!ctx->fstree){
				CAFS_LOG_ERROR("create root[0] tree fail");
				remove_prt_node(prt_node, ctx->prt);
				destroy_prt_node(prt_node);
				ret = CAFS_ERR;
				break;
			}
		}
		if(!prt_insert(prt_node->path, prt_node->key, ctx->fstree)){
			CAFS_LOG_ERROR("insert node to tree [%p] fail", ctx->prt);
			remove_prt_node(prt_node, ctx->prt);
			destroy_prt_node(prt_node);
		}
	}
	free_vector(&vector);
	cafs_rwlock_unlock(&ctx->prt_lock);
	return ret;
}

static inline int get_vnode_on_etcd(const struct json_obj *obj, struct vnode_cfg *vnode)
{
	int ret;
	uint32_t tmp = 0;
	char port[32] = {0};
	char strbuff[MAX_MSG_BUFF_LEN] = {0};

	ret = json_getstring(obj, G_ETCD_VNODE_URI, strbuff, sizeof(strbuff));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "json_getstring <path> fail.");

	CAFS_LOG_NOTICE("uri [%s]", strbuff);

	ret = cafs_uri_get_resource(strbuff, vnode->addr, 16);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_uri_get_resource fail.");

	ret = cafs_uri_get_portal(strbuff, port, sizeof(port));
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_uri_get_portal fail.");

	vnode->port = atol(port);
	vnode->uri = strdup(strbuff);

	ret = json_getuint(obj, G_ETCD_VNODE_CONN_NUM, &tmp);
	if(ret) {
		vnode->connection = 2;
	}else{
		vnode->connection = tmp;
	}

	ret = json_getuint64(obj, G_ETCD_VNODE_DATA_LEN, &vnode->msg_data_max_len);
	if(ret) {
		vnode->msg_data_max_len = 16384;
	}

	ret = json_getuint(obj, G_ETCD_VNODE_HEAD_LEN, &vnode->msg_head_max_len);
	if(ret) {
		vnode->msg_head_max_len = 1024;
	}

	ret = json_getuint(obj, G_ETCD_VNODE_IOV_LEN, &vnode->msg_iov_max_len);
	if(ret) {
		vnode->msg_iov_max_len = 4096;
	}

	return 0;
}

static inline void put_vnode_on_etcd(struct vnode_cfg *vnode)
{
	if (vnode->uri) {
		free(vnode->uri);
	}
	return;
}


static inline struct mds_node_cfg *create_mds_node(uint32_t key, const char *json)
{
	int ret;
	uint32_t i;
	struct mds_node_cfg *node =NULL;
	struct json_obj json_obj = {0};
	char strbuff[MAX_MSG_BUFF_LEN] = {0};

	ret = json_parse(json, &json_obj);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "json_parse <%s> fail.", json);

	node = CAFS_ALLOC(sizeof(struct mds_node_cfg), NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!node, free_node, "CAFS_ALLOC node fail.");
	memset(node, 0, sizeof(struct mds_node_cfg));

	ret = get_vnode_on_etcd(&json_obj, &node->node);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "get_mds_node fail.");

	node->node.id = key;

	ret = json_getuint(&json_obj, G_ETCD_MDS_VMDS_NUM, &node->vmds_num);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "json_getuint vmds_num fail.");

	CAFS_LOG_NOTICE("node [vmds_num:%u ]", node->vmds_num);

	if(node->vmds_num){
		node->vmds = CAFS_ALLOC(node->vmds_num * sizeof(uint32_t), NULL);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!node->vmds, free_node, "CAFS_ALLOC <vmds_node_cfg> fail.");
	}
	for (i = 0; i < node->vmds_num; i++) {
		snprintf(strbuff, sizeof(strbuff), "%s|%u", G_ETCD_MDS_VMDS_ARR, i);
		ret = json_getuint(&json_obj, strbuff, &node->vmds[i]);
		LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "get <%s> fail.", strbuff);
		CAFS_LOG_NOTICE("vmds_id [ %u ]", node->vmds[i]);
	}
	
	free_json_obj(&json_obj);

	return node;

free_node:
	free_json_obj(&json_obj);
	if(node){
		SAFE_CAFS_FREE(node->vmds);
		put_vnode_on_etcd(&node->node);
	}
	SAFE_CAFS_FREE(node);
	return NULL;
}

static inline void destroy_mds_node(struct mds_node_cfg *node)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!node, ;, "node is null.");
	SAFE_CAFS_FREE(node->vmds);
	put_vnode_on_etcd(&node->node);
	SAFE_CAFS_FREE(node);
	return;
}

static inline int insert_vmds_node(uint32_t vmds_id, uint32_t mds_id, khash_t(h_vmds) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_vmds, map, vmds_id);
	if (iter == kh_end(map)) {
		iter = kh_put(h_vmds, map, vmds_id, &ret);
		if ( ret < 0){
			CAFS_LOG_ERROR("kh_put node id [%u] fail.", vmds_id);
			return CAFS_ERR;
		}
	}else{
		CAFS_LOG_NOTICE("node id [%u] exitsed, reaplace it.", vmds_id);
	}
	kh_val(map, iter) = mds_id;
	return 0;
}

static inline void remove_vmds_node(uint32_t vmds_id, khash_t(h_vmds) *map)
{
	khiter_t iter = 0; //iter
	iter = kh_get(h_vmds, map, vmds_id);
	if (iter != kh_end(map)) {
		kh_del(h_vmds, map, vmds_id);
	}
	return;
}

static inline int insert_mds_node(struct mds_node_cfg *node, khash_t(h_mds) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_mds, map, node->node.id);
	if (iter == kh_end(map)) {
		iter = kh_put(h_mds, map, node->node.id, &ret);
		if ( ret < 0){
			CAFS_LOG_ERROR("kh_put node id [%u] fail.", node->node.id);
			return CAFS_ERR;
		}
	}else{
		CAFS_LOG_NOTICE("node id [%u] exitsed, reaplace it.", node->node.id);
		destroy_mds_node(kh_val(map, iter));
	}
	kh_val(map, iter) = node;
	return 0;
}

static inline void remove_mds_node(struct mds_node_cfg *node, khash_t(h_mds) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_mds, map, node->node.id);
	if (iter != kh_end(map)) {
		kh_val(map, iter) = NULL;
		kh_del(h_mds, map, node->node.id);
	}

	return;
}

static inline int build_mds_node(struct mds_node_cfg *node, struct cfg_ctx *ctx)
{
	int ret;
	uint32_t i;

	ret = insert_mds_node(node, ctx->mds);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "insert_mds_node mds[%u] fail.", node->node.id);
	for (i = 0; i < node->vmds_num; i++) {
		ret = insert_vmds_node(node->vmds[i], node->node.id, ctx->vmds);
		LOG_ERROR_IF_VAL_TRUE(ret, "insert_vmds_node [%u] fail.", node->vmds[i]);
	}
	return 0;
}


static inline int load_etcd_mds(struct etcd_client_obj *etcd, struct cfg_ctx *ctx)
{
	int ret = 0;
	size_t i;
	const char *elem;
	uint32_t mds_id = 0;
	char strbuff[MAX_MSG_BUFF_LEN] = {0};
	struct etcd_vector vector = {0};
	struct mds_node_cfg *mds;

	ret = etcd_list(etcd, G_ETCD_MDS_KEY, &vector);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "etcd ls fail.");

	ret = cafs_rwlock_wrlock(&ctx->mds_lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	for(i = 0; i < vector.size; i++){
		elem = get_element(&vector, i);
		CAFS_LOG_NOTICE("get elem keys[%s]", elem);

		ret = get_elem_id(elem, &mds_id);
		if(ret){
			CAFS_LOG_ERROR("get mds id with [%s] fail", elem);
			continue;
		}

		ret = etcd_request(etcd,  elem, strbuff, sizeof(strbuff));
		if(ret){
			CAFS_LOG_ERROR("etcd_request with key [%s] fail", elem);
			continue;
		}

		mds = create_mds_node(mds_id, strbuff);
		if(!mds){
			CAFS_LOG_ERROR("create_mds_node with id [%u] fail", mds_id);
			continue;
		}

		ret = build_mds_node(mds, ctx);
		if(ret){
			CAFS_LOG_ERROR("build_mds_node with id [%u] fail", mds_id);
			destroy_mds_node(mds);
			continue;
		}
	}
	free_vector(&vector);
	cafs_rwlock_unlock(&ctx->mds_lock);
	return 0;
}

static inline struct pfile_node_cfg *create_pfile_node(uint32_t key, const char *json)
{
	int ret;
	struct pfile_node_cfg *node =NULL;
	struct json_obj json_obj = {0};

	ret = json_parse(json, &json_obj);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, "json_parse <%s> fail.", json);

	node = CAFS_ALLOC(sizeof(struct pfile_node_cfg), NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!node, free_node, "CAFS_ALLOC node fail.");
	memset(node, 0, sizeof(struct pfile_node_cfg));
	node->node.id = key;

	ret = get_vnode_on_etcd(&json_obj, &node->node);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_node, "get_mds_node fail.");

	free_json_obj(&json_obj);

	return node;

free_node:
	free_json_obj(&json_obj);
	if(node){
		put_vnode_on_etcd(&node->node);
	}
	SAFE_CAFS_FREE(node);
	return NULL;
}

static inline void destroy_pfile_node(struct pfile_node_cfg *node)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!node, ;, "node is null.");
	put_vnode_on_etcd(&node->node);
	SAFE_CAFS_FREE(node);
	return;
}

static inline int insert_pfile_node(struct pfile_node_cfg *node, khash_t(h_pfile) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_pfile, map, node->node.id);
	if (iter == kh_end(map)) {
		iter = kh_put(h_pfile, map, node->node.id, &ret);
		if ( ret < 0){
			CAFS_LOG_ERROR("kh_put node id [%u] fail.", node->node.id);
			return CAFS_ERR;
		}
	}else{
		CAFS_LOG_NOTICE("node id [%u] exitsed, reaplace it.", node->node.id);
		destroy_pfile_node(kh_val(map, iter));
	}
	kh_val(map, iter) = node;
	return 0;
}

static inline void remove_pfile_node(struct pfile_node_cfg *node, khash_t(h_pfile) *map)
{
	int ret;
	khiter_t iter = 0; //iter

	iter = kh_get(h_pfile, map, node->node.id);
	if (iter != kh_end(map)) {
		kh_val(map, iter) = NULL;
		kh_del(h_pfile, map, node->node.id);
	}

	return;
}

static inline int load_etcd_pfile(struct etcd_client_obj *etcd, struct cfg_ctx *ctx)
{
	int ret = 0;
	size_t i;
	const char *elem;
	uint32_t pfile_id = 0;
	char strbuff[MAX_MSG_BUFF_LEN] = {0};
	struct etcd_vector vector = {0};
	struct pfile_node_cfg *pfile;

	ret = etcd_list(etcd, G_ETCD_PFILE_KEY, &vector);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "etcd ls fail.");

	ret = cafs_rwlock_wrlock(&ctx->pfile_lock);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "cafs_rwlock_wrlock fail.");

	for(i = 0; i < vector.size; i++){
		elem = get_element(&vector, i);
		CAFS_LOG_NOTICE("get elem keys[%s]", elem);

		ret = get_elem_id(elem, &pfile_id);
		if(ret){
			CAFS_LOG_ERROR("get mds id with [%s] fail", elem);
			continue;
		}

		ret = etcd_request(etcd,  elem, strbuff, sizeof(strbuff));
		if(ret){
			CAFS_LOG_ERROR("etcd_request with key [%s] fail", elem);
			continue;
		}

		pfile = create_pfile_node(pfile_id, strbuff);
		if(!pfile){
			CAFS_LOG_ERROR("create_mds_node with id [%u] fail", pfile_id);
			continue;
		}

		ret = insert_pfile_node(pfile, ctx->pfile);
		if(ret){
			CAFS_LOG_ERROR("insert_pfile_node with id [%u] fail", pfile_id);
			destroy_pfile_node(pfile);
			continue;
		}
	}
	free_vector(&vector);
	cafs_rwlock_unlock(&ctx->pfile_lock);
	return 0;
}

static int load_base_cfg(dictionary *ini_fd, struct cafs_cfg_obj *base)
{

	LOG_THEN_RETURN_VAL_IF_TRUE(!ini_fd, 0, "ini_fd is null");
	LOG_THEN_RETURN_VAL_IF_TRUE(!base, 0, " pointer base is null");

	base->thread_num = iniparser_getint(ini_fd, "base:thread_max_num", DEFAULT_THREAD_MAX_NUM);
	LOG_THEN_RETURN_VAL_IF_TRUE(!base->thread_num, -1, " thread_num is 0");

	base->usr_id = iniparser_getint(ini_fd, "base:uuid", 10086);
	LOG_THEN_RETURN_VAL_IF_TRUE(!base->thread_num, -1, " usr_id is 0");

	CAFS_LOG_DEBUG("get thread_num is :%u", base->thread_num);
	
	return 0;
}


/*!
 *  @brief  加载本地静态参数到内存
 *
 *  @param[in]  config_file  配置文件
 *  @param[out] cfg  配置参数
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
static int load_pfile_cfg(dictionary *ini_fd, struct cfg_ctx *ctx)
{
	const char *ipaddr =NULL;
	char  tag[256] = {0};
	uint32_t   i;
	int ret;
	uint32_t node_num = 0;
	struct pfile_node_cfg *pnode;
	struct vnode_cfg *pvnode;
	LOG_THEN_RETURN_VAL_IF_TRUE(!ini_fd, 0, " ini_fd is null");

	node_num = iniparser_getint(ini_fd, "base:pfile_num", 0);
	LOG_THEN_RETURN_VAL_IF_TRUE(!node_num, 0, " num is 0");
	CAFS_LOG_DEBUG("get pfile num is :%u", node_num);

	for (i = 0; i < node_num; i ++) {
		pnode = CAFS_ALLOC(sizeof(struct pfile_node_cfg), NULL);
		if(!pnode) {
			CAFS_LOG_ERROR("alloc node fail");
			continue;
		}
		memset(pnode, 0, sizeof(struct pfile_node_cfg));
		pvnode = &pnode->node;

		snprintf(tag, sizeof(tag), "pfile_node_%u:key", i);
		pvnode->id = iniparser_getint(ini_fd, tag, i);

		snprintf(tag, sizeof(tag), "pfile_node_%u:port", i);
		pvnode->port = iniparser_getint(ini_fd, tag, 50020);
		
		snprintf(tag, sizeof(tag), "pfile_node_%u:addr", i);
		ipaddr = iniparser_getstring(ini_fd, tag, "127.0.0.1");
		if (ipaddr) {
			memcpy(pvnode->addr, ipaddr, strlen(ipaddr));
		}
		CAFS_LOG_DEBUG("pvnode->ip:%s", pvnode->addr);

		snprintf(tag, sizeof(tag), "pfile_node_%u:connection", i);
		pvnode->connection = iniparser_getint(ini_fd, tag, DEFAULT_PFILE_CONNECTION);
		
		CAFS_LOG_DEBUG("pvnode->connection:%u", pvnode->connection);

		snprintf(tag, sizeof(tag), "pfile_node_%u:data_max_len", i);
		pvnode->msg_data_max_len = iniparser_getint(ini_fd, tag, (1024*1024));

		snprintf(tag, sizeof(tag), "pfile_node_%u:head_max_len", i);
		pvnode->msg_head_max_len = iniparser_getint(ini_fd, tag, (256));

		snprintf(tag, sizeof(tag), "pfile_node_%u:iov_max_len", i);
		pvnode->msg_iov_max_len = iniparser_getint(ini_fd, tag, (4*1024));

		ret = insert_pfile_node(pnode, ctx->pfile);
		if(ret) {
			CAFS_LOG_ERROR("insert_pfile_node[%u] fail", pvnode->id);
			SAFE_CAFS_FREE(pnode);
		}
	}
	
	return 0;
}


/*!
 *  @brief  加载本地静态参数到内存
 *
 *  @param[in]  config_file  配置文件
 *  @param[out] cfg  配置参数
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
static int load_mds_cfg(dictionary *ini_fd, struct cfg_ctx *ctx)
{
	const char *ipaddr =NULL;
	char  tag[256] = {0};
	uint32_t   i;
	int ret;
	uint32_t node_num = 0;
	struct mds_node_cfg *pnode;
	struct vnode_cfg *pvnode;
	LOG_THEN_RETURN_VAL_IF_TRUE(!ini_fd, 0, " ini_fd is null");

	node_num = iniparser_getint(ini_fd, "base:mds_num", 0);
	LOG_THEN_RETURN_VAL_IF_TRUE(!node_num, 0, " num is 0");
	CAFS_LOG_DEBUG("get mds num is :%u", node_num);

	for (i = 0; i < node_num; i ++) {
		pnode = CAFS_ALLOC(sizeof(struct mds_node_cfg), NULL);
		if(!pnode) {
			CAFS_LOG_ERROR("alloc node fail");
			continue;
		}
		memset(pnode, 0, sizeof(struct mds_node_cfg));
		pvnode = &pnode->node;

		snprintf(tag, sizeof(tag), "mds_node_%u:key", i);
		pvnode->id = iniparser_getint(ini_fd, tag, i);

		snprintf(tag, sizeof(tag), "mds_node_%u:port", i);
		pvnode->port = iniparser_getint(ini_fd, tag, 50020);
		
		snprintf(tag, sizeof(tag), "mds_node_%u:addr", i);
		ipaddr = iniparser_getstring(ini_fd, tag, "127.0.0.1");
		if (ipaddr) {
			memcpy(pvnode->addr, ipaddr, strlen(ipaddr));
		}
		CAFS_LOG_DEBUG("pvnode->ip:%s", pvnode->addr);

		snprintf(tag, sizeof(tag), "mds_node_%u:connection", i);
		pvnode->connection = iniparser_getint(ini_fd, tag, DEFAULT_PFILE_CONNECTION);

		snprintf(tag, sizeof(tag), "mds_node_%u:data_max_len", i);
		pvnode->msg_data_max_len = iniparser_getint(ini_fd, tag, (1024*1024));

		snprintf(tag, sizeof(tag), "mds_node_%u:head_max_len", i);
		pvnode->msg_head_max_len = iniparser_getint(ini_fd, tag, (256));

		snprintf(tag, sizeof(tag), "mds_node_%u:iov_max_len", i);
		pvnode->msg_iov_max_len = iniparser_getint(ini_fd, tag, (4*1024));

		ret = insert_mds_node(pnode, ctx->mds);
		if(ret) {
			CAFS_LOG_ERROR("insert_pfile_node[%u] fail", pvnode->id);
			SAFE_CAFS_FREE(pnode);
		}
	}
	
	return 0;
}

/*!
 *  @brief  加载本地静态参数到内存
 *
 *  @param[in]  config_file  配置文件
 *  @param[out] cfg  配置参数
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
static int load_prt_cfg(dictionary *ini_fd, struct cfg_ctx *ctx)
{
	const char *string =NULL;
	char  tag[256] = {0};
	uint32_t   i;
	int ret;
	uint32_t node_num = 0;
	struct prt_node_cfg *pnode;
	LOG_THEN_RETURN_VAL_IF_TRUE(!ini_fd, 0, " ini_fd is null");

	node_num = iniparser_getint(ini_fd, "base:prt_num", 0);
	LOG_THEN_RETURN_VAL_IF_TRUE(!node_num, 0, " num is 0");
	CAFS_LOG_DEBUG("get prt num is :%u", node_num);

	for (i = 0; i < node_num; i ++) {
		pnode = CAFS_ALLOC(sizeof(struct prt_node_cfg), NULL);
		if(!pnode) {
			CAFS_LOG_ERROR("alloc node fail");
			continue;
		}
		memset(pnode, 0, sizeof(struct prt_node_cfg));

		snprintf(tag, sizeof(tag), "prt_node_%u:key", i);
		pnode->key = iniparser_getint(ini_fd, tag, i);

		pnode->vmds_num = 1; // 配置文件默认一个
		snprintf(tag, sizeof(tag), "prt_node_%u:vmds_id", i);
		pnode->vmds.vmds_id = iniparser_getint(ini_fd, tag, 0);

		snprintf(tag, sizeof(tag), "prt_node_%u:subtree_id", i);
		pnode->vmds.subtree_id = iniparser_getint(ini_fd, tag, 0);

		snprintf(tag, sizeof(tag), "prt_node_%u:path", i);
		string = iniparser_getstring(ini_fd, tag, "/");
		if (string) {
			pnode->path = strdup(string);
		}
		CAFS_LOG_DEBUG("pvnode->path:%s", pnode->path);

		ret = insert_prt_node(pnode, ctx->prt);
		if(ret) {
			CAFS_LOG_ERROR("insert_prt_node[%u] fail", pnode->key);
			SAFE_CAFS_FREE(pnode->path);
			SAFE_CAFS_FREE(pnode);
		}
		if(!ctx->fstree){
			ctx->fstree = prt_create_tree(0);//添加根目录
			if(!ctx->fstree){
				CAFS_LOG_ERROR("create root[0] tree fail");
				remove_prt_node(pnode, ctx->prt);
				SAFE_CAFS_FREE(pnode);
				ret = CAFS_ERR;
				break;
			}
		}
		if(!prt_insert(pnode->path, pnode->key, ctx->fstree)){
			CAFS_LOG_ERROR("insert node to tree [%p] fail", ctx->prt);
			remove_prt_node(pnode, ctx->prt);
			SAFE_CAFS_FREE(pnode);
		}
	}
	
	return 0;
}

/*!
 *  @brief  加载本地静态参数到内存
 *
 *  @param[in]  config_file  配置文件
 *  @param[out] cfg  配置参数
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
static int load_vmds_cfg(dictionary *ini_fd, struct cfg_ctx *ctx)
{
	const char *string =NULL;
	char  tag[256] = {0};
	uint32_t   i;
	int ret;
	uint32_t node_num = 0;
	uint32_t key = 0;
	uint32_t val = 0;
	LOG_THEN_RETURN_VAL_IF_TRUE(!ini_fd, 0, " ini_fd is null");

	node_num = iniparser_getint(ini_fd, "base:vmds_num", 0);
	LOG_THEN_RETURN_VAL_IF_TRUE(!node_num, 0, " num is 0");
	CAFS_LOG_DEBUG("get prt num is :%u", node_num);

	for (i = 0; i < node_num; i ++) {
		snprintf(tag, sizeof(tag), "vmds_node_%u:key", i);
		key = iniparser_getint(ini_fd, tag, i);

		snprintf(tag, sizeof(tag), "prt_node_%u:mds_id", i);
		val = iniparser_getint(ini_fd, tag, 0);

		ret = insert_vmds_node(key, val, ctx->vmds);
		if(ret) {
			CAFS_LOG_ERROR("insert_vmds_node[%u] fail", key);
		}
	}
	
	return 0;
}
