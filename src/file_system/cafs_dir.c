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
#include "cafs_dir.h"
#include "cafs_dentry.h"
#include "cafs_mds.h"

#include "klist.h"

#define IS_PARENT_DIR   (1)
#define IS_SELF_DIR     (0)
#define IS_CUR_FILE     (2)

#define READ_DIR_LAST               (1<<0)
#define DIR_REQUEST_ENTRY_MAX_NUM   (64)
#define DIR_REQUEST_WAIT_TIMEOUT    (1000)
#define MAX_DENTRIES_LIMITE         (10*1000)

#define DIR_CTX(ctx_name, obj, ret)\
struct _dir_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _dir_ctx *)obj->dir_ctx;


#define DIR_NAME_MAX_LEN 255
#define RSP_MAX_DENTRIS_LIMITS 32

struct cafs_dirent
{
    int64_t offset;
    uint32_t mode;
    struct dirent _dirent;
    struct cafs_dirent *next;
};
static void free_cafs_dirent(void *iter);

KLIST_INIT(l_dirent, struct cafs_dirent *, free_cafs_dirent);

static void free_cafs_dirent(void *iter)
{
    if (iter) {
        return;
    }
    SAFE_CAFS_FREE(kl_val((kliter_t(l_dirent) *)iter));
}

struct _dir_ctx{ 
    klist_t(l_dirent) *list;
    struct cafs_rwlock rwlock;
    const struct mds_node_obj *mds;
    uint64_t uid;
    uint64_t gid;
    uint64_t client_id;
    char *dir_path;
    int32_t flags;
    int64_t  last_offset;
    uint32_t total_num;
    kliter_t(l_dirent) *offset;
};

static int add_child(struct cafs_dir *dir, const CommonDentry *de);
static int add_parent(struct cafs_dir *dir, const CommonDentry *de);
static int add_self(struct cafs_dir *dir, const CommonDentry *de);
static int do_opendir(struct cafs_dir *dir, const char *path);
static int do_readdir(struct cafs_dir *dir, uint32_t max_dentries);
static int do_closedir(struct cafs_dir *dir);
static kliter_t(l_dirent) *get_next_dentry(struct cafs_dir *dir);

static struct dirent *readdir_dirent(struct cafs_dir *dir);
static int64_t tell_dirent(struct cafs_dir *dir);
static int seek_dirent(struct cafs_dir *dir, int64_t offset);
static int rewind_dirent(struct cafs_dir *dir);

static struct cafs_dir_ops dir_ops = {
    .readdir = &readdir_dirent,
    .tell = &tell_dirent,
    .seek = &seek_dirent,
    .rewind = &rewind_dirent,
};
struct cafs_dir *create_dir(struct cafs_dir_param *param)
{
    struct cafs_dir *obj = NULL;
	int ret;
	struct _dir_ctx *ctx;
    uint32_t path_len;

    LOG_THEN_RETURN_VAL_IF_TRUE(!param, NULL, "param is null");
    LOG_THEN_RETURN_VAL_IF_TRUE(!param->open_path, NULL, "open_path is null");
    LOG_THEN_RETURN_VAL_IF_TRUE(!param->mds, NULL, "mds is null");
  
	obj = (struct cafs_dir *)CAFS_ALLOC(sizeof(struct cafs_dir) + sizeof(struct _dir_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC cafs_dir fail.");
	memset(obj, 0, sizeof(struct cafs_dir) + sizeof(struct _dir_ctx));

	obj->ops = &dir_ops;

	ctx = (struct _dir_ctx *)obj->dir_ctx;

    ret = cafs_rwlock_init(&ctx->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");

    ctx->list = kl_init(l_dirent);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE((!ctx->list), free_obj, "kl_init list fail.");
    ctx->mds = param->mds;
    ctx->gid = param->gid;
    ctx->uid = param->uid;

    ret = do_opendir(obj, param->open_path);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "opendir path[%s] fail.", param->open_path);

    path_len = strlen(param->open_path);
    ctx->dir_path = CAFS_ALLOC(path_len + 1, NULL);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ctx->dir_path, close_dir, "CAFS_ALLOC fail.");

    memcpy(ctx->dir_path, param->open_path, path_len);
    ctx->dir_path[path_len] = '\0';
    obj->name = ctx->dir_path;

	return obj;
close_dir:
    do_closedir(obj);
free_obj:
    SAFE_CAFS_FREE(ctx->dir_path);

    if (ctx->list) {
        kl_destroy(l_dirent, ctx->list);
        ctx->list = NULL;
    }
	cafs_rwlock_destroy(&ctx->rwlock);
	SAFE_CAFS_FREE(obj);
	return NULL;
}

int destroy_dir(struct cafs_dir *dir)
{
    int ret;
    DIR_CTX(ctx, dir, CAFS_ERR);

    cafs_rwlock_wrlock(&ctx->rwlock);

    ret = do_closedir(dir);
    LOG_ERROR_IF_VAL_TRUE(ret, "close dir[%s] fail.", ctx->dir_path);

    SAFE_CAFS_FREE(ctx->dir_path);

    if (ctx->list) {
        kl_destroy(l_dirent, ctx->list);
        ctx->list = NULL;
    }

    cafs_rwlock_unlock(&ctx->rwlock);
    cafs_rwlock_destroy(&ctx->rwlock);
    SAFE_CAFS_FREE(dir);
    return 0;
}

static struct dirent *readdir_dirent(struct cafs_dir *dir)
{
    struct cafs_dirent *dirent = NULL;
    DIR_CTX(ctx, dir, NULL);

    if (IS_SET(ctx->flags, READ_DIR_LAST)) {
        return NULL;
    }
    if (!ctx->offset) {
        ctx->offset = kl_begin(ctx->list);
        LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->offset, NULL, "get begin dirent fail.");
        dirent = kl_val(ctx->offset);
    }else{
        dirent = kl_val(ctx->offset);
    }
    ctx->offset = get_next_dentry(dir);
    LOG_THEN_RETURN_VAL_IF_TRUE(!dirent, NULL,
                                 "get dirent fail, last_offset:%ld, total_num:%u.", 
                                 ctx->last_offset,
                                  ctx->total_num);
    
    return &dirent->_dirent;
}

static int64_t tell_dirent(struct cafs_dir *dir)
{
    struct cafs_dirent *dirent = NULL;
    DIR_CTX(ctx, dir, 0);
    if (!ctx->offset){
        return 0;
    }
    dirent = kl_val(ctx->offset);
    return dirent->offset;
}

static int seek_dirent(struct cafs_dir *dir, int64_t offset)
{
    struct cafs_dirent *dirent = NULL;
    kliter_t(l_dirent) *iter;
    DIR_CTX(ctx, dir, CAFS_ERR);

    if (offset < 0) {
         return CAFS_ERR;
    }
    for ( iter = kl_begin(ctx->list); iter != kl_end(ctx->list); iter = kl_next(iter)) {
        dirent = kl_val(iter);
        CAFS_ASSERT(dirent, "dirent empty on list node");
        if (dirent->offset == offset){
            ctx->offset = iter;
            if (IS_SET(ctx->flags, READ_DIR_LAST) && (dirent->offset != ctx->last_offset)) {
                CLR_FLAG(ctx->flags, READ_DIR_LAST);
            }
            return 0;
        }
    }
    CAFS_LOG_ERROR("can't find the offset[%ld] on list", offset);
    return CAFS_ERR;
}
static int rewind_dirent(struct cafs_dir *dir)
{
    DIR_CTX(ctx, dir, CAFS_ERR);
    ctx->offset = NULL;
    CLR_FLAG(ctx->flags, READ_DIR_LAST);
    return 0;
}


static inline int dentry2dirent(const CommonDentry *d, struct cafs_dirent *dirent)
{
    uint32_t name_len = 0;

    dirent->offset = d->offset;
    dirent->mode = d->mode;
    dirent->_dirent.d_ino = d->ino;
    dirent->_dirent.d_type = IFTODT(d->mode);
    name_len = strlen(d->name);
    dirent->_dirent.d_off = d->offset;
    name_len = (name_len > DIR_NAME_MAX_LEN)? DIR_NAME_MAX_LEN: name_len;
    dirent->_dirent.d_reclen = name_len;
    memcpy(dirent->_dirent.d_name, d->name, name_len);

    return 0;
}

static kliter_t(l_dirent) *get_next_dentry(struct cafs_dir *dir)
{
    int ret;
    kliter_t(l_dirent) *iter;
    DIR_CTX(ctx, dir, NULL);

    iter = kl_next(ctx->offset);
    if (iter != kl_end(ctx->list)) {
        return iter;
    }

    if(ctx->total_num <= (uint32_t)ctx->list->size) {
        SET_FLAG(ctx->flags, READ_DIR_LAST); //说明已经到结尾了
        return NULL;
    }

    ret = do_readdir(dir, DIR_REQUEST_ENTRY_MAX_NUM);
    LOG_THEN_RETURN_VAL_IF_TRUE(ret, NULL, 
                                "do_readdir fail, total_num:%u, read dir num:%u.", 
                                ctx->total_num, 
                                (uint32_t)ctx->list->size);
    iter = kl_next(ctx->offset);
    if (iter != kl_end(ctx->list)) {
        return iter;
    }
    SET_FLAG(ctx->flags, READ_DIR_LAST);
    return NULL;
}

inline static int init_request_head(const char *file_path, const char *mds_path, struct _dir_ctx *ctx, CaMdsReqHead *head) {
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, MSG_ID_CA_MDS_REQ_HEAD), head, sizeof(CaMdsReqHead));
	head->file_path = (char *)file_path;
	head->root_path = (char *)mds_path;
	head->uid = ctx->uid;
	head->gid = ctx->gid;
	head->client_id = ctx->client_id;
	return 0;
}

inline static int mds_request(const char *file_path, struct mds_req_msg *req, struct _dir_ctx *ctx, struct mds_rsp_msg *rsp)
{
	const struct mds_node_obj *mds_node;
	int ret;

    mds_node = ctx->mds;
    LOG_THEN_RETURN_VAL_IF_TRUE(!mds_node, CAFS_ERR, "mds node is empty.");
    rsp->op_id = req->op_id;
	ret = cafs_mds_request(mds_node, req, rsp, DIR_REQUEST_WAIT_TIMEOUT);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, put_rsp, "request op[%d] fail.", req->op_id);
	return 0;
put_rsp:
    cafs_mds_put_rsp(rsp);
    return -1;
}

static int readdir_request(const char *file_path, struct _dir_ctx *ctx,  int64_t offset, 
							uint32_t max_dentries, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, CAFS_ERR, "file path null.");
	ret = init_request_head(file_path, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_READDIR;
	INIT_REQ_FSMSG(req.op_id, &req.msg.readdir);
	req.msg.readdir.head = &req_head;
	req.msg.readdir.max_entries = max_dentries;
	req.msg.readdir.offset = (uint32_t)offset;
	ret = mds_request(file_path, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}

static int opendir_request(const char *file_path, struct _dir_ctx *ctx, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, CAFS_ERR, "file path null.");
	ret = init_request_head(file_path, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_OPENDIR;
	INIT_REQ_FSMSG(req.op_id, &req.msg.opendir);
	req.msg.opendir.head = &req_head;
	ret = mds_request(file_path, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}

static int closedir_request(const char *file_path, struct _dir_ctx *ctx, struct mds_rsp_msg *rsp)
{
	CaMdsReqHead req_head;
	struct mds_req_msg req;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!file_path, CAFS_ERR, "file path null.");
	ret = init_request_head(file_path, NULL, ctx, &req_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "init_request_head fail.");
	memset(&req, 0, sizeof(req));
	req.op_id = MSG_OP_TYPE_E_CLOSEDIR;
	INIT_REQ_FSMSG(req.op_id, &req.msg.closedir);
	req.msg.closedir.head = &req_head;
	ret = mds_request(file_path, &req, ctx, rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_mds_request fail.");
	return 0;
}


static inline int add_self(struct cafs_dir *dir, const CommonDentry *de)
{
    int ret;
    char self[] = ".";
    struct cafs_dirent *dire;
    struct cafs_dirent **pdire = NULL;
    DIR_CTX(ctx, dir, CAFS_ERR);

    dire = CAFS_ALLOC(sizeof(struct cafs_dirent), NULL);
    LOG_THEN_RETURN_VAL_IF_TRUE(!dire, CAFS_ERR, "CAFS_ALLOC dirent null.");
    memset(dire, 0, sizeof(struct cafs_dirent));

    ret = dentry2dirent(de, dire);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "dentry2dirent fail.");

    if (strcmp(dire->_dirent.d_name, self) != 0) {
        memcpy(dire->_dirent.d_name, self, sizeof(self));
    }
    dire->offset = IS_SELF_DIR;
    pdire = kl_pushp(l_dirent, ctx->list);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pdire, free_buf, "kl_pushp fail.");
    *pdire = dire;
    ctx->last_offset = dire->offset;
    return 0;
free_buf:
    SAFE_CAFS_FREE(dire);
    return -1;

}

static inline int add_parent(struct cafs_dir *dir, const CommonDentry *de)
{
    int ret;
    char parent[] = "..";
    struct cafs_dirent *dire;
    struct cafs_dirent **pdire = NULL;
    DIR_CTX(ctx, dir, CAFS_ERR);

    dire = CAFS_ALLOC(sizeof(struct cafs_dirent), NULL);
    LOG_THEN_RETURN_VAL_IF_TRUE(!dire, CAFS_ERR, "CAFS_ALLOC dirent null.");

    memset(dire, 0, sizeof(struct cafs_dirent));

    ret = dentry2dirent(de, dire);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "dentry2dirent fail.");

    if (strcmp(dire->_dirent.d_name, parent) != 0) {
        memcpy(dire->_dirent.d_name, parent, sizeof(parent));
    }
    dire->offset = IS_PARENT_DIR;

    pdire = kl_pushp(l_dirent, ctx->list);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pdire, free_buf, "kl_pushp fail.");
    *pdire = dire;

    ctx->last_offset = dire->offset;
    return 0;
free_buf:
    SAFE_CAFS_FREE(dire);
    return -1;
}

static int do_opendir(struct cafs_dir *dir, const char *path)
{
  	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	CaMdsRspOpendir *opendir;
	int ret;

	DIR_CTX(ctx, dir, CAFS_ERR);

	memset(&rsp, 0, sizeof(rsp));
	ret = opendir_request(path, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "opendir_request fail.");

	rsp_head = rsp.msg->opendir.head;
	LOG_THEN_RETURN_VAL_IF_TRUE(rsp_head->rsp_result, CAFS_ERR, "get_rsp result[%d] fail.", rsp_head->rsp_result);

	opendir = &rsp.msg->opendir;
	LOG_THEN_RETURN_VAL_IF_TRUE(!opendir->self, CAFS_ERR, "get_rsp opendir->self null fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(!opendir->parent, CAFS_ERR, "get_rsp opendir->parent null fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(opendir->dentry_num < 1, CAFS_ERR, "dentry_num invalid fail.");
	LOG_THEN_RETURN_VAL_IF_TRUE(opendir->dentry_num > MAX_DENTRIES_LIMITE, CAFS_ERR, "dentry_num over max[%lu] fail.", opendir->dentry_num);

    ctx->total_num = opendir->dentry_num;

	ret = add_self(dir, opendir->self);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "add_self fail.");

	ret = add_parent(dir, opendir->parent);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "add_parent fail.");

	return 0;
}

static int do_closedir(struct cafs_dir *dir)
{
  	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
	int ret;

	DIR_CTX(ctx, dir, CAFS_ERR);

	memset(&rsp, 0, sizeof(rsp));
	ret = closedir_request(dir->name, ctx, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_closedir_request fail.");

	rsp_head = rsp.msg->closedir.head;
	LOG_THEN_RETURN_VAL_IF_TRUE(rsp_head->rsp_result, CAFS_ERR, "get_rsp result[%d] fail.", rsp_head->rsp_result);

	return 0;
}

static inline int add_child(struct cafs_dir *dir, const CommonDentry *de)
{
    int ret;
    struct cafs_dirent *dire;
    struct cafs_dirent **pdire = NULL;
    kliter_t(l_dirent) *iter; //iter
    DIR_CTX(ctx, dir, CAFS_ERR);

    LOG_THEN_RETURN_VAL_IF_TRUE(de->offset < 0, CAFS_ERR, "offset[%ld] must over 0.", de->offset);

    dire = CAFS_ALLOC(sizeof(struct cafs_dirent), NULL);
    LOG_THEN_RETURN_VAL_IF_TRUE(!dire, CAFS_ERR, "CAFS_ALLOC dirent null.");

    memset(dire, 0, sizeof(struct cafs_dirent));

    ret = dentry2dirent(de, dire);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "dentry2dirent fail.");

    ctx->last_offset = de->offset;
    pdire = kl_pushp(l_dirent, ctx->list);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!pdire, free_buf, "kl_pushp fail.");
    *pdire = dire;
    return 0;

free_buf:
    SAFE_CAFS_FREE(dire);
    return -1;
}

static int do_readdir(struct cafs_dir *dir, uint32_t max_dentries)
{
  	struct mds_rsp_msg rsp;
	CaMdsRspHead *rsp_head;
    CaMdsRspReaddir *preaddir;
    uint32_t i;
	int ret;

	DIR_CTX(ctx, dir, CAFS_ERR);

	memset(&rsp, 0, sizeof(rsp));
	ret = readdir_request(dir->name, ctx, ctx->last_offset + 1, max_dentries, &rsp);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, CAFS_ERR, "_closedir_request fail.");

	rsp_head = rsp.msg->readdir.head;
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(rsp_head->rsp_result, put_rsp, "get_rsp result[%d] fail.", rsp_head->rsp_result);
    preaddir = &rsp.msg->readdir;

    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!preaddir->n_dentry, put_rsp, "n_dentry is 0.");
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!preaddir->dentry, put_rsp, "dentry is NULL.");
    for (i = 0; i < (uint32_t)preaddir->n_dentry; i++) {
        if (!preaddir->dentry[i]) {
            continue;
        }
        ret = add_child(dir, preaddir->dentry[i]);
        if (ret) {
            CAFS_LOG_ERROR("add_child offset[%u] fail", i);
        }
    }
    cafs_mds_put_rsp(&rsp);
	return 0;
put_rsp:
cafs_mds_put_rsp(&rsp);
   return -1;
}