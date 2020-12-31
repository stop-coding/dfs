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
#include "cafs_dentry.h"
#include "cafs_dir.h"

#define DENTRY_CTX(ctx_name, obj, ret)\
struct _dentry_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _dentry_ctx *)obj->dentry_ctx;

struct _dentry_ctx{
    int32_t     _ref;      // ref count. 1 for each dentry, fh that links to me.
    struct cafs_dentry_info parent;
    struct cafs_dentry_info self;
};

static void get_dentry(struct cafs_dentry *dentry);
static void put_dentry(struct cafs_dentry *dentry);
static const struct cafs_dentry_info* get_parent(struct cafs_dentry *dentry)
{
    DENTRY_CTX(ctx, dentry, NULL);
    return &ctx->parent;
}
static const struct cafs_dentry_info* get_self(struct cafs_dentry *dentry)
{
    DENTRY_CTX(ctx, dentry, NULL);
    return &ctx->self;
}
static int move_dentry2cafs(const CommonDentry *d, struct cafs_dentry_info *de);

static struct cafs_dentry_ops dentry_ops = {
	.get =&get_dentry,
	.put =&put_dentry,
    .get_parent = &get_parent,
    .get_self = &get_self,
};
struct cafs_dentry *create_dentry(const CommonDentry *parent, const CommonDentry *self)
{
    struct cafs_dentry *obj = NULL;
	int ret;
	struct _dentry_ctx *ctx;
    uint32_t path_len;

	LOG_THEN_RETURN_VAL_IF_TRUE(!parent, NULL, "the parent of dentry is null");
    LOG_THEN_RETURN_VAL_IF_TRUE(!self, NULL, "the self of dentry is null");
 
	obj = (struct cafs_dentry *)CAFS_ALLOC(sizeof(struct cafs_dentry) + sizeof(struct _dentry_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC cafs_dentry fail.");
	memset(obj, 0, sizeof(struct cafs_dentry) + sizeof(struct _dentry_ctx));

	obj->ops = &dentry_ops;

	ctx = (struct _dentry_ctx *)obj->dentry_ctx;

    ret = cafs_rwlock_init(&obj->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");
	ctx->_ref = 0;
	
    ret = move_dentry2cafs(parent, &ctx->parent);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "move_dentry2cafs fail.");

    ret = move_dentry2cafs(self, &ctx->self);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "move_dentry2cafs fail.");

	return obj;
free_obj:
	cafs_rwlock_destroy(&obj->rwlock);
	SAFE_CAFS_FREE(obj);
	return NULL;
}

int destroy_dentry(struct cafs_dentry *dentry)
{
    int ret;
    DENTRY_CTX(ctx, dentry, CAFS_ERR);

    cafs_rwlock_wrlock(&dentry->rwlock);

    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ctx->_ref > 0, error, "_ref is [%d], can't detroy it.", ctx->_ref);


    cafs_rwlock_unlock(&dentry->rwlock);
    cafs_rwlock_destroy(&dentry->rwlock);
    SAFE_CAFS_FREE(dentry);
    return 0;
error:
     cafs_rwlock_unlock(&dentry->rwlock);
    return CAFS_ERR;
}

static void get_dentry(struct cafs_dentry *dentry)
{
	DENTRY_CTX(ctx, dentry, ;);
	ctx->_ref++;
}
static void put_dentry(struct cafs_dentry *dentry)
{
	DENTRY_CTX(ctx, dentry, ;);
	ctx->_ref--;
}

static int move_dentry2cafs(const CommonDentry *d, struct cafs_dentry_info *de)
{
    uint32_t name_len = 0;

    de->mode = d->mode;
    de->ino = d->ino;
    name_len = strlen(d->name);
    name_len = (name_len > FS_MAX_FILE_NAME_LIMIT)? FS_MAX_FILE_NAME_LIMIT: name_len;
    memcpy(de->d_name, d->name, name_len);
    return 0;
}