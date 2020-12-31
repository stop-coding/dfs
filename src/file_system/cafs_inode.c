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
#include "cafs_inode.h"

#define INODE_CTX(ctx_name, obj, ret)\
struct _ino_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct _ino_ctx *)obj->ino_ctx;

struct _ino_ctx{
    int32_t     _ref;      // ref count. 1 for each dentry, fh that links to me.
	CommonInode *inode;
};

static void add_ref(struct cafs_inode *inode);
static void dec_ref(struct cafs_inode *inode);
static const CommonInode *get_inode(struct cafs_inode *inode);
static struct cafs_inode_ops inode_ops = {
	.ref_add =&add_ref,
	.ref_dec =&dec_ref,
	.get_inode =&get_inode,
};
struct cafs_inode *create_inode(const CommonInode *inode)
{
    struct cafs_inode *obj = NULL;
	int ret;
	struct _ino_ctx *ctx;

	LOG_THEN_RETURN_VAL_IF_TRUE(!inode, NULL, "the ino of this inode is 0");

	obj = (struct cafs_inode *)CAFS_ALLOC(sizeof(struct cafs_inode) + sizeof(struct _ino_ctx), NULL);
	LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "CAFS_ALLOC fs_obj fail.");
	memset(obj, 0, sizeof(struct cafs_inode) + sizeof(struct _ino_ctx));

	obj->ops = &inode_ops;
	ctx = (struct _ino_ctx *)obj->ino_ctx;

    ret = cafs_rwlock_init(&obj->rwlock);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_obj, "cafs_wrlock_init fail.");
	ctx->_ref = 0;
	//ctx->inode = *inode;
	
	return obj;
free_obj:
	cafs_rwlock_destroy(&obj->rwlock);
	SAFE_CAFS_FREE(obj);
	return NULL;
}

int destroy_inode(struct cafs_inode *inode)
{
    INODE_CTX(ctx, inode, CAFS_ERR);
    cafs_rwlock_wrlock(&inode->rwlock);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ctx->_ref > 0, error, "_ref is [%d], can't detroy it.", ctx->_ref);
    if (ctx->inode) {
        fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), ctx->inode);
        ctx->inode = NULL;
    }
    cafs_rwlock_unlock(&inode->rwlock);
    cafs_rwlock_destroy(&inode->rwlock);
    SAFE_CAFS_FREE(inode);
    return 0;
error:
     cafs_rwlock_unlock(&inode->rwlock);
    return CAFS_ERR;
}

static void add_ref(struct cafs_inode *inode)
{
	INODE_CTX(ctx, inode, ;);
	ctx->_ref++;
}
static void dec_ref(struct cafs_inode *inode)
{
	INODE_CTX(ctx, inode, ;);
	ctx->_ref--;
}

static const CommonInode *get_inode(struct cafs_inode *inode)
{
	INODE_CTX(ctx, inode, NULL);
	return ctx->inode;
}