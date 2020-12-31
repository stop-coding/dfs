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
#include "cafs_tree.h"

#include "klist.h"


#define DEFAULT_NODE_MAX_NUM 10

static void _kmp_free(void  *iter)
{
    return;
}

KLIST_INIT(_list, struct prt_tree_node *, _kmp_free);

struct _node_ctx{
    klist_t(_list) *child;
    struct prt_tree_node *parent; // 父节点
};

inline static uint32_t find_seq(const char *head)
{
    uint32_t i = 1;
    if (*head == '\0') {
        return 0;
    }
    while(*(head + i) != '/' && *(head + i) != '\0'){
        i++;
    }
    return i;
}

inline static char* new_format_path(const char *path)
{
    char *format;
    uint32_t len;
    const char *tmp = path;
    len = strlen(path);
    format = (char*)CAFS_ALLOC(len + 2, NULL);
    if (len > 1 && tmp[0] == '/') {
        tmp = path + 1;
        len--;
    }
    memcpy(format, tmp, len);
    if (format[len - 1] != '/'){
        format[len] = '/';
        len++;
    }
    format[len] = '\0';
    return format;
}

inline static int path_compare(const char *path1, const char *path2, uint32_t cmp_len)
{
    uint32_t i;
    for (i = 0; i < cmp_len; i ++) {
        if ((*(path1 + i) == '\0' && *(path2 + i) == '/') || 
            (*(path2 + i) == '\0' && *(path1 + i) == '/')) {
            return 0;
        }else if (*(path1 + i) == '\0' || *(path2 + i) == '\0'){
            return -1;
        }else if (*(path1 + i) != *(path2 + i)) {
            return -1;
        }
    }
    return 0;
}

inline static struct prt_tree_node *new_node(const char *path, uint32_t id){
    struct _node_ctx *ctx;
    struct prt_tree_node *node = CAFS_ALLOC(sizeof(struct prt_tree_node) + sizeof(struct _node_ctx), NULL);
    if (node) {
        memset(node, 0, sizeof(struct prt_tree_node) + sizeof(struct _node_ctx));
        node->path = new_format_path(path);
        node->path_len = strlen(node->path);
        node->node_id = id;
        ctx = (struct _node_ctx *)node->node_ctx;
        ctx->child = kl_init(_list);
    }
    return node;
}

inline static struct prt_tree_node *new_node_nochild(const char *path, uint32_t id){
    struct _node_ctx *ctx;
    struct prt_tree_node *node = CAFS_ALLOC(sizeof(struct prt_tree_node) + sizeof(struct _node_ctx), NULL);
    if (node) {
        memset(node, 0, sizeof(struct prt_tree_node) + sizeof(struct _node_ctx));
        node->path = new_format_path(path);
        node->path_len = strlen(node->path);
        node->node_id = id;
        ctx = (struct _node_ctx *)node->node_ctx;
        ctx->child = NULL;
    }
    return node;
}


inline static struct prt_tree_node *insert_child(struct prt_tree_node *node, struct prt_tree_node *child){
    struct _node_ctx *ctx;
    struct prt_tree_node **tmp_ppchild;

    LOG_THEN_RETURN_VAL_IF_TRUE((!node || !child), NULL, "null pointer.");

    ctx = (struct _node_ctx *)node->node_ctx;
    tmp_ppchild = kl_pushp(_list, ctx->child);
    *tmp_ppchild = child;

    ctx = (struct _node_ctx *)child->node_ctx;
    ctx->parent = node;
    return child;
}

inline static void remove_parent(struct prt_tree_node *child){
    struct _node_ctx *par_ctx;
    struct prt_tree_node *parent;
    struct prt_tree_node *tmp_node;
    kliter_t(_list)  *iter, *pre_iter;

    LOG_THEN_RETURN_IF_VAL_TRUE((!child), "null pointer.");
    parent = ((struct _node_ctx *)child->node_ctx)->parent;
    if (!parent) {
        return;
    }
    par_ctx = (struct _node_ctx *)parent->node_ctx;
    iter = kl_begin(par_ctx->child);
    pre_iter = NULL;
    while(iter) {
        tmp_node = kl_val(iter);
        if (tmp_node != child) {
            pre_iter = iter;
            iter = kl_next(iter);
            continue;
        }
        kl_val(iter) = NULL;
        if (iter == kl_begin(par_ctx->child)) {
            kl_shift(_list, par_ctx->child, NULL);
        }else if (pre_iter){
            kl_next(pre_iter) = kl_next(iter);
            --par_ctx->child->size;
            kmp_free(_list, par_ctx->child->mp, iter);
        }
        break;
    }
    return;
}

inline static void free_node(struct prt_tree_node *node)
{
    LOG_THEN_RETURN_IF_VAL_TRUE((!node), "null pointer.");
    SAFE_CAFS_FREE(node->path);
    remove_parent(node);
    kl_destroy(_list, ((struct _node_ctx *)node->node_ctx)->child);
    SAFE_CAFS_FREE(node);
    return;
}

uint32_t find_com_path_lenght(const char *path1, const char *path2)
{
    uint32_t i ;
    uint32_t path1_len = strlen(path1);
    uint32_t path2_len = strlen(path2);
    uint32_t com_len = 0;

    for (i = 0; i < path1_len && i < path2_len; i++) {
        if (*(path1 + i) !=  *(path2 + i)) {
            break;
        }
        if (*(path2 + i) == '/' || i == 0) {
            com_len = i + 1;
        }
    }

    return com_len;
}   

inline static struct prt_tree_node *split_node(struct prt_tree_node *node, uint32_t com_len)
{
    char *new_path;
    struct prt_tree_node *n_child;
    struct prt_tree_node *parent;
    struct prt_tree_node *gradparent;

    if (com_len == 0) {
        return node;
    }
    gradparent = ((struct _node_ctx *)node->node_ctx)->parent;
    remove_parent(node);

    new_path = new_format_path(node->path + com_len);

    node->path[com_len] = '\0';
    parent = new_node(node->path, gradparent->node_id);
    insert_child(gradparent, parent);

    SAFE_CAFS_FREE(node->path);
    node->path = new_path;
    ((struct _node_ctx *)node->node_ctx)->parent = parent;
    node->path_len = strlen(node->path);
    insert_child(parent, node);
    //prt_dump_tree(node);
    return parent;
}   

struct prt_tree_node *prt_create_tree(uint32_t id)
{
    return new_node("/", id);
}

struct prt_tree_node *prt_insert(const char *path, uint32_t id, struct prt_tree_node *root)
{
    struct prt_tree_node *node;
    struct _node_ctx *ctx;
    uint32_t    head = 0, tail = 1;
    uint32_t    path_len = 0;
    uint32_t    com_len = 0;
    kliter_t(_list)  *iter;
    struct prt_tree_node *tmp_node;

    LOG_THEN_RETURN_VAL_IF_TRUE((!root), NULL, "root null pointer.");
    LOG_THEN_RETURN_VAL_IF_TRUE((!path), NULL, "path null pointer.");

    path_len = strlen(path);
    if((path_len == 1) && (path[0] == '/')){
        root->node_id = id;
        return root;
    }
    LOG_THEN_RETURN_VAL_IF_TRUE((path[0] != '/'), NULL, "path[0] msut be '/'.");
    node = root;
    while(node) {
        if (strncmp(node->path, (path + head), node->path_len) != 0) {
            // 分裂
            com_len =find_com_path_lenght(node->path, (path + head));
            if (com_len > 0) {
                //CAFS_LOG_DEBUG(" path1[%s], path2[%s], com_len:%u.", node->path, (path + head), com_len);
                node = split_node(node, com_len);
                head += com_len;
            }
            break;
        }

        if (head + node->path_len >= path_len) {
            // 已存在
            CAFS_LOG_ERROR("node exist: path[%s], path + head[%s].",  node->path, path + head);
            return NULL;
        }

        head += node->path_len;
        ctx = (struct _node_ctx *)node->node_ctx;
        if (ctx->child->size == 0) {
            break;
        }

        iter = kl_begin(ctx->child);
        while(iter) {
            tmp_node = kl_val(iter);
            iter = kl_next(iter);
            if (!tmp_node) {
                continue;
            }
            if (strncmp(tmp_node->path, (path + head), find_seq(path + head)) == 0) {
                node = tmp_node;
                break;
            }

        }
        if (!iter) {
            break;
        }
    }

    return insert_child(node, new_node((path + head), id));
}

const struct prt_tree_node *prt_search(const struct prt_tree_node *root, const char *path)
{
    const struct prt_tree_node *node;
    struct _node_ctx *ctx;
    uint32_t    head = 0;
    kliter_t(_list)  *iter;
    const struct prt_tree_node *tmp_node;
    uint32_t depth = 0;
    CAFS_LOG_DEBUG("prt to search target path:[%s].", path);
    LOG_THEN_RETURN_VAL_IF_TRUE((!root || !path), NULL, "null pointer.");

    node = root;
    while(node) {
        if (path_compare(node->path, (path + head), node->path_len) != 0) {
            break;
        }
        ctx = (struct _node_ctx *)node->node_ctx;
        if (ctx->child->size == 0) {
            break;
        }
        head += node->path_len;
        iter = kl_begin(ctx->child);
        while(iter) {
            tmp_node = kl_val(iter);
            iter = kl_next(iter);
            depth++;
            if (!tmp_node) {
                continue;
            }
            if (path_compare(tmp_node->path, (path + head), tmp_node->path_len) == 0) {
                node = tmp_node;
                break;
            }
        }
        if (!iter) {
            break;
        }
    }
    CAFS_LOG_DEBUG("prt search result: path[%s], prt-id[%u].", node->path, node->node_id);
    return node;
}

int prt_remove(const char *path, struct prt_tree_node *root)
{
    struct prt_tree_node *find_node = (struct prt_tree_node *)prt_search(root, path);

    LOG_THEN_RETURN_VAL_IF_TRUE((!find_node), CAFS_ERR, "can't find node fail.");

    free_node(find_node);
    return 0;
}

void prt_destroy_tree(struct prt_tree_node *root)
{
    struct _node_ctx *ctx;
    kliter_t(_list)  *iter;

    if (!root) return;
    ctx = (struct _node_ctx *)root->node_ctx;
    if (ctx->child->size) {
        iter = kl_begin(ctx->child);
        while(iter){
            prt_destroy_tree(iter->data);
            iter = kl_next(iter);
        }
    }
    //CAFS_LOG_DEBUG("depth: path[%s], id[%u].",root->path, root->node_id);
    free_node(root);
    return;
}

void prt_dump_tree(const struct prt_tree_node *root)
{
    struct _node_ctx *ctx;
    kliter_t(_list)  *iter;

    if (!root) return;
    CAFS_LOG_DEBUG("--------------Node[%s]----------------", root->path);
    CAFS_LOG_DEBUG("dump: [%p][%u].", root, root->node_id);
    ctx = (struct _node_ctx *)root->node_ctx;
    if (ctx->parent){
        CAFS_LOG_DEBUG("parent:path[%s], prt[%p].",ctx->parent->path, ctx->parent);
    }
    if (ctx->child->size) {
        iter = kl_begin(ctx->child);
        while(iter){
            if (iter->data){
                CAFS_LOG_DEBUG("child:[%s][%u][%p].",iter->data->path, iter->data->node_id, iter->data);
            }
            iter = kl_next(iter);
        }
        CAFS_LOG_DEBUG("--------------end----------------");
        iter = kl_begin(ctx->child);
        while(iter){
            prt_dump_tree(iter->data);
            iter = kl_next(iter);
        }
    }
    return;
}