/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */

/*!
* \file x.h
* \brief 
* 
* ....
*
* \copyright 2020 Ruijie Network. All rights reserved.
* \author hongchunhua@ruijie.com.cn
* \version v1.0.0
* \date 2020.08.05
* \note none 
*/

#ifndef _CAFS_PFILE_NODE_H_
#define _CAFS_PFILE_NODE_H_

#include "cafs_public.h"
#include "cafs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pfile_w_msg{
    uint64_t uid;
    uint64_t gid;
    uint64_t client_id;
    uint64_t obj_id;
    uint64_t w_offset;
    uint64_t w_max_size;
};

struct pfile_r_msg{
    uint64_t uid;
    uint64_t gid;
    uint64_t client_id;
    uint64_t obj_id;
    uint64_t r_offset;
    uint64_t r_max_size;
};

struct pfile_node_obj;

struct pfile_node_ops {
    int64_t (*write)(const struct pfile_node_obj *pfile, const struct pfile_w_msg *w_msg, const void *buf, int64_t count);
    int64_t (*read)(const struct pfile_node_obj *pfile, const struct pfile_r_msg *r_msg, void *buf, int64_t count);
};

enum pfile_node_type{
    PFILE_NODE_TYPE_MINI_IO = 0,
    PFILE_NODE_TYPE_BIG_IO
};

struct pfile_node_obj {
    uint32_t  id;
    struct pfile_node_ops *ops;
    enum pfile_node_type type;
    char    ctx[0];
};

#define CAFS_PFILE_KEEP_CONNECT_FOREVER         (-1)

struct pfile_node_cfg{
	struct vnode_cfg *node;
    int64_t     timeout_ms;
};
/*!
 *  @brief  创建一个消息连接对象
 *
 *  @param[in]  conf  连接对象
 *  @return  struct connect_obj * 请求消息的操作对象; (<em>NULL</em>: fail ; ( <em>非NULL</em>: succeed
 *
 */
struct pfile_node_obj *cafs_create_pfile_node(const struct pfile_node_cfg *cfg);


/*!
 *  @brief  销毁一个连接对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_pfile_node(struct pfile_node_obj *obj);

#ifdef __cplusplus
}
#endif

#endif
