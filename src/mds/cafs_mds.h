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

#ifndef _CAFS_MDS_H_
#define _CAFS_MDS_H_

#include "cafs_public.h"
#include "cafs_mds_node.h"
#include "cafs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mds_obj;
struct mds_ops {
    const struct mds_node_obj *(*get)(struct mds_obj *obj, const char *path);
    const struct mds_node_obj *(*get_by_vmds)(struct mds_obj *obj, uint32_t vmds_id);
    int (*put)(struct mds_obj *obj, const struct mds_node_obj *node);
};

struct mds_obj {
    struct mds_ops *ops;
    char    ctx[0];
};

struct mds_cfg{
    const char *cfg_file;
    const struct cafs_cfg_obj *cfg;
};
/*!
 *  @brief  创建一个消息连接对象
 *
 *  @param[in]  conf  连接对象
 *  @return  struct connect_obj * 请求消息的操作对象; (<em>NULL</em>: fail ; ( <em>非NULL</em>: succeed
 *
 */
struct mds_obj *cafs_create_mds(const struct mds_cfg *cfg);


/*!
 *  @brief  销毁一个连接对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_mds(struct mds_obj *obj);


#ifdef __cplusplus
}
#endif

#endif
