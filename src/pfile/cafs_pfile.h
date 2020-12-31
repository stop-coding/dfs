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

#ifndef _CAFS_PFILE_H_
#define _CAFS_PFILE_H_

#include "cafs_public.h"
#include "cafs_config.h"
#include "cafs_pfile_node.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pfile_obj;
struct pfile_ops {
    const struct pfile_node_obj *(*get)(struct pfile_obj *obj, uint32_t pfile_id);
    int (*put)(struct pfile_obj *obj, uint32_t pfile_id);
    const struct pfile_node_obj *(*get_bigio)(struct pfile_obj *obj, uint32_t pfile_id);
};

struct pfile_obj {
    struct pfile_ops *ops;
    char    ctx[0];
};

struct pfile_cfg{
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
struct pfile_obj *cafs_create_pfile(const struct pfile_cfg *cfg);


/*!
 *  @brief  销毁一个连接对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_pfile(struct pfile_obj *obj);

#ifdef __cplusplus
}
#endif

#endif
