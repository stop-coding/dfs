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

#ifndef _CAFS_MDS_NODE_H_
#define _CAFS_MDS_NODE_H_

#include "cafs_public.h"
#include "cafs_mds_msg.h"
#include "cafs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WAIT_FOREVER -1

/*!
 * @brief  ca请求参数
 *
 * @details
 *  该参数是调用者请求，并且获得到对方的消息
 *  
 */
struct mds_req_msg {
    enum msg_op_type    op_id;
    mds_req_msg_u       msg;            // 请求消息的结构化数据
    void              *data;          // 请求消息的二进制数据
    uint32_t          data_len;
};

/*!
 * @brief  ca回复参数
 *
 * @details
 *  该参数是调用者请求，并且获得到对方的消息
 *  
 */
struct mds_rsp_msg {
    enum msg_op_type    op_id;
    mds_rsp_msg_u       *msg;            // 接收消息的结构化数据
    void              *data;          // 接收消息的二进制数据
    uint32_t          data_len;
    void                *ctx;
};

struct mds_node_obj {
    uint32_t id;
    char    ctx[0];
};

struct mds_node_cfg{
    struct vnode_cfg *node;
    int64_t     timeout_ms;
};

int cafs_mds_request(const struct mds_node_obj *mds, struct mds_req_msg *req, struct mds_rsp_msg *rsp, int32_t timeout_ms);
void cafs_mds_put_rsp(struct mds_rsp_msg *rsp);

/*!
 *  @brief  创建一个mds node对象
 *
 *  @param[in]  conf  连接对象
 *  @return  struct connect_obj * 请求消息的操作对象; (<em>NULL</em>: fail ; ( <em>非NULL</em>: succeed
 *
 */
struct mds_node_obj *cafs_create_mds_node(const struct mds_node_cfg *cfg);


/*!
 *  @brief  销毁一个mds node对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_mds_node(struct mds_node_obj *obj);


#ifdef __cplusplus
}
#endif

#endif
