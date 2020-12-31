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

#ifndef _CAFS_CONNECT_H_
#define _CAFS_CONNECT_H_

#include "cafs_public.h"
#include "queue.h"
#include "arpc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*  @brief  请求阻塞等待直到收到回复 */
#define REQ_WAIT_FOREVER  -1

#define MAX_ONEWAY_MSG_LIMIT    (100)

struct iovec {                    
	void  *iov_base;             
	size_t iov_len;
};

#define CAFS_IOV_NUM  4
enum cafs_vec_type{
    CAFS_VEC_E_NULL = 0,
    CAFS_VEC_E_IOV,
    CAFS_VEC_E_PTR,
};

struct cafs_vmsg {
    QUEUE           q;
    void			*head;
    uint32_t		head_len;
    uint32_t 		vec_num; // 4
    enum cafs_vec_type   type;
    union 
    {
        struct iovec    vec[CAFS_IOV_NUM];
        struct iovec    *vecptr;
    };
};

#define get_cafsvmsg_vec(vmsg)\
(vmsg->type == CAFS_VEC_E_IOV)?vmsg->vec:((vmsg->type == CAFS_VEC_E_PTR)?vmsg->vecptr:NULL);

struct cafs_request_msg {
    struct cafs_vmsg req;
    struct cafs_vmsg rsp;
    char ctx[0];
};

struct connect_init_param {
    int     connect_id;
    int     thread_max_num;
};

struct cafs_connect_cfg {
    const char *entity_addr;
    int32_t   port;
    uint16_t  conn_num;
    uint16_t  rx_con_num;
    uint64_t  msg_data_max_len;
    uint32_t  msg_head_max_len;
    uint32_t  msg_iov_max_len;
    int64_t   timeout_ms;
    int (*rx_oneway_cb)(struct cafs_vmsg *vmsg, void *usr_ctx);
    void *usr_ctx;
};


struct connect_obj {
    uint64_t connect_id;
    char     private[0];
};

/*!
 *  @brief  初始化连接模块
 *
 *  @param[in]  p  初始化参数
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_connect_init(struct connect_init_param *p);

/*!
 *  @brief  关闭连接模块
 *
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_connect_shutdown();


/*!
 *  @brief  创建一个消息连接对象
 *
 *  @param[in]  conf  连接对象
 *  @return  struct connect_obj * 请求消息的操作对象; (<em>NULL</em>: fail ; ( <em>非NULL</em>: succeed
 *
 */
struct connect_obj *cafs_create_connect_obj(const struct cafs_connect_cfg *conf);


/*!
 *  @brief  销毁一个连接对象
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_destroy_connect_obj(struct connect_obj *obj);

/*!
 *  @brief  打印链路信息
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
void cafs_connect_obj_status(struct connect_obj *obj);

/*!
 *  @brief  打印链路信息
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_connect_islive(struct connect_obj *obj);


/*!
 *  @brief  打印链路信息
 *
 *  @param[in]  obj  请求消息的操作对象
 *  @return  int; (<em>-1</em>: fail ; ( <em> 0 </em>: succeed
 *
 */
int cafs_connect_restart(const struct connect_obj *obj);

/*!
 *  @brief  请求一个消息获取回复
 *
 *  @param[in]  obj          请求消息的操作对象
 *  @param[in] timeout_ms    请求等待超时时间，-1阻塞等待，0不等待，消息回复时，可以通过cafs_get_mds_rsp获取。
 *  @param[inout] req        请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_do_request(const struct connect_obj *obj, struct cafs_request_msg *req, int32_t timeout_ms);

/*!
 *  @brief  获取回复消息
 *
 *  @param[in]  obj                 请求消息的操作对象
 *  @param[inout] req               请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail 不存在回复消息; ( <em>0</em>: succeed
 *
 */
struct cafs_request_msg *cafs_new_request();

/*!
 *  @brief 释放回复
 *
 *  @param[in]  obj                 请求消息的操作对象
 *  @param[inout] req               请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail 不存在回复消息; ( <em>0</em>: succeed
 *
 */
void cafs_delete_request(struct cafs_request_msg *req);

/*!
 *  @brief 释放回复
 *
 *  @param[in]  obj                 请求消息的操作对象
 *  @param[inout] req               请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail 不存在回复消息; ( <em>0</em>: succeed
 *
 */
void cafs_reset_request(struct cafs_request_msg *req);

/*!
 *  @brief  发送一个oneway_msg
 *
 *  @param[in]  obj          请求消息的操作对象
 *  @param[in] timeout_ms    请求等待超时时间，-1阻塞等待，0不等待，消息回复时，可以通过cafs_get_mds_rsp获取。
 *  @param[inout] req        请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_send_oneway(const struct connect_obj *obj, struct cafs_vmsg *in);

/*!
 *  @brief  释放一个oneway_msg
 *
 *  @param[in]  obj          请求消息的操作对象
 *  @param[in] timeout_ms    请求等待超时时间，-1阻塞等待，0不等待，消息回复时，可以通过cafs_get_mds_rsp获取。
 *  @param[inout] req        请求参数输入和回复参数输出
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int cafs_put_oneway_vmsg(struct cafs_vmsg *oneway);

#ifdef __cplusplus
}
#endif

#endif
