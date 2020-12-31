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

#ifndef _CAFS_CONFIG_H_
#define _CAFS_CONFIG_H_

#include "cafs_public.h"

#ifdef __cplusplus
extern "C" {
#endif

//
#define DEFAULT_THREAD_MAX_NUM      10

#define DEFAULT_MDS_CONNECTION      2
#define DEFAULT_MDS_RX_CONN         0

#define DEFAULT_PFILE_CONNECTION    2
#define DEFAULT_PFILE_RX_CONN       0

struct cafs_prt_cfg {
    uint32_t prt_id;
    uint32_t vmds_id;
    uint32_t subtree_id;
};

// arpc node 配置
struct vnode_cfg {
    uint32_t id;
    char    addr[16];
    int32_t port;
    char    *uri;
    uint16_t  connection;
    uint64_t  msg_data_max_len;
    uint32_t  msg_head_max_len;
    uint32_t  msg_iov_max_len;
};

struct cafs_cfg_obj;
struct cafs_cfg_ops {
  int (*get_prt)(const struct cafs_cfg_obj *cfg, const char *path, struct cafs_prt_cfg *prt);
  int (*get_mds_on_vmds)(const struct cafs_cfg_obj *cfg, uint32_t vmds_id, struct vnode_cfg *mds);
  int (*get_mds)(const struct cafs_cfg_obj *cfg, const char *path, struct vnode_cfg *mds);
  int (*get_pfile)(const struct cafs_cfg_obj *cfg, const uint32_t pfile_id, struct vnode_cfg *pfile);
};


struct cafs_cfg_obj {
    uint32_t fs_id;
    uint64_t usr_id;
    uint64_t thread_num;
    struct cafs_cfg_ops *ops;
    char      cfg_ctx[0];
};

struct cafs_cfg_obj *create_cfg_obj(const char *cfg_path);
int destroy_cfg_obj(struct cafs_cfg_obj *cfg);

#ifdef __cplusplus
}
#endif

#endif
