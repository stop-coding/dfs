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

#ifndef _CAFS_MDS_MSG_H_
#define _CAFS_MDS_MSG_H_

#include "fsmsg.h"

#ifdef __cplusplus
extern "C" {
#endif

struct msg_base{
	uint32_t msg_id;
	uint32_t msg_len;
    void* (*handle)();
    void (*init)(void *);
    void (*print)(void *);
};

struct msg_operater{
	struct msg_base req;
	struct msg_base rsp;
};

enum msg_op_type{
    MSG_OP_TYPE_E_LOOKUP = 0,
    MSG_OP_TYPE_E_LOOKUPINO,
    MSG_OP_TYPE_E_GETATTR,
    MSG_OP_TYPE_E_SETATTR,
    MSG_OP_TYPE_E_OPENDIR,
    MSG_OP_TYPE_E_CLOSEDIR,
    MSG_OP_TYPE_E_MKDIR,
    MSG_OP_TYPE_E_RMDIR,
    MSG_OP_TYPE_E_READDIR,
    MSG_OP_TYPE_E_CREATE,
    MSG_OP_TYPE_E_OPEN,
    MSG_OP_TYPE_E_CLOSE,
    MSG_OP_TYPE_E_RENAME,
    MSG_OP_TYPE_E_ALLOC,
    MSG_OP_TYPE_E_LINK,
    MSG_OP_TYPE_E_UNLINK,
    MSG_OP_TYPE_E_SYMLINK,
    MSG_OP_TYPE_E_READLINK,
};

typedef union{
    CaMdsReqLookup lookup;
    CaMdsReqLookupino lookupino;
    CaMdsReqGetattr getattr;
    CaMdsReqSetattr setattr;
    CaMdsReqOpendir opendir;
    CaMdsReqClosedir closedir;
    CaMdsReqMkdir   mkdir;
    CaMdsReqRmdir   rmdir;
    CaMdsReqReaddir readdir;
    CaMdsReqCreate  create;
    CaMdsReqOpen    open;
    CaMdsReqClose   close;
    CaMdsReqRename  rename;
    CaMdsReqAlloc   alloc;
    CaMdsReqLink    link;
    CaMdsReqUnlink  unlink;
    CaMdsReqSymlink symlink;
    CaMdsReqReadlink readlink;
    CaMdsReqSetxattr    setxattr;
    CaMdsReqGetxattr    getxattr;
    CaMdsReqRmxattr rmxattr;
    CaMdsReqSetfilelock setfilelock;
    CaMdsReqGetfilelock Getfilelock;
}mds_req_msg_u;

typedef union{
    CaMdsRspLookup lookup;
    CaMdsRspLookupino lookupino;
    CaMdsRspGetattr getattr;
    CaMdsRspSetattr setattr;
    CaMdsRspOpendir opendir;
    CaMdsRspClosedir closedir;
    CaMdsRspMkdir   mkdir;
    CaMdsRspRmdir   rmdir;
    CaMdsRspReaddir readdir;
    CaMdsRspCreate  create;
    CaMdsRspOpen    open;
    CaMdsRspClose   close;
    CaMdsRspRename  rename;
    CaMdsRspAlloc   alloc;
    CaMdsRspLink    link;
    CaMdsRspUnlink  unlink;
    CaMdsRspSymlink symlink;
    CaMdsRspReadlink readlink;
    CaMdsRspSetxattr    setxattr;
    CaMdsRspGetxattr    getxattr;
    CaMdsRspRmxattr rmxattr;
    CaMdsRspSetfilelock setfilelock;
    CaMdsRspGetfilelock Getfilelock;
}mds_rsp_msg_u;

int cafs_mds_msg_init(struct fsmsg_allocator *ops);
void cafs_mds_msg_exit();


const struct msg_operater *cafs_get_msg_op(enum msg_op_type op_id);

#define GET_REQ_HANDLE(op_id) cafs_get_msg_op(op_id)->req.handle()
#define GET_RSP_HANDLE(op_id) cafs_get_msg_op(op_id)->rsp.handle()

#define GET_REQ_MSG_SIZE(op_id) cafs_get_msg_op(op_id)->req.msg_len
#define GET_RSP_MSG_SIZE(op_id) cafs_get_msg_op(op_id)->rsp.msg_len

#define GET_REQ_MSG_ID(op_id) cafs_get_msg_op(op_id)->req.msg_id
#define GET_RSP_MSG_ID(op_id) cafs_get_msg_op(op_id)->rsp.msg_id

#define INIT_REQ_FSMSG(op_id, pmsg)\
fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_req, GET_REQ_MSG_ID(op_id)), pmsg, GET_REQ_MSG_SIZE(op_id));

#define INIT_RSP_FSMSG(op_id, pmsg)\
fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, GET_RSP_MSG_ID(op_id)), pmsg, GET_RSP_MSG_SIZE(op_id));

#define PRINT_REQ_CONTEXT(op_id, data) cafs_get_msg_op(op_id)->req.print(data)
#define PRINT_RSP_CONTEXT(op_id, data) cafs_get_msg_op(op_id)->rsp.print(data)

#define MSG_HEAD_HANDLE FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD)


#ifdef __cplusplus
}
#endif

#endif
