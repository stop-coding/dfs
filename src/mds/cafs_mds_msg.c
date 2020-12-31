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


#include "cafs_mds_msg.h"
#include "cafs_public.h"


#define DEFINE_HANDLE_FUNC(name, MSG_TYPE, op)\
static void *handle_req_##MSG_TYPE##_##op()\
{\
	return FSMSG_GET_OPS(name##_req, MSG_ID_##MSG_TYPE##_REQ_##op);\
}\
static void *handle_rsp_##MSG_TYPE##_##op()\
{\
	return FSMSG_GET_OPS(name##_rsp, MSG_ID_##MSG_TYPE##_RSP_##op);\
}

#define MSG_OP_INIT(MSG_TYPE, op, struct_name, op_name)\
[MSG_OP_TYPE_E_##op] ={\
.req = {MSG_ID_##MSG_TYPE##_REQ_##op, sizeof(CaMdsReq##struct_name), handle_req_##MSG_TYPE##_##op, init_req_##op_name, print_req_##op_name},\
.rsp = {MSG_ID_##MSG_TYPE##_RSP_##op, sizeof(CaMdsRsp##struct_name), handle_rsp_##MSG_TYPE##_##op, init_rsp_##op_name, print_rsp_##op_name}\
}

#define MSG_OP_INIT_NULL(MSG_TYPE, op, struct_name)\
[MSG_OP_TYPE_E_##op] ={\
.req = {MSG_ID_##MSG_TYPE##_REQ_##op, sizeof(CaMdsReq##struct_name), handle_req_##MSG_TYPE##_##op, NULL, NULL},\
.rsp = {MSG_ID_##MSG_TYPE##_RSP_##op, sizeof(CaMdsRsp##struct_name), handle_rsp_##MSG_TYPE##_##op, NULL, NULL}\
}

int cafs_mds_msg_init(struct fsmsg_allocator *ops)
{
    FSMSG_BOX_INIT(ca_mds_req, ops);
	FSMSG_BOX_INIT(ca_mds_rsp, ops);
	FSMSG_BOX_INIT(common, ops);
    return 0;
}

void cafs_mds_msg_exit()
{
    FSMSG_BOX_EXIT(ca_mds_req);
	FSMSG_BOX_EXIT(ca_mds_rsp);
	FSMSG_BOX_EXIT(common);
    return;
}

DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, LOOKUP);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, LOOKUPINO);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, GETATTR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, SETATTR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, OPENDIR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, CLOSEDIR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, MKDIR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, RMDIR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, READDIR);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, CREATE);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, OPEN);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, CLOSE);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, RENAME);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, ALLOC);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, LINK);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, UNLINK);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, SYMLINK);
DEFINE_HANDLE_FUNC(ca_mds, CA_MDS, READLINK);

static struct msg_operater g_op_map[] = {
	MSG_OP_INIT_NULL(CA_MDS, LOOKUP, Lookup),
	MSG_OP_INIT_NULL(CA_MDS, LOOKUPINO, Lookupino),
	MSG_OP_INIT_NULL(CA_MDS, GETATTR, Getattr),
	MSG_OP_INIT_NULL(CA_MDS, SETATTR, Setattr),
	MSG_OP_INIT_NULL(CA_MDS, OPENDIR, Opendir),
	MSG_OP_INIT_NULL(CA_MDS, CLOSEDIR, Closedir),
	MSG_OP_INIT_NULL(CA_MDS, MKDIR, Mkdir),
	MSG_OP_INIT_NULL(CA_MDS, RMDIR, Rmdir),
	MSG_OP_INIT_NULL(CA_MDS, READDIR, Readdir),
	MSG_OP_INIT_NULL(CA_MDS, CREATE, Create),
	MSG_OP_INIT_NULL(CA_MDS, OPEN, Open),
	MSG_OP_INIT_NULL(CA_MDS, CLOSE, Close),
	MSG_OP_INIT_NULL(CA_MDS, RENAME, Rename),
	MSG_OP_INIT_NULL(CA_MDS, ALLOC, Alloc),
	MSG_OP_INIT_NULL(CA_MDS, LINK, Link),
	MSG_OP_INIT_NULL(CA_MDS, UNLINK, Unlink),
	MSG_OP_INIT_NULL(CA_MDS, SYMLINK, Symlink),
	MSG_OP_INIT_NULL(CA_MDS, READLINK, Readlink),
};

const struct msg_operater *cafs_get_msg_op(enum msg_op_type op_id)
{
	if (((uint32_t)op_id >= (uint32_t)(sizeof(g_op_map)/sizeof(struct msg_operater)) || op_id < 0)) {
		return NULL;
	}
	return &g_op_map[op_id];
}
