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

#ifndef _PFILE_DISPATCH_H_
#define _PFILE_DISPATCH_H_

#include "cafs_public.h"
#include "fsmsg.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rx_msg{
	arpc_session_handle_t fd;
	const char *path;
};

typedef union{
    CaPfileReqWrite write;
    CaPfileReqRead read;

}pfile_req_msg_u;

typedef union{
    CaPfileRspWrite write;
    CaPfileRspRead read;
}pfile_rsp_msg_u;

struct dispatch_op{
	uint32_t req_msg_id;
	const char *op_info;
	uint32_t rsp_msg_id;
	int (*rsp_msg)(pfile_req_msg_u *req, struct arpc_vmsg *req_iov, struct rx_msg *ctx);
};

const struct dispatch_op *get_op(uint32_t req_msg_id);

#ifdef __cplusplus
}
#endif

#endif
