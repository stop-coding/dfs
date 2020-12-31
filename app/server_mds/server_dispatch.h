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

#ifndef _SERVER_DISPATCH_H_
#define _SERVER_DISPATCH_H_

#include "mds_log.h"
#include "cafs_public.h"
#include "cafs_mds_msg.h"
#include "fsmsg.h"
#include "fsdb.hpp"

#ifdef __cplusplus
extern "C" {
#endif

struct dispatch_op{
	uint32_t req_msg_id;
	const char *op_info;
	uint32_t rsp_msg_id;
	uint32_t (*rsp_msg)(mds_req_msg_u *req, void **buf, cafs::fsdb *db);
};

const struct dispatch_op *get_op(uint32_t req_msg_id);

#ifdef __cplusplus
}
#endif

#endif
