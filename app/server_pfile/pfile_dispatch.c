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
#include <sys/types.h>    
#include <sys/stat.h>
#include <unistd.h>
#include<dirent.h>
#include<errno.h>
#include <fcntl.h>

#include "arpc_api.h"
#include "cafs_public.h"
#include "pfile_dispatch.h"

#define OBJ_DATA_FORMAT "%s/obj_%04lu_%016lu_%04lu.data"
#define OBJ_DATA_MAX_SIZE (10L*1024*1024*1024)

uint32_t init_common_head(void *pri_head, uint32_t pri_head_len, void **out, uint64_t rsp_msg_id)
{
	uint32_t pack_len;
	CommonHead cmo_head;
	CommonHead *header;
	int ret;
	LOG_THEN_RETURN_VAL_IF_TRUE(!pri_head , 0, "pri_head empty.");

	header = &cmo_head;

	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), header, sizeof(CommonHead));
	header->msg_id = rsp_msg_id;
	header->entity = ENTITY_ROLE__PFILE;
	header->entity_id = 10010;
	header->seg_num = 1;
	header->seg_sn = 0;
	header->seg_total = 0;
	header->type = DATA_TYPE__DATA_E_PROTO;
	header->private_id = rsp_msg_id;
	header->private_type = DATA_TYPE__DATA_E_BIN;
	header->private_head.data = (uint8_t*)pri_head;
	header->private_head.len = pri_head_len;
	pack_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), header, sizeof(CommonHead));
	*out = CAFS_ALLOC(pack_len, NULL);
	ret = fsmsg_encode(FSMSG_GET_OPS(common, MSG_ID_COMMON_HEAD), header, *out);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "fsmsg_encode fail.");
	
	return pack_len;
}

static int get_rsp_head(CaPfileRspHead *rsp_head, int32_t ret, uint64_t p_id, uint64_t obj_id)
{
	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_HEAD), rsp_head, sizeof(CaPfileRspHead));
	rsp_head->cnode_id = p_id;
	rsp_head->obj_id = obj_id;
	rsp_head->rsp_result = ret;
	return 0;
}

static uint32_t create_write_common_head(int32_t result, uint64_t p_id, uint64_t obj_id,
										 uint64_t magic, uint64_t seg_sn, uint64_t seg_size, uint64_t seg_num, void **com_head)
{
	CaPfileRspHead	rsp_head;
	void *private_data = NULL;
	uint32_t private_len;
	CaPfileRspWrite _write;
	uint32_t common_head_len;
	int ret;
	// 回复消息
	ret = get_rsp_head(&rsp_head, result, p_id, obj_id);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");
	
	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_WRITE), &_write, sizeof(CaPfileRspWrite));
	_write.head = &rsp_head;
	_write.w_magic = magic;
	_write.w_seg_sn = seg_sn;
	_write.w_seg_size = seg_size;
	_write.w_seg_num = seg_num;

	private_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_WRITE), &_write, sizeof(CaPfileRspWrite));
	LOG_THEN_RETURN_VAL_IF_TRUE(!private_len, 0, "fsmsg_get_encoded_size  is 0.");
	private_data = CAFS_ALLOC(private_len, NULL);

	ret = fsmsg_encode(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_WRITE), &_write, private_data);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "fsmsg_encode fail.");

	common_head_len = init_common_head(private_data, private_len, com_head, MSG_ID_CA_PFILE_RSP_WRITE);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!common_head_len, free_buf, "common_head_len  is 0.");

	SAFE_CAFS_FREE(private_data);
	return common_head_len;
free_buf:
	SAFE_CAFS_FREE(private_data);
	return 0;
}

static int rsp_write(pfile_req_msg_u *req, struct arpc_vmsg *req_iov,  struct rx_msg *ctx)
{
	uint32_t buf_len = 0;
	struct arpc_vmsg vmsg_iov;
	int ret;
	int fd;
	uint32_t i;
	char obj_file[1024] = {0};

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !req_iov || !ctx), 0, "invalid input parameter.");
	
	CAFS_LOG_NOTICE("----------------WRITE REQ-----------------------.");
	CAFS_LOG_NOTICE("cnode_id:%lu.", req->write.head->cnode_id);
	CAFS_LOG_NOTICE("obj_id:%lu.", req->write.head->obj_id);

	CAFS_LOG_NOTICE("w_magic:%lu.", req->write.w_magic);
	CAFS_LOG_NOTICE("w_offset:%lu.", req->write.w_offset);
	CAFS_LOG_NOTICE("w_seg_size:%lu.", req->write.w_seg_size);
	CAFS_LOG_NOTICE("w_seg_num:%lu.", req->write.w_seg_num);
	CAFS_LOG_NOTICE("w_seg_sn:%lu.", req->write.w_seg_sn);

	// 写文件
	sprintf(obj_file, OBJ_DATA_FORMAT, 
			ctx->path, 
			req->write.head->cnode_id, 
			req->write.head->obj_id, 
			(req->write.w_offset/OBJ_DATA_MAX_SIZE));
	if (req->write.w_offset == 0 
		&& req->write.w_seg_num == 1 
		&& req_iov->vec_num == 1
		&& req_iov->vec[0].len == 1
		&& ((char *)req_iov->vec[0].data)[0] == 32) {
		unlink(obj_file);
		buf_len = 0;//todo删除分段数据
		CAFS_LOG_NOTICE("unlink obj:%s.", obj_file);
	}else{
		fd = open(obj_file, O_CREAT|O_RDWR, 0777);
		LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, -1, "open[%s] fail.", obj_file);
		lseek(fd, req->write.w_offset, SEEK_SET);
		CAFS_LOG_NOTICE("write vec_num:%u.", req_iov->vec_num);
		for(i = 0; i < req_iov->vec_num; i++){
			write(fd, req_iov->vec[i].data, req_iov->vec[i].len);
			lseek(fd, 0, SEEK_END);
			buf_len += req_iov->vec[i].len;
		}
		close(fd);
	}
	
	CAFS_LOG_NOTICE("write len:%u, thread:%lu.", buf_len, (uint64_t)pthread_self());
	if(req->write.w_seg_num > req->write.w_seg_sn + 1 ) {
		return 0;
	}
	memset(&vmsg_iov, 0, sizeof(vmsg_iov));
	vmsg_iov.head_len = create_write_common_head(0, req->write.head->cnode_id, req->write.head->obj_id,
												 req->write.w_magic, req->write.w_seg_sn,
												 buf_len,req->write.w_seg_num, &vmsg_iov.head);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!vmsg_iov.head_len, free, "vmsg_iov.head_len  is 0.");
	vmsg_iov.total_data = 0;
	ret = arpc_send_oneway_msg(ctx->fd, &vmsg_iov, NULL, NULL);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "arpc_send_oneway_msg fail.");

	SAFE_CAFS_FREE(vmsg_iov.head);
	CAFS_LOG_NOTICE("write arpc_send_oneway_msg end!!!");
	return 0;

free:
	SAFE_CAFS_FREE(vmsg_iov.head);
	return 0;
}

static uint32_t create_read_common_head(int32_t result, uint64_t p_id, uint64_t obj_id, 
									uint64_t magic, uint64_t offset,uint64_t seg_sn, uint64_t seg_size, uint64_t seg_num, void **com_head)
{
	CaPfileRspHead	rsp_head;
	void *private_data = NULL;
	uint32_t private_len;
	CaPfileRspRead _read;
	uint32_t common_head_len;
	int ret;
	// 回复消息
	ret = get_rsp_head(&rsp_head, result, p_id, obj_id);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");
	
	fsmsg_encode_init(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_READ), &_read, sizeof(CaPfileRspRead));
	_read.head = &rsp_head;
	_read.r_magic = magic;
	_read.r_offset = offset;
	_read.r_seg_sn = seg_sn;
	_read.r_seg_size = seg_size;
	_read.r_seg_num = seg_num;

	private_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_READ), &_read, sizeof(CaPfileRspRead));
	LOG_THEN_RETURN_VAL_IF_TRUE(!private_len, 0, "fsmsg_get_encoded_size  is 0.");
	private_data = CAFS_ALLOC(private_len, NULL);

	ret = fsmsg_encode(FSMSG_GET_OPS(ca_pfile_rsp, MSG_ID_CA_PFILE_RSP_READ), &_read, private_data);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free_buf, "fsmsg_encode fail.");

	common_head_len = init_common_head(private_data, private_len, com_head, MSG_ID_CA_PFILE_RSP_READ);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!common_head_len, free_buf, "common_head_len  is 0.");

	SAFE_CAFS_FREE(private_data);
	return common_head_len;
free_buf:
	SAFE_CAFS_FREE(private_data);
	return 0;
}

static int rsp_read(pfile_req_msg_u *req, struct arpc_vmsg *req_iov,  struct rx_msg *ctx)
{
	uint64_t obj_read_size = 0;
	struct arpc_vmsg vmsg_iov;
	uint32_t send_len;
	int ret;
	int fd;
	uint32_t i, k;
	uint32_t read_len = 0;
	uint32_t seg_num;
	uint64_t r_offset;
	uint32_t last_size = 0, vec_last_size = 0;

	char obj_file[1024] = {0};
	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !req_iov|| !ctx), 0, "invalid input parameter.");
	
	CAFS_LOG_NOTICE("----------------READ REQ-----------------------.");
	CAFS_LOG_NOTICE("cnode_id:%lu.", req->read.head->cnode_id);
	CAFS_LOG_NOTICE("obj_id:%lu.", req->read.head->obj_id);

	CAFS_LOG_NOTICE("r_magic:%lu.", req->read.r_magic);
	CAFS_LOG_NOTICE("r_offset:%lu.", req->read.r_offset);
	CAFS_LOG_NOTICE("r_seg_max_num:%lu.", req->read.r_seg_max_num);
	CAFS_LOG_NOTICE("r_seg_max_size:%lu.", req->read.r_seg_max_size);
	CAFS_LOG_NOTICE("r_size:%lu.", req->read.r_size);

	// 读文件
	sprintf(obj_file, OBJ_DATA_FORMAT,
			ctx->path, 
			req->read.head->cnode_id, 
			req->read.head->obj_id, 
			(req->read.r_offset/OBJ_DATA_MAX_SIZE));

	fd = open(obj_file, O_RDONLY);
	LOG_THEN_RETURN_VAL_IF_TRUE(fd < 0, -1, "open obj_file[%s] fail.", obj_file);

	obj_read_size = lseek(fd, 0, SEEK_END);

	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(obj_read_size < req->read.r_offset, free_buf, "open obj_file[%s] fail.", obj_file);

	obj_read_size = obj_read_size - req->read.r_offset;
	req->read.r_size = (req->read.r_size < obj_read_size) ?req->read.r_size:obj_read_size;

	r_offset = req->read.r_offset;
	lseek(fd, req->read.r_offset, SEEK_SET);

	last_size = req->read.r_size%DATA_DEFAULT_MAX_LEN;
	seg_num = (last_size)? 1: 0;
	seg_num += req->read.r_size/DATA_DEFAULT_MAX_LEN;
	last_size = (last_size)?last_size:DATA_DEFAULT_MAX_LEN;
	// 发送
	for (k = 0 ; k < seg_num; k++) {
		send_len = (k == (seg_num -1))? last_size:DATA_DEFAULT_MAX_LEN;
		memset(&vmsg_iov, 0 , sizeof(vmsg_iov));
		vmsg_iov.head_len = create_read_common_head(0, req->read.head->cnode_id, req->read.head->obj_id,
													req->read.r_magic, r_offset, k, send_len, seg_num, &vmsg_iov.head);
		CAFS_LOG_NOTICE("rsp r_magic:%lu.", req->read.r_magic);
		CAFS_LOG_NOTICE("rsp r_offset:%lu.", r_offset);
		CAFS_LOG_NOTICE("rsp seg_num:%lu.", seg_num);
		CAFS_LOG_NOTICE("rsp send_len:%lu.", send_len);

		vmsg_iov.total_data = send_len;
		CAFS_LOG_DEBUG("************read - rsp total_data:%lu", vmsg_iov.total_data);
		vec_last_size = send_len%IOV_DEFAULT_MAX_LEN;
		vmsg_iov.vec_num = (vec_last_size)?1:0;
		vmsg_iov.vec_num += (send_len / IOV_DEFAULT_MAX_LEN);
		CAFS_LOG_DEBUG("************read - rsp vec_num:%u", vmsg_iov.vec_num);
		vmsg_iov.vec = (struct arpc_iov*)malloc(vmsg_iov.vec_num * sizeof(struct arpc_iov));
		vec_last_size = (vec_last_size)?vec_last_size:IOV_DEFAULT_MAX_LEN;
		for (i = 0; i  < vmsg_iov.vec_num; i++) {
			vmsg_iov.vec[i].len = (i == vmsg_iov.vec_num -1)? vec_last_size:IOV_DEFAULT_MAX_LEN;
			vmsg_iov.vec[i].data = malloc(vmsg_iov.vec[i].len);
			vmsg_iov.vec[i].len = read(fd, vmsg_iov.vec[i].data, vmsg_iov.vec[i].len);
			CAFS_LOG_DEBUG("************read - len:%lu", vmsg_iov.vec[i].len);
		}
	
		ret = arpc_send_oneway_msg(ctx->fd, &vmsg_iov, NULL, NULL);
		if (ret != 0){
			CAFS_LOG_ERROR("arpc_send_oneway_msg fail");
		}
		r_offset +=send_len;
		read_len += send_len;
		CAFS_LOG_DEBUG("already read size[%u], expact read size[%lu]", read_len, req->read.r_size);
		// 释放资源
		for (i = 0; i < vmsg_iov.vec_num; i++) {
			SAFE_CAFS_FREE(vmsg_iov.vec[i].data);
		}
		SAFE_CAFS_FREE(vmsg_iov.vec);
	}

	close(fd);

	return 0;
free_buf:
	close(fd);
	return -1;

}


static struct dispatch_op g_map[] = {
	{MSG_ID_CA_PFILE_REQ_WRITE, "rsp_write", MSG_ID_CA_PFILE_RSP_WRITE, rsp_write},
	{MSG_ID_CA_PFILE_REQ_READ, "rsp_read", MSG_ID_CA_PFILE_RSP_READ, rsp_read},
};

const struct dispatch_op *get_op(uint32_t req_msg_id)
{
	uint32_t i;
	uint32_t loop_num = (uint32_t)(sizeof(g_map)/sizeof(struct dispatch_op));
	for ( i = 0; i < loop_num; i++) {
		if (g_map[i].req_msg_id == req_msg_id) {
			return &g_map[i];
		}
	}
	return NULL;
}


