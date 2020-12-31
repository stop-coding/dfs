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

#include <iostream>

#include "metadata.hpp"

using namespace cafs;
using namespace std;

//fshead;
static const uint64_t default_max_size = 10L*1024*1024*1024; //M

metadata::metadata(const std::string &key, const std::string &raw):m_is_create(false),m_key(key)
{
	m_is_ok = false;
	m_inode = (CommonInode*)fsmsg_decode_new(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), const_cast<char *>(raw.data()), raw.size());
	if (!m_inode) {
		MDS_LOG_ERROR("fsmsg_decode_new fail, raw size:%lu.", raw.size());
		return;
	}
	m_is_ok = true;
}

metadata::metadata(const std::string &key, const uint32_t &pfileid, const uint64_t &ino, const uint32_t &mode):m_is_create(true),m_key(key)
{
	m_is_ok = false;

	m_inode = create_inode(pfileid, ino, mode);
	if (!m_inode) {
		MDS_LOG_ERROR("create_inode fail.");
		return;
	}

	pack_inode(m_inode, m_rawdata);
	m_is_ok = true;
}

metadata::~metadata()
{
	if (m_is_create) {
		destory_inode(m_inode);
		m_inode = NULL;
	} else {
		if (m_inode) {
			fsmsg_decode_delete(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), m_inode);
			m_inode = NULL;
		}
	}
}

void metadata::pack_inode(const CommonInode *inode, string &raw)
{
	uint32_t pbraw_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), const_cast<CommonInode *>(inode), sizeof(CommonInode));
	assert(pbraw_len);

	char *pbraw = (char *)calloc(1, pbraw_len);
	int ret = fsmsg_encode(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), const_cast<CommonInode *>(inode), pbraw);
	assert(!ret);

	raw = move(string(pbraw, pbraw_len));
	free(pbraw);
}

CommonInode *metadata::create_inode(const uint32_t &pfileid, const uint64_t &ino, const uint32_t &mode)
{
	CommonInode *inode = (CommonInode*)calloc(1, sizeof(CommonInode));
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_INODE), inode, sizeof(CommonInode));
	inode->ino = ino;
	inode->snapid = ino;
	inode->mode = mode;
	inode->max_size = default_max_size;
	inode->ctime = (CommonUtime*)calloc(1, sizeof(CommonUtime));
	inode->btime = (CommonUtime*)calloc(1, sizeof(CommonUtime));
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_UTIME), inode->ctime, sizeof(CommonUtime));
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_UTIME), inode->btime, sizeof(CommonUtime));
	if (!S_ISREG(mode)) {
		return inode;
	}
	inode->file = (CommonFile*)calloc(1, sizeof(CommonFile));
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_FILE), inode->file, sizeof(CommonFile));
	inode->file->n_obj = 1;
	inode->file->obj = (CommonObj**)calloc(1, inode->file->n_obj * sizeof(CommonObj *));
	for (uint32_t i = 0; i < inode->file->n_obj; i++) {
		inode->file->obj[i] = (CommonObj*)calloc(1, sizeof(CommonObj));
		fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_OBJ), inode->file->obj[i], sizeof(CommonObj));
		inode->file->obj[i]->cnode_id = pfileid;
		inode->file->obj[i]->obj_id = ino;
		inode->file->obj[i]->obj_max_size = default_max_size;
		inode->file->obj[i]->data_sn = i;
		inode->file->obj[i]->data_size = 0;
		inode->file->obj[i]->data_offset = 0;
	}

	return inode;
}


void metadata::destory_inode(CommonInode *inode)
{
	if(!inode){
		return;
	}
	if(inode->ctime){
		free(inode->ctime);
		inode->ctime = NULL;
	}

	if(inode->btime){
		free(inode->btime);
		inode->btime = NULL;
	}

	if(inode->file){
		for (uint32_t i = 0; i < inode->file->n_obj; i++){
			free(inode->file->obj[i]);
			inode->file->obj[i] = NULL;
		}
		free(inode->file);
		inode->file = NULL;
	}
}


