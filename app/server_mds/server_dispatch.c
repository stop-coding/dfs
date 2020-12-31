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

#include "cafs_public.h"
#include "server_dispatch.h"

using namespace cafs;
using namespace std;

static int get_rsp_head(CaMdsRspHead *rsp_head)
{
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_HEAD), rsp_head, sizeof(CaMdsRspHead));
	rsp_head->rsp_result = 0;
	rsp_head->flags = 520;
	return 0;
}

static uint32_t rsp_getattr(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspGetattr getattr;
	uint32_t buf_len = 0;
	int ret;
	CommonInode 	*pinode;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	const metadata *fd = db->get(req->lookup.head->file_path);
	if (!fd) {
		MDS_LOG_ERROR(" file path[%s] not existd.", req->lookup.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		pinode = NULL;
	}else{
		pinode = const_cast<CommonInode *> (&(fd->inode()));
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_GETATTR), &getattr, sizeof(CaMdsRspGetattr));
	getattr.head = &rsp_head;
	getattr.inode = pinode;
	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_GETATTR), &getattr, sizeof(CaMdsRspGetattr));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_GETATTR), &getattr, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_lookup(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspLookup lookup;
	uint32_t buf_len = 0;
	int ret;
	CommonInode 	*pinode;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	MDS_LOG_NOTICE("lookup path: %s ", req->lookup.head->file_path);

	const metadata *fd = db->get(req->lookup.head->file_path);
	if (!fd) {
		MDS_LOG_ERROR(" file path[%s] not existd.", req->lookup.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		pinode = NULL;
	}else{
		pinode = const_cast<CommonInode *> (&(fd->inode()));
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_LOOKUP), &lookup, sizeof(CaMdsRspLookup));
	lookup.head = &rsp_head;
	lookup.inode = pinode;
	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_LOOKUP), &lookup, sizeof(CaMdsRspLookup));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_LOOKUP), &lookup, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_opendir(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CommonDentry 	parent;
	char parent_name[] = "..";
	CommonDentry 	self;
	char self_name[] = ".";
	uint64_t dentry_num = 0;
	CaMdsRspOpendir p_opendir;
	uint32_t buf_len = 0;
	int ret;
	Cdir *dir;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_DENTRY), &parent, sizeof(CommonDentry));
	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_DENTRY), &self, sizeof(CommonDentry));

	const metadata *fd = db->get(req->opendir.head->file_path);
	if (!fd || !fd->is_dir()) {
		MDS_LOG_ERROR(" file path[%s] not existd.", req->opendir.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		goto rsp;
	}
	
	MDS_LOG_NOTICE("open dir path: %s ", req->opendir.head->file_path);

	dir = db->opendir(req->opendir.head->file_path);
	if (dir) {
		dentry_num = dir->num();
		parent.offset = dir->parent().offset();
		parent.name = parent_name;
		parent.ino = dir->parent().ino();
		parent.mode = DTTOIF(dir->parent().mode());
		MDS_LOG_NOTICE("d_name : %s, ino:%lu", dir->parent().name().c_str(), parent.ino);

		self.offset = dir->self().offset();
		self.name = self_name;
		self.ino = dir->self().ino();
		self.mode = DTTOIF(dir->self().mode());
	}else{
		rsp_head.rsp_result = -ENOENT;
	}
	
rsp:
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_OPENDIR), &p_opendir, sizeof(CaMdsRspOpendir));
	p_opendir.head = &rsp_head;
	p_opendir.parent = &parent;
	p_opendir.self = &self;
	p_opendir.dentry_num = dentry_num;

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_OPENDIR), &p_opendir, sizeof(CaMdsRspOpendir));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_OPENDIR), &p_opendir, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_closedir(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspClosedir p_closedir;
	uint32_t buf_len = 0;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");
	
	const metadata *fd = db->get(req->closedir.head->file_path);
	if (!fd || !fd->is_dir()) {
		MDS_LOG_ERROR(" file path[%s] not existd.", req->closedir.head->file_path);
		rsp_head.rsp_result = -ENOENT;
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CLOSEDIR), &p_closedir, sizeof(CaMdsRspClosedir));
	p_closedir.head = &rsp_head;

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CLOSEDIR), &p_closedir, sizeof(CaMdsRspClosedir));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CLOSEDIR), &p_closedir, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_readdir(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CommonDentry 	**ppdentry = NULL;
	uint32_t i = 0;
	CaMdsRspReaddir p_readdir;
	uint32_t buf_len = 0;
	int ret;
	Cdir* dir_p;
	std::vector<Cdentry> dns;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	MDS_LOG_NOTICE("open dir path: %s ", req->readdir.head->file_path);
	dir_p = db->opendir(req->opendir.head->file_path);
	if (!dir_p) {
		MDS_LOG_ERROR(" file path[%s] is not dir.", req->opendir.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		goto rsp;
	}

	MDS_LOG_NOTICE("max_entries:%u", req->readdir.max_entries);
	dns = dir_p->childs(0, req->readdir.max_entries);
	if (!dns.size()) {
		MDS_LOG_ERROR(" open path[%s] dentry is empty.", req->opendir.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		goto rsp;
	}
	ppdentry = (CommonDentry**)CAFS_ALLOC(dns.size() * sizeof(CommonDentry *), NULL);

	for (auto &iter:dns) {
		ppdentry[i] = (CommonDentry*)CAFS_ALLOC(sizeof(CommonDentry), NULL);
		fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_DENTRY), ppdentry[i], sizeof(CommonDentry));
		ppdentry[i]->ino = iter.ino();
		ppdentry[i]->mode = DTTOIF(iter.mode());
		ppdentry[i]->offset = iter.offset();
		ppdentry[i]->name = const_cast<char *>(iter.name().c_str());
		MDS_LOG_NOTICE("d_name : %s, ino:%lu, offset:%u", ppdentry[i]->name, ppdentry[i]->ino, ppdentry[i]->offset);
		i++;
	}
rsp:	
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_READDIR), &p_readdir, sizeof(CaMdsRspReaddir));
	p_readdir.head = &rsp_head;
	p_readdir.dentry = ppdentry;
	p_readdir.n_dentry = i;
	MDS_LOG_NOTICE("dentry_num:%lu", p_readdir.n_dentry);

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_READDIR), &p_readdir, sizeof(CaMdsRspReaddir));
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!buf_len, free, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_READDIR), &p_readdir, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");

	for (i = 0; i < p_readdir.n_dentry; i++) {
		SAFE_CAFS_FREE(p_readdir.dentry[i]);
	}
	SAFE_CAFS_FREE(ppdentry);

	return buf_len;
free:
	if (ppdentry) {
		for (i = 0; i < dns.size(); i++) {
			SAFE_CAFS_FREE(ppdentry[i]);
		}
	}
	SAFE_CAFS_FREE(ppdentry);

	SAFE_CAFS_FREE(*buf);

	return 0;
}

static uint32_t rsp_mkdir(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CommonDentry 	self;
	CaMdsRspMkdir p_mkdir;
	uint32_t buf_len = 0;
	int ret;
	metadata *meta_dir;
	Cdir *newdir;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	fsmsg_encode_init(FSMSG_GET_OPS(common, MSG_ID_COMMON_DENTRY), &self, sizeof(CommonDentry));

	meta_dir = db->mkdir(req->mkdir.head->file_path, 0777);
	if (!meta_dir) {
		MDS_LOG_ERROR(" file path[%s] is not dir.", req->mkdir.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		goto rsp;
	}

	newdir = db->opendir(req->mkdir.head->file_path);
	if (!newdir) {
		MDS_LOG_ERROR(" file path[%s] is not dir.", req->mkdir.head->file_path);
		rsp_head.rsp_result = -ENOENT;
		goto rsp;
	}
	self.offset = newdir->self().offset();
	self.ino = newdir->self().ino();
	self.mode = DTTOIF(newdir->self().mode());
	self.name = const_cast<char *>(newdir->self().name().c_str());
rsp:
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_MKDIR), &p_mkdir, sizeof(CaMdsRspMkdir));
	p_mkdir.head = &rsp_head;
	p_mkdir.self = &self;

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_MKDIR), &p_mkdir, sizeof(CaMdsRspMkdir));
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!buf_len, free, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_MKDIR), &p_mkdir, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");

	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_rmdir(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspRmdir p_rmdir;
	uint32_t buf_len = 0;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");
	db->rmdir(req->rmdir.head->file_path);
	
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_RMDIR), &p_rmdir, sizeof(CaMdsRspRmdir));
	p_rmdir.head = &rsp_head;

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_RMDIR), &p_rmdir, sizeof(CaMdsRspRmdir));
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!buf_len, free, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_RMDIR), &p_rmdir, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");

	return buf_len;
free:

	SAFE_CAFS_FREE(*buf);
	
	return 0;
}

static uint32_t rsp_create(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CommonInode 	*pinode = NULL;
	CaMdsRspCreate create;
	uint32_t buf_len = 0;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	const metadata *fd = db->get(req->create.head->file_path);
	if (!fd) {
		fd = db->create(req->create.head->file_path, req->create.mode);
		if (!fd) {
			MDS_LOG_ERROR(" file path[%s] create fail.", req->create.head->file_path);
			pinode = NULL;
			rsp_head.rsp_result = -ENOENT;
		}else{
			pinode = const_cast<CommonInode *> (&(fd->inode()));
		}
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CREATE), &create, sizeof(CaMdsRspCreate));
	create.head = &rsp_head;
	create.inode = pinode;
	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CREATE), &create, sizeof(CaMdsRspCreate));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CREATE), &create, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_open(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspOpen open;
	uint32_t buf_len = 0;
	int ret;
	CommonInode 	*pinode;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	const metadata *fd = db->get(req->open.head->file_path);
	if (!fd) {
		rsp_head.rsp_result = -ENOENT;
		pinode = NULL;
	}else{
		pinode = const_cast<CommonInode *> (&(fd->inode()));
	}
	
	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_OPEN), &open, sizeof(CaMdsRspOpen));
	open.head = &rsp_head;
	open.inode = pinode;
	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_OPEN), &open, sizeof(CaMdsRspOpen));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_OPEN), &open, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_close(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspClose close;
	uint32_t buf_len = 0;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");
	const metadata *fd = db->get(req->close.head->file_path);
	if (!fd) {
		rsp_head.rsp_result = -ENOENT;
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CLOSE), &close, sizeof(CaMdsRspClose));
	close.head = &rsp_head;
	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CLOSE), &close, sizeof(CaMdsRspClose));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_CLOSE), &close, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_alloc(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspAlloc alloc;
	uint32_t buf_len = 0;
	int ret;
	CommonInode 	*pinode;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	const metadata *fd = db->modify(req->alloc.head->file_path, req->alloc.size);
	if (!fd) {
		rsp_head.rsp_result = -ENOENT;
		pinode = NULL;
	}else{
		pinode = const_cast<CommonInode *> (&(fd->inode()));
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_ALLOC), &alloc, sizeof(CaMdsRspAlloc));
	alloc.head = &rsp_head;
	alloc.inode = pinode;

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_ALLOC), &alloc, sizeof(CaMdsRspAlloc));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_ALLOC), &alloc, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}

static uint32_t rsp_setattr(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspSetattr setattr;
	uint32_t buf_len = 0;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	const metadata *fd = db->modify(req->setattr.head->file_path, req->setattr.size);
	if (!fd) {
		rsp_head.rsp_result = -ENOENT;
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_SETATTR), &setattr, sizeof(CaMdsRspSetattr));
	setattr.head = &rsp_head;

	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_SETATTR), &setattr, sizeof(CaMdsRspSetattr));
	LOG_THEN_RETURN_VAL_IF_TRUE(!buf_len, 0, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_SETATTR), &setattr, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");
	return buf_len;
free:
	SAFE_CAFS_FREE(*buf);
	return 0;
}
static uint32_t rsp_unlink(mds_req_msg_u *req, void **buf, fsdb *db)
{
	CaMdsRspHead	rsp_head;
	CaMdsRspUnlink p_unlink;
	uint32_t buf_len = 0;
	int ret;

	LOG_THEN_RETURN_VAL_IF_TRUE((!req || !buf), 0, "invalid input parameter.");

	ret = get_rsp_head(&rsp_head);
	LOG_THEN_RETURN_VAL_IF_TRUE(ret, 0, "get_rsp_head fail.");

	const metadata *fd = db->get(req->unlink.head->file_path);
	if (fd) {
		db->unlink(req->unlink.head->file_path);
	}else{
		rsp_head.rsp_result = -ENOENT;
	}

	fsmsg_encode_init(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_UNLINK), &p_unlink, sizeof(CaMdsRspUnlink));
	p_unlink.head = &rsp_head;
	
	buf_len = fsmsg_get_encoded_size(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_UNLINK), &p_unlink, sizeof(CaMdsRspUnlink));
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!buf_len, free, "fsmsg_get_encoded_size  is 0.");
	*buf = CAFS_ALLOC(buf_len, NULL);
	// 编码
	ret = fsmsg_encode(FSMSG_GET_OPS(ca_mds_rsp, MSG_ID_CA_MDS_RSP_UNLINK), &p_unlink, *buf);
	LOG_THEN_GOTO_TAG_IF_VAL_TRUE(ret, free, "fsmsg_encode fail.");

	return buf_len;
free:

	SAFE_CAFS_FREE(*buf);
	
	return 0;
}

static struct dispatch_op g_map[] = {
	{MSG_ID_CA_MDS_REQ_GETATTR, "rsp_getattr", MSG_ID_CA_MDS_RSP_GETATTR, rsp_getattr},
	{MSG_ID_CA_MDS_REQ_LOOKUP, "print_lookup", MSG_ID_CA_MDS_RSP_LOOKUP, rsp_lookup},
	{MSG_ID_CA_MDS_REQ_OPENDIR, "rsp_opendir", MSG_ID_CA_MDS_RSP_OPENDIR, rsp_opendir},
	{MSG_ID_CA_MDS_REQ_CLOSEDIR, "rsp_closedir", MSG_ID_CA_MDS_RSP_CLOSEDIR, rsp_closedir},
	{MSG_ID_CA_MDS_REQ_READDIR, "rsp_readdir", MSG_ID_CA_MDS_RSP_READDIR, rsp_readdir},
	{MSG_ID_CA_MDS_REQ_MKDIR, "rsp_mkdir", MSG_ID_CA_MDS_RSP_MKDIR, rsp_mkdir},
	{MSG_ID_CA_MDS_REQ_RMDIR, "rsp_rmdir", MSG_ID_CA_MDS_RSP_RMDIR, rsp_rmdir},
	{MSG_ID_CA_MDS_REQ_CREATE, "rsp_create", MSG_ID_CA_MDS_RSP_CREATE, rsp_create},
	{MSG_ID_CA_MDS_REQ_OPEN, "rsp_open", MSG_ID_CA_MDS_RSP_OPEN, rsp_open},
	{MSG_ID_CA_MDS_REQ_CLOSE, "rsp_close", MSG_ID_CA_MDS_RSP_CLOSE, rsp_close},
	{MSG_ID_CA_MDS_REQ_ALLOC, "rsp_alloc", MSG_ID_CA_MDS_RSP_ALLOC, rsp_alloc},
	{MSG_ID_CA_MDS_REQ_SETATTR, "rsp_setattr", MSG_ID_CA_MDS_RSP_SETATTR, rsp_setattr},
	{MSG_ID_CA_MDS_REQ_UNLINK, "rsp_unlink", MSG_ID_CA_MDS_RSP_UNLINK, rsp_unlink},
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


