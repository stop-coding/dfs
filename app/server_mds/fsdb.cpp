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
#include <regex>

#include "fsdb.hpp"

using namespace cafs;
using namespace std;
using namespace ROCKSDB_NAMESPACE;

//fshead;
static const char *FS_ROOT =".cafs_root";
static const char *FS_VOLUME =".cafs_volume";
static const char *FS_INO =".cafs_ino";
static const char *FS_USED =".cafs_used";

fsdb::fsdb(const std::string &db_path, const std::string &root_dir, uint64_t volume):
		  m_root(root_dir),
		  m_ino(1),
		  m_used_size(0),
		  m_sync_thread(nullptr)
{
	DB *pdb = nullptr;
	m_is_ok = false;
	Options options;
	options.IncreaseParallelism();
  	options.OptimizeLevelStyleCompaction();
	options.create_if_missing = true;
	Status status = DB::Open(options, db_path, &pdb);
	if (!status.ok() || !pdb) {
		MDS_LOG_ERROR("open db file[%s] fail.", db_path.c_str());
		return;
	}
	m_db.reset(pdb);

	std::string value;

	status = pdb->Get(ReadOptions(), FS_ROOT, &value);
	if (!status.ok()) {
		status = pdb->Put(WriteOptions(), FS_ROOT, m_root);
		assert(status.ok());
	}
	m_root = value;
	value.clear();
  	status = pdb->Get(ReadOptions(), FS_VOLUME, &value);
	if (!status.ok()) {
		value = std::move(to_string(volume));
		status = pdb->Put(WriteOptions(), FS_VOLUME, value);
		assert(status.ok());
	}
	m_volume = std::stoull(value);

	value.clear();
	status = pdb->Get(ReadOptions(), FS_INO, &value);
	if (!status.ok()) {
		value = "1";
		status = pdb->Put(WriteOptions(), FS_INO, value);
		assert(status.ok());
	}

	m_ino = std::stoull(value);

	status = pdb->Get(ReadOptions(), FS_USED, &value);
	if (!status.ok()) {
		value = "0";
		status = pdb->Put(WriteOptions(), FS_USED, "0");
		assert(status.ok());
	}
	m_used_size = std::stoull(value);

	mkroot("/");

	cout<<"fs vol: "<<(m_volume/1024)<<" GB"<<endl;
	cout<<"fs m_ino: "<<m_ino<<endl;
	cout<<"fs m_used_size: "<<m_used_size/1024/1024<<" MB"<<endl;

	m_sync_thread = new thread(&sync_run, this);
	m_is_ok = true;
}

fsdb::~fsdb()
{
	m_is_ok = false;
	m_sync_conditon.notify_all();
	m_sync_thread->join();
	cout<<"descontruction"<<endl;
	do_sync();

	for (auto &iter:m_md) {
		delete iter.second;
	}

	for (auto &iter:m_dir) {
		delete iter.second;
	}
}

void fsdb::do_sync()
{
	lock_guard<mutex> lck(m_mutex);//互斥锁
	Status status = m_db.get()->Put(WriteOptions(), FS_INO, to_string(m_ino));
	assert(status.ok());
	status = m_db.get()->Put(WriteOptions(), FS_USED, to_string(m_used_size));
	assert(status.ok());
}

void fsdb::sync_run(fsdb *obj)
{
	assert(obj);
	while(obj->m_is_ok){
		unique_lock<mutex> lck(obj->m_syc_mutex);//互斥锁
		obj->m_sync_conditon.wait_for(lck, std::chrono::seconds(10));
		obj->do_sync();
	}
}

metadata *fsdb::get(const std::string &path)
{
	string path_key = move(convert_key(path));
	return get_metadata(path_key);
}

Cdir *fsdb::get_dir(const string &dir)
{
	metadata *meta = get_metadata(convert_key(dir));
	if (!meta) {
		MDS_LOG_NOTICE("Get dir path:%s fail.", dir.c_str());
		return nullptr;
	}
	assert(meta->is_dir());

	lock_guard<mutex> lck(m_mutex);//互斥锁

	auto iter = m_dir.find(meta->inode().ino);
	if (iter != m_dir.end()) {
		return iter->second;
	}else{
		Cdir *target_dir = new Cdir(m_db, meta->inode().ino);
		assert(target_dir->ok());
		m_dir[meta->inode().ino] = target_dir;
		return m_dir[meta->inode().ino];
	}
}

metadata *fsdb::get_metadata(const std::string &path)
{
	auto iter = m_md.find(path);
	if (iter != m_md.end()) {
		return iter->second;
	}

	lock_guard<mutex> lck(m_mutex);//互斥锁

	string raw_inode;
	Status status = m_db.get()->Get(ReadOptions(), path, &raw_inode);
	if (!status.ok()) {
		MDS_LOG_NOTICE("Get db path:%s fail.", path.c_str());
		return nullptr;
	}

	metadata *pmeta = new metadata(path, raw_inode);
	if(!pmeta->ok()){
		delete pmeta;
		MDS_LOG_ERROR("convert metadata fail.");
		return nullptr;
	}

	m_md[path] = pmeta;

	return pmeta;
}

metadata *fsdb::create(const std::string &path, const uint32_t &mode)
{
	metadata *p = get_metadata(convert_key(path));
	if (p) {
		return p;
	}

	string dir;
	string lastname;
	int ret = walk_path(path, dir, lastname);
	if (ret) {
		return nullptr;
	}
	
	if (!lastname.size()) {
		return nullptr;
	}

	Cdir *parent_dir = get_dir(dir);
	if (!parent_dir){
		return nullptr;
	}

	lock_guard<mutex> lck(m_mutex);//互斥锁

	string file_key = convert_key(path);
	auto iter = m_md.find(file_key);
	if (iter != m_md.end()) {
		return iter->second;
	}

	string raw_inode;
	metadata *pmeta =nullptr;
	Status status = m_db.get()->Get(ReadOptions(), file_key, &raw_inode);
	if (status.ok()) {
		pmeta = new metadata(file_key, raw_inode);
		if(!pmeta->ok()){
			delete pmeta;
			return nullptr;
		}
	}else{
		pmeta = new metadata(file_key, 0, m_ino, S_IFREG|((~S_IFMT)&mode));// 默认为0 TODO,从ETCD获取存储配置
		m_ino++;
		if(!pmeta->ok()){
			delete pmeta;
			return nullptr;
		}
		Slice s(pmeta->rawdata().data(), pmeta->rawdata().size());
		status = m_db.get()->Put(WriteOptions(), file_key, s);
		assert(status.ok());
	}

	parent_dir->add(Cdentry(pmeta->inode().ino, pmeta->inode().mode, lastname));
	m_md.insert(pair<string, metadata *>(file_key, pmeta));
	m_dir[parent_dir->self().ino()] = parent_dir;

	return pmeta;
}

metadata *fsdb::mkdir(const std::string &path, const uint32_t &mode)
{
	metadata *p = get_metadata(convert_key(path));
	if (p) {
		return p;
	}

	string dir;
	string lastname;
	int ret = walk_path(path, dir, lastname);
	if (ret) {
		MDS_LOG_ERROR("walk path:%s fail.", path.c_str());
		return nullptr;
	}
	
	if (!lastname.size()) {
		MDS_LOG_ERROR("lastname empty fail.");
		return nullptr;
	}

	Cdir *parent = get_dir(dir);
	if (!parent) {
		MDS_LOG_ERROR("dir[%s] empty fail.", dir.c_str());
		return nullptr;
	}

	lock_guard<mutex> lck(m_mutex);//互斥锁

	string key_dir = convert_key(path);
	auto iter = m_md.find(key_dir);
	if (iter != m_md.end()) {
		return iter->second;
	}

	string raw_inode;
	metadata *pmeta =nullptr;
	Status status = m_db.get()->Get(ReadOptions(), key_dir, &raw_inode);
	if (status.ok()) {
		pmeta = new metadata(key_dir,raw_inode);
		if(!pmeta->ok()){
			delete pmeta;
			return nullptr;
		}
	}else{
		pmeta = new metadata(key_dir, 0, m_ino, S_IFDIR|((~S_IFMT)&mode));
		if(!pmeta->ok()){
			delete pmeta;
			return nullptr;
		}
		m_ino++;
		Slice s(pmeta->rawdata().data(), pmeta->rawdata().size());
		status = m_db.get()->Put(WriteOptions(), key_dir, s);
		assert(status.ok());
	}

	m_md[key_dir] = pmeta;
	Cdir *self =  new Cdir(m_db, Cdentry(pmeta->inode().ino, pmeta->inode().mode, lastname), *parent);
	m_dir[pmeta->inode().ino] = self;
	m_dir[parent->self().ino()] = parent;

	return pmeta;
}

void fsdb::rmdir(const std::string &path)
{
	string dir;
	string lastname;
	int ret = walk_path(path, dir, lastname);
	if (ret) {
		MDS_LOG_ERROR("walk path:%s fail.", path.c_str());
		return;
	}

	if (!lastname.size()) {
		MDS_LOG_ERROR("lastname empty fail.");
		return;
	}

	const Cdir *rm_dir = get_dir(convert_key(path));
	if (!rm_dir) {
		return;
	}
	if (!rm_dir->empty()) {
		return;
	}
	uint64_t ino = rm_dir->self().ino();
	Cdir *parent = get_dir(dir);
	assert(parent);

	lock_guard<mutex> lck(m_mutex);//互斥锁

	parent->del(ino);
	m_dir.erase(ino);
	m_md.erase(convert_key(path));

	Status status = m_db.get()->Delete(WriteOptions(), convert_key(path));
	assert(status.ok());

}

void fsdb::unlink(const std::string &path)
{
	string dir;
	string lastname;
	int ret = walk_path(path, dir, lastname);
	if (ret) {
		MDS_LOG_ERROR("walk path:%s fail.", path.c_str());
		return;
	}

	if (!lastname.size()) {
		MDS_LOG_ERROR("lastname empty fail.");
		return;
	}

	metadata *meta = get_metadata(convert_key(path));
	if (!meta) {
		MDS_LOG_NOTICE("Get path:%s fail.", path.c_str());
		return;
	}

	if (!meta->is_file()) {
		MDS_LOG_NOTICE("the path:%s is not file.", path.c_str());
		return;
	}

	Cdir *parent = get_dir(dir);
	assert(parent);

	lock_guard<mutex> lck(m_mutex);//互斥锁

	parent->del(meta->inode().ino);
	Status status = m_db.get()->Delete(WriteOptions(), convert_key(path));
	assert(status.ok());
	if (m_used_size > meta->inode().size) {
		m_used_size -= meta->inode().size;
	}else{
		m_used_size = 0;
	}

	m_md.erase(convert_key(path));

}
void fsdb::mkroot(const std::string &path)
{
	if (path != "/") {
		return;
	}

	metadata *pmeta = get_metadata(path);
	if (pmeta) {
		return;
	}

	pmeta = new metadata(path, 0, m_ino, S_IFDIR|((~S_IFMT)&(0755)));
	assert(pmeta);
	m_ino++;

	lock_guard<mutex> lck(m_mutex);//互斥锁

	Slice s(pmeta->rawdata().data(), pmeta->rawdata().size());
	Status status = m_db.get()->Put(WriteOptions(), path, s);
	assert(status.ok());

	Cdir *root_dir = new Cdir(m_db, Cdentry(pmeta->inode().ino, pmeta->inode().mode, "/"));
	m_dir[pmeta->inode().ino] = root_dir;
	m_md[path] = pmeta;
	return;
}


vector<string> fsdb::split(const string& in, const string& delim)
{
    vector<string> ret;
    try
    {
        regex re{delim};
        return vector<string>{
                sregex_token_iterator(in.begin(), in.end(), re, -1),
                sregex_token_iterator()
           };      
    }
    catch(const std::exception& e)
    {
        cout<<"error:"<<e.what()<<std::endl;
    }
    return ret;
}

int fsdb::walk_path(const std::string &path, string &dir, string &lastname)
{
	if (path == "/") {
		dir = "/";
		lastname = "/";
		return 0;
	}
	auto path_vec = move(split(path, "/"));
	if (!path_vec.size()) {
		MDS_LOG_ERROR("walk path:%s fail.", path.c_str());
		return -1;
	}

	dir = "/";
    for(uint32_t i= 1; i < (path_vec.size() -1); i++){
		dir += path_vec[i];
		const metadata *p = get_metadata(dir);
		if (!p) {
			MDS_LOG_ERROR("get dir:%s fail", dir.c_str());
			return -1;
		}
		if (!p->is_dir()) {
			MDS_LOG_ERROR("path:%s invalid dir", dir.c_str());
			return -1;
		}
		dir += "/";
    }
	lastname = path_vec[path_vec.size() -1];

	return 0;
}

string fsdb::convert_key(const string &path)
{
	//sha256?
	string key;
	if (!path.size()) {
		return move(key);
	}
	key = path;
	if (path == "/") {
		return move(key);
	}

	if (key[key.size() -1] == '/') {
		key.pop_back();
	}
	return move(key);
}

metadata *fsdb::modify(const std::string &path, const uint64_t &size)
{
	metadata *meta = get_metadata(convert_key(path));
	if (meta) {
		if (meta->inode().size <= size) {
			m_used_size += (size - meta->inode().size);
		}else{
			m_used_size -= (meta->inode().size - size);
		}
		meta->set_size(size);
		lock_guard<mutex> lck(m_mutex);//互斥锁
		Slice s(meta->rawdata().data(), meta->rawdata().size());
		Status status = m_db.get()->Put(WriteOptions(), convert_key(path), s);
		assert(status.ok());
	}

	return meta;
}
