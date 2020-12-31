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

#include "dir.hpp"

using namespace cafs;
using namespace std;
using namespace ROCKSDB_NAMESPACE;

static const char *DENTRY_FLAGS = ".dentry-";

Cdir::Cdir(const std::shared_ptr<ROCKSDB_NAMESPACE::DB> &db, const uint64_t &ino):m_db(db)
{
	m_is_ok = false;
	string key = move(to_string(ino) + DENTRY_FLAGS + "base");
    string rawJson;
    Status status = m_db.get()->Get(ReadOptions(), key, &rawJson);
	if (!status.ok()) {
        MDS_LOG_ERROR("key:%s is not existed.", key.c_str());
		return ;
	}

    Json::Value base;
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(rawJson.c_str(), rawJson.c_str() + rawJson.length(), &base, &err)) {
        MDS_LOG_ERROR("json:%s is not valid.", rawJson.c_str());
        return ;
    }

    m_first_ino = base["first"].asUInt64();
    m_last_ino = base["last"].asUInt64();
    m_dentry_num = base["num"].asUInt();
    m_self.m_ino = ino;

    key = move(to_string(ino) + DENTRY_FLAGS + to_string(m_first_ino));
    status = m_db.get()->Get(ReadOptions(), key, &rawJson);
    if ( !status.ok() ) {
        MDS_LOG_ERROR("key:%s is not existed.", key.c_str());
        return;
    }
    m_parent = move(Cdentry(rawJson));
    assert(m_parent.ino() == m_first_ino);

    key = move(to_string(ino) + DENTRY_FLAGS + to_string(ino));
    status = m_db.get()->Get(ReadOptions(), key, &rawJson);
    if ( !status.ok() ) {
        MDS_LOG_ERROR("key:%s is not existed.", key.c_str());
        return;
    }
    m_self = move(Cdentry(rawJson));

    assert(m_self.ino() == ino);

    MDS_LOG_NOTICE("Cdir:%lu, m_dentry_num:%u .",ino, m_dentry_num);
	m_is_ok = true;
}

Cdir::Cdir(const std::shared_ptr<ROCKSDB_NAMESPACE::DB> &db, const Cdentry &self, const Cdir &parent_dir):m_db(db),m_dentry_num(0)
{
    m_is_ok = false;

    Cdentry parent(parent_dir.self());
    Cdentry dn(self);

    m_first_ino = parent.ino();
    parent.m_pre = 0;
    parent.m_next = dn.ino();
    dn.m_pre = parent.ino();
    dn.m_next = dn.ino();
    m_last_ino = dn.ino();

    m_dentry_num = 2;

    string key = move(to_string(dn.ino()) + DENTRY_FLAGS);

    WriteBatch batch;
    batch.Put(key + to_string(parent.ino()), move(parent.jsonstring()));
    batch.Put(key + to_string(dn.ino()), move(dn.jsonstring()));

    Json::Value base_msg;
    base_msg["first"] = m_first_ino;
    base_msg["last"] = m_last_ino;
    base_msg["num"] = m_dentry_num;
    Json::StreamWriterBuilder builder;
    batch.Put(key + "base", Json::writeString(builder, base_msg));

    Status status = m_db.get()->Write(WriteOptions(), &batch);
    assert(status.ok());

    m_dentry[m_first_ino] = move(parent);
    m_dentry[m_last_ino] = move(dn);
    m_self = m_dentry[m_last_ino];
    m_parent = m_dentry[m_first_ino];

    // 父目录插入
    const_cast<Cdir &>(parent_dir).add(m_self);
    m_is_ok = true;
}
Cdir::Cdir(const std::shared_ptr<ROCKSDB_NAMESPACE::DB> &db, const Cdentry &self):m_db(db)
{
    m_is_ok = false;
    m_first_ino = 1;
    m_last_ino = 1;
    Cdentry root(self);
    assert(root.ino() == 1);
    string key = move(to_string(root.ino()) + DENTRY_FLAGS);
    root.m_pre = 1;
    root.m_next = 0;
    m_dentry_num = 2;
    WriteBatch batch;
    batch.Put(key + to_string(root.ino()), move(root.jsonstring()));

    Json::Value base_msg;
    base_msg["first"] = m_first_ino;
    base_msg["last"] = m_last_ino;
    base_msg["num"] = m_dentry_num;

    Json::StreamWriterBuilder builder;
    batch.Put(key + "base", Json::writeString(builder, base_msg));

    Status status = m_db.get()->Write(WriteOptions(), &batch);
    assert(status.ok());

    m_dentry[m_last_ino] = move(self);
    m_self = m_dentry[m_last_ino];
    m_parent = m_dentry[m_last_ino];
    m_is_ok = true;
}


Cdir::~Cdir()
{
	
}

int Cdir::get_dentry(const uint64_t offset, Cdentry &dn)
{
    string rawJson;
    string key = move(to_string(m_self.ino()) + DENTRY_FLAGS + to_string(offset));
    Status status = m_db.get()->Get(ReadOptions(), key, &rawJson);
    if ( !status.ok() ) {
        MDS_LOG_ERROR("key:%s is not existed.", key.c_str());
        return -1;
    }

    dn = move(Cdentry(rawJson));
    assert(offset == dn.ino());

    m_dentry[dn.ino()] = dn;
    return 0;
}
void Cdir::add_dentry(Cdentry &&dn)
{
    Cdentry tail;
    int ret = get_dentry(m_last_ino, tail);
    assert(ret == 0);
    if (m_last_ino == m_self.ino()) {
        m_self.m_next = dn.ino();
        m_dentry[m_self.ino()] = m_self;
    }
    m_last_ino = dn.ino();
    dn.m_pre = tail.ino();
    tail.m_next = dn.ino();
    dn.m_next = 0;
    m_dentry_num++;

    m_dentry[tail.ino()] = move(tail);

    string key = move(to_string(m_self.ino()) + DENTRY_FLAGS);

    WriteBatch batch;
    batch.Put(key + to_string(dn.ino()), move(dn.jsonstring()));
    batch.Put(key + to_string(tail.ino()), move(tail.jsonstring()));

    Json::Value base_msg;
    base_msg["first"] = m_first_ino;
    base_msg["last"] = m_last_ino;
    base_msg["num"] = m_dentry_num;
    Json::StreamWriterBuilder builder;
    batch.Put(key + "base", Json::writeString(builder, base_msg));

    Status status = m_db.get()->Write(WriteOptions(), &batch);
    assert(status.ok());

    m_dentry[m_last_ino] = move(dn);
};

void Cdir::del_dentry(const uint64_t ino)
{
    if (ino == m_parent.ino() || ino == m_self.ino()) {
        return;
    }
    
    Cdentry pre_node, next_node, node;
    int ret = get_dentry(ino, node);
    if (ret) {
        return;
    }

    ret = get_dentry(node.m_pre, pre_node);
    assert(ret == 0);

    string key = move(to_string(m_self.ino()) + DENTRY_FLAGS);
    WriteBatch batch;
    if (ino == m_last_ino) {
        m_last_ino = pre_node.ino();
        pre_node.m_next = 0;
        m_dentry[pre_node.ino()] = pre_node;
    }else{
        ret = get_dentry(node.m_next, next_node);
        assert(ret == 0);
        pre_node.m_next = next_node.ino();
        m_dentry[pre_node.ino()] = pre_node;
        next_node.m_pre = pre_node.ino();
        m_dentry[next_node.ino()] = next_node;
        batch.Put(key + to_string(next_node.ino()), move(next_node.jsonstring()));
    }

    if (m_dentry_num) {
        m_dentry_num--;
    }

    batch.Put(key + to_string(pre_node.ino()), move(pre_node.jsonstring()));
    batch.Delete(key + to_string(node.ino()));

    Json::Value base_msg;
    base_msg["first"] = m_first_ino;
    base_msg["last"] = m_last_ino;
    base_msg["num"] = m_dentry_num;
    Json::StreamWriterBuilder builder;
    batch.Put(key + "base", Json::writeString(builder, base_msg));

    Status status = m_db.get()->Write(WriteOptions(), &batch);
    assert(status.ok());

    m_dentry.erase(ino);
};


vector<string> Cdir::split(const string& in, const string& delim)
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

