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

#ifndef _DIR_H_
#define _DIR_H_

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <condition_variable>

#include "json/json.h"
#include "mds_log.h"

#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include "rocksdb/options.h"

namespace cafs{
	class Cdir;
	class Cdentry
	{
	public:
		Cdentry(const uint64_t &ino, const uint32_t &mode, const std::string &name):
				m_ino(ino),m_mode(mode),m_name(name),m_pre(0),m_next(0){};
		Cdentry():m_ino(0),m_mode(0),m_name("none"),m_pre(0),m_next(0){};
		Cdentry(const Json::Value &json)
		{
			m_ino = json["ino"].asUInt64();
			m_mode = json["mode"].asUInt();
			m_name = json["name"].asString();
			m_pre = json["pre"].asUInt64();
			m_next = json["next"].asUInt64();
		};

		Cdentry(const std::string &rawjson)
		{
			Json::Value json;
			JSONCPP_STRING err;
			Json::CharReaderBuilder builder;
			const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
			if (!reader->parse(rawjson.c_str(), rawjson.c_str() + rawjson.length(), &json, &err)) {
				return;
			}
			m_ino = json["ino"].asUInt64();
			m_mode = json["mode"].asUInt();
			m_name = json["name"].asString();
			m_pre = json["pre"].asUInt64();
			m_next = json["next"].asUInt64();
		};

		Cdentry(const Cdentry& dn){
			m_ino = dn.m_ino;
			m_mode = dn.m_mode;
			m_name = dn.m_name;
			m_pre = dn.m_pre;
			m_next = dn.m_next;
		};
		Cdentry &operator =(const Cdentry& dn)
		{
			m_ino = dn.m_ino;
			m_mode = dn.m_mode;
			m_name = dn.m_name;
			m_pre = dn.m_pre;
			m_next = dn.m_next;
			return *this;
		}

		Cdentry(Cdentry &&dn){
			m_ino = dn.m_ino;
			m_mode = dn.m_mode;
			m_name = std::move(dn.m_name);
			m_pre = dn.m_pre;
			m_next = dn.m_next;
		};
		Cdentry &operator =(Cdentry &&dn)
		{
			if (this != &dn) {
				m_ino = dn.m_ino;
				m_mode = dn.m_mode;
				m_name = std::move(dn.m_name);
				m_pre = dn.m_pre;
				m_next = dn.m_next;
			}
			return *this;
		}

		~Cdentry(){};
		const std::string jsonstring() 
		{
			Json::Value json;
			json["ino"] = m_ino;
			json["mode"] = m_mode;
			json["name"] = m_name;
			json["pre"] = m_pre;
			json["next"] = m_next;
			Json::StreamWriterBuilder builder;
    		return std::move(Json::writeString(builder, json));
		};
		Json::Value json() 
		{
			Json::Value json;
			json["ino"] = m_ino;
			json["mode"] = m_mode;
			json["name"] = m_name;
			json["pre"] = m_pre;
			json["next"] = m_next;
    		return std::move(json);
		};

		uint64_t ino() const{return m_ino;};
		uint32_t mode() const{return m_mode;};
		uint32_t offset() const{return m_next;};
		std::string name() const{return m_name;};
	private:
		friend class Cdir;
		uint64_t m_ino;
		uint32_t m_mode;
		std::string m_name;
		uint64_t m_pre = 0;
		uint64_t m_next = 0;
	};
	class Cdir
	{
	public:
		Cdir(const std::shared_ptr<ROCKSDB_NAMESPACE::DB> &db, const uint64_t &ino);
		Cdir(const std::shared_ptr<ROCKSDB_NAMESPACE::DB> &db, const Cdentry &self, const Cdir &parent_dir);
		Cdir(const std::shared_ptr<ROCKSDB_NAMESPACE::DB> &db, const Cdentry &self);
		Cdir() = delete;
		~Cdir();
		/*Cdir(const Cdir &dir) {
			m_db = dir.m_db;
			m_dentry = dir.m_dentry;
			m_is_ok = dir.m_is_ok;
			m_self = dir.m_self;
			m_parent = dir.m_parent;
			m_first_ino = dir.m_first_ino;
			m_last_ino = dir.m_last_ino;
			m_dentry_num = dir.m_dentry_num;
		}
		Cdir &operator =(const Cdir &dir) {
			if (this != &dir) {
				m_db = dir.m_db;
				m_dentry = dir.m_dentry;
				m_is_ok = dir.m_is_ok;
				m_self = dir.m_self;
				m_parent = dir.m_parent;
				m_first_ino = dir.m_first_ino;
				m_last_ino = dir.m_last_ino;
				m_dentry_num = dir.m_dentry_num;
			}
			return *this;
		}
		Cdir(Cdir &&dir) {
			m_db = std::move(dir.m_db);
			m_dentry = std::move(dir.m_dentry);
			m_is_ok = dir.m_is_ok;
			m_self = std::move(dir.m_self);
			m_parent = std::move(dir.m_parent);
			m_first_ino = dir.m_first_ino;
			m_last_ino = dir.m_last_ino;
			m_dentry_num = dir.m_dentry_num;
		}
		Cdir &operator = (Cdir &&dir) {
			if (this != &dir) {
				m_db = std::move(dir.m_db);
				m_dentry = std::move(dir.m_dentry);
				m_is_ok = dir.m_is_ok;
				m_self = std::move(dir.m_self);
				m_parent = std::move(dir.m_parent);
				m_first_ino = dir.m_first_ino;
				m_last_ino = dir.m_last_ino;
				m_dentry_num = dir.m_dentry_num;
			}
			return *this;
        }*/

		bool ok(){return m_is_ok;};

		void add(Cdentry &&dn)
		{ 
			std::unique_lock<std::mutex> lck(m_mutex);//互斥锁
			add_dentry(std::move(dn)); 
		};
		void add(const Cdentry &dn)
		{ 
			std::unique_lock<std::mutex> lck(m_mutex);//互斥锁
			add_dentry(Cdentry(dn)); 
		};

		void del(const uint64_t &ino)
		{
			std::unique_lock<std::mutex> lck(m_mutex);//互斥锁
			del_dentry(ino);
		};

		const Cdentry &self()const{return m_self;};
		const Cdentry &parent()const{return m_parent;};
		uint32_t num()const {return m_dentry_num;};
		bool empty() const
		{
			if (m_dentry_num > 2) {
				return false;
			}
			return true;
		};

		int child(const uint64_t &offset, Cdentry &dn) 
		{
			if (m_self.m_next == 0) {//ino从1开始
				MDS_LOG_ERROR("self next is 0");
				return -1;
			}
			uint64_t ino = offset;
			if (ino == 0 ) {//ino从1开始
				ino = m_self.m_next;
			}
			auto iter = m_dentry.find(ino);
			if (iter != m_dentry.end()) {
				dn = iter->second;
				return 0;
			}
			std::unique_lock<std::mutex> lck(m_mutex);//互斥锁
			if (get_dentry(ino, dn) != 0) {
				MDS_LOG_ERROR("get inode :%lu fail", ino);
				return -1;
			}
			return 0;
		}

		std::vector<Cdentry> childs(const uint64_t &offset, const uint32_t &dn_num)
		{
			std::vector<Cdentry> vecs;
			uint64_t index = offset;
			for (uint32_t i = 0; i < dn_num; i++) {
				Cdentry dn;
				if (child(index, dn) != 0) {
					break;
				}
				//MDS_LOG_ERROR("get dentry:%lu ,name:%s, next:%lu", dn.ino(), dn.name().c_str(), dn.offset());
				index = dn.offset();
				vecs.push_back(dn);
				if (index == 0 || dn.ino() == m_last_ino) {
					break;
				}
			}
			//MDS_LOG_ERROR("get vecs size:%lu, m_dentry_num:%u", vecs.size(), m_dentry_num);
			return std::move(vecs);
		}

	private:
		static std::vector<std::string> split(const std::string& in, const std::string& delim);
		int get_dentry(const uint64_t offset, Cdentry &dn);
		void add_dentry(Cdentry &&dn);
		void del_dentry(const uint64_t ino);
	private:
		std::shared_ptr<ROCKSDB_NAMESPACE::DB> m_db;
		std::mutex m_mutex;
		std::unordered_map<uint64_t, Cdentry> m_dentry;
		bool m_is_ok = false;
		Cdentry m_self;
		Cdentry m_parent;
		uint64_t m_first_ino;
		uint64_t m_last_ino;
		uint32_t m_dentry_num;
	};
}

#endif
