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

#ifndef _METADATA_H_
#define _METADATA_H_

#include <sys/stat.h>

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "mds_log.h"
#include "cafs_public.h"
#include "cafs_mds_msg.h"
#include "fsmsg.h"

#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include "rocksdb/options.h"

namespace cafs{
	class metadata
	{
	public:
		metadata(const std::string &key, const std::string &raw);
		metadata(const std::string &key, const uint32_t &pfileid, const uint64_t &ino, const uint32_t &mode);
		metadata() = delete;
		~metadata();
		bool ok(){return m_is_ok;};
		bool empty(){return !m_is_ok;};
		bool is_dir() const 
		{
			return (S_ISDIR(m_inode->mode)) ?true:false;
		};
		bool is_file() const 
		{
			return (S_ISREG(m_inode->mode)) ?true:false;
		};

		const CommonInode &inode() const{return *m_inode;};
		const std::string &rawdata()const {return m_rawdata;};
		const std::string &key()const {return m_key;};

		void set_size(const uint64_t &size)
		{
			std::unique_lock<std::mutex> lck(m_mutex, std::adopt_lock);//互斥锁
			if (m_inode) {
				m_inode->size = size;
				pack_inode(m_inode, m_rawdata);
			}
		};

	private:
		static void pack_inode(const CommonInode *inode, std::string &raw);
		static CommonInode *create_inode(const uint32_t &pfileid, const uint64_t &ino, const uint32_t &mode);
		static void destory_inode(CommonInode *inode);
	private:
		std::mutex m_mutex;
		uint32_t lru_cnt;
		bool m_is_ok = false;
		bool m_is_create = false;
		std::string m_rawdata;
		std::string m_key;
		CommonInode *m_inode;
	};
}

#endif
