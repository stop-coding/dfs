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

#ifndef _FSDB_H_
#define _FSDB_H_

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

#include "dir.hpp"
#include "metadata.hpp"

#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include "rocksdb/options.h"

namespace cafs{
	class fsdb
	{
	public:
		fsdb(const std::string &db_path):fsdb(db_path, "/", 256 *1024){};
		fsdb(const std::string &db_path, const std::string &root_dir):fsdb(db_path, root_dir, 256 *1024){};
		fsdb() = delete;
		~fsdb();
		bool ok() const {return m_is_ok;};
		metadata *get(const char *path)
		{ 
			assert(path);
			return get(std::string(path)); 
		};
		metadata *get(const std::string &path);
		metadata *create(const std::string &path, const uint32_t &mode);
		metadata *mkdir(const std::string &path, const uint32_t &mode);
		metadata *modify(const std::string &path, const uint64_t &size);
		void unlink(const std::string &path);
		Cdir *opendir(const std::string &dir){ return get_dir(dir);};
		void rmdir(const std::string &path);
	private:
		int walk_path(const std::string &path, std::string &dir, std::string &lastname);
		//std::string sha256(const std::string &path);
		fsdb(const std::string &db_path, const std::string &root_dir, uint64_t volume);
		static void sync_run(fsdb *this_obj);
		void do_sync();
		static std::vector<std::string> split(const std::string& in, const std::string& delim);
		metadata *get_metadata(const std::string &path);
		std::string convert_key(const std::string &path);
		void dir_add_file(const std::string &dir, const Cdentry &subdir);
		Cdir *get_dir(const std::string &dir);
		void mkroot(const std::string &path);
	private:
		std::string m_root;
		std::unordered_map<std::string, cafs::metadata *> m_md;
		std::unordered_map<uint64_t, cafs::Cdir*> m_dir;
		std::shared_ptr<ROCKSDB_NAMESPACE::DB> m_db;
		bool m_is_ok;
		uint64_t m_volume;
		std::atomic<uint64_t> m_ino;
		std::atomic<uint64_t> m_used_size;
		std::thread *m_sync_thread;
		std::mutex m_mutex;
		std::mutex m_syc_mutex;
		std::condition_variable m_sync_conditon;
	};

}

#endif
