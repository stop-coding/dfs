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

#ifndef _CAFS_TOOLS_H_
#define _CAFS_TOOLS_H_

#include <functional>
#include <iostream>
#include "libcafs.h"
#include "cmdline.h"
#include <vector>
#include <regex>

namespace cafs{

//cmd基类
class cmd_base{
public:
    virtual ~cmd_base(){}
	virtual const std::string &name() const=0;
    virtual void usage() const=0;
	virtual std::string show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const
	{
		usage();
		cmd_print = "\n";
		return "";
	}
    virtual int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)=0;
};

//ls
class cmd_ls : public cmd_base{
public:
	~cmd_ls(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	const std::string m_name = "ls";
};

//mkdirs
class cmd_mkdirs : public cmd_base{
public:
	~cmd_mkdirs(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	const std::string m_name = "mkdir";
};

//cd
class cmd_cd : public cmd_base{
public:
	~cmd_cd(){}
	const std::string &name() const {return m_name;}
    void usage() const;
	std::string show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	std::string list_cwddir(const cafs_mount_handle_t cafs_fd) const;
	const std::string m_name = "cd";
};

//write
class cmd_write : public cmd_base{
public:
	~cmd_write(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
	std::string show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const;
private:
	void show_remote_file(const cafs_mount_handle_t cafs_fd, const std::string &remote_path) const;
	void show_local_file(const std::string &local_path) const;
	const std::string m_name = "write";
};

//rm
class cmd_rm : public cmd_base{
public:
	~cmd_rm(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
	std::string show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const;
private:
	std::string list_cwddir(const cafs_mount_handle_t cafs_fd) const;
	const std::string m_name = "rm";
};

//iotest
class cmd_iotest : public cmd_base{
public:
	cmd_iotest();
	~cmd_iotest(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	static void iorun_write(const cafs_mount_handle_t cafs_fd,
					int64_t io_count, 
					int64_t io_size, 
					const std::string dir, 
					const std::string name, 
					int sn);
	static void iorun_read(const cafs_mount_handle_t cafs_fd,
					int64_t io_count, 
					int64_t io_size, 
					const std::string dir, 
					const std::string name, 
					int sn);
	const std::string m_name = "iotest";
	cmdline::parser m_cmd;
};

//qps
class cmd_qps : public cmd_base{
public:
	cmd_qps();
	~cmd_qps(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	static void qps_test(const cafs_mount_handle_t cafs_fd, int64_t count, const std::string dir, int sn);
	const std::string m_name = "qps";
	cmdline::parser m_cmd;
};

//echo
class cmd_echo : public cmd_base{
public:
	~cmd_echo(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	const std::string m_name = "echo";
};

//cat
class cmd_cat : public cmd_base{
public:
	~cmd_cat(){}
	const std::string &name() const {return m_name;}
    void usage() const;
    int run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args);
private:
	const std::string m_name = "cat";
};

//命令解析器
class toolbox{
public:
	toolbox(int argc, const char * const argv[]);
	~toolbox();
	bool isok() const{
      return m_init;
    }
	void dispatch(bool &is_stop);
private:
	cafs_mount_handle_t m_cafs_fd;
	bool m_init;
	std::string  m_mount_path;
	std::map<std::string, cmd_base *> m_func;

	int m_cmd_index = 0;
	std::string m_cmdline;
	std::string m_cmdline_tmp;

	int m_history_index = 0;
	std::vector<std::string>  m_history;

	std::string m_cmd_head;
private:
	void list_cmd();
	std::string list_cmd(const std::string &cmd);
	void show();
	void exec();
	void del();
	void quit();
	void pre_cmd();
	void next_cmd();
	void left_shift();
	void right_shift();
	void update(const char &ch);
	bool is_compose_key();

	template <class T>
	void add()
	{
		cmd_base *base = new T();
		m_func[base->name()] = base;
	}
	void register_cmd()
	{
		add<cmd_ls>();			// 注册ls命令
		add<cmd_mkdirs>();		// 注册mkdirs命令
		add<cmd_cd>();			// 注册cd命令
		add<cmd_write>();		// 注册write命令
		add<cmd_iotest>();		// 注册io_test命令
		add<cmd_qps>();			// 注册qpst命令
		add<cmd_rm>();			//
		add<cmd_echo>();			
		add<cmd_cat>();			
	}	
};
}
#endif
