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
#include <sys/time.h>
#include <stdio.h>
#include <termios.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <queue>
#include <thread>
#include "cafs_tools.hpp"


using namespace std;
using namespace cafs;

toolbox::toolbox(int argc, const char * const argv[])
{
    int ret;
    cmdline::parser entry;
    m_cafs_fd = NULL;
    entry.add<string>("cfg", 'f', "config file path of cafs, default:/etc/cafs/cafs.cfg", true, "/etc/cafs/cafs.cfg");
    entry.add<string>("path", 'p', "mount path on cafs, default:/home", true, "/home");
    entry.add("help", 0, "help that show all cmd");
    m_init = entry.parse(argc, argv);
    if (!m_init){
        cerr<<entry.error()<<endl<<entry.usage();
        return;
    }
    if (argc ==1 || entry.exist("help")){
        cerr<<entry.usage();
        return;
    }

    struct cafs_mount_info conf_ctx = {};
    conf_ctx.config_path = (char *)entry.get<string>("cfg").c_str();
    ret = cafs_create(&conf_ctx, &m_cafs_fd);
	if (ret != 0 ) {
        cout<<"create cafs fd fail,"<<ret<<endl;
		goto end;
	}

	ret = cafs_init(m_cafs_fd);
	if (ret != 0 ) {
		cout<<"m_init cafs fd fail,"<<ret<<endl;
		goto end;
	}
    ret = cafs_mount(m_cafs_fd, (char*)entry.get<string>("path").c_str());
	if (ret != 0 ) {
		cout<<"mount cafs fail, path"<<entry.get<string>("path")<<endl;
		goto end;
	}
    m_mount_path = entry.get<string>("path");
    register_cmd();
    m_cmd_head = "[cafs@" + m_mount_path + "]# ";
    return;
end:
    m_init = false;
    cafs_finish(m_cafs_fd);
    m_cafs_fd = nullptr;
    return;
}

toolbox::~toolbox()
{
    cafs_finish(m_cafs_fd);
    for(auto iter=m_func.begin(); iter!=m_func.end(); iter++){
        delete iter->second;
    }
}

static int getch() {
    struct termios tm, tm_old;
    int fd =0, c;
 
    if (tcgetattr(fd, &tm) < 0) {
        return -1;
    }
 
    tm_old = tm;    // save original mode
    cfmakeraw(&tm);
 
    if (tcsetattr(fd, TCSANOW, &tm) < 0) {    // set new mode
        return -1;
    }
 
    c = fgetc(stdin);
 
    if (tcsetattr(fd, TCSANOW, &tm_old) < 0) {   // set old mode
        return -1;
    }
 
    return c;
}

static void locateCursor(const int row, const int col){
    printf("%c[%d;%dH",27,row,col);
}

static void left_shift_cursor(const int n)
{
    printf("\033[%dD",n);
}

static void right_shift_cursor(const int n)
{
    printf("\033[%dC",n);
}
static void clean_cursor_ctx()
{
    printf("\033[K");
}

static void light_cursor()
{
    printf("\033[8m");
}

static string get_longest_comm_prefix(const string& str1, const string& str2)
{
    
    if (str1.size() == 0) {
        return str2;
    }
    if (str2.size() == 0) {
        return str1;
    }
    string common;
    int min_len = (str1.size() < str2.size())?str1.size():str2.size();
    for (auto i =0; i < min_len; i++) {
        if(str1[i] != str2[i]){
            break;
        }
        common.push_back(str1[i]);
    }
    return common;
}

static vector<string> split(const string& in, const string& delim)
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

void toolbox::list_cmd()
{
    int i = 1;
    cout<<endl;
    cout<<"cmd list:"<<endl;
    for(auto &iter:m_func){
        i++;
        cout<<iter.first<<"  ";
        if (i %10 == 0) {
            cout<<endl;
        }
    }
    cout<<endl;
    cout<<endl;
}

string toolbox::list_cmd(const string &cmd)
{
    vector<string> cmds;
    for(auto &iter:m_func){
        if(iter.first.find(cmd) != 0){
            continue;
        }
        cmds.push_back(iter.first);
    }
    if (cmds.size() == 1) {
        return cmds[0] + " ";
    }
    cout<<endl;
    cout<<"cmd list: "<<endl;
    for(auto i = 0; i < cmds.size(); i++) {
        cout<<cmds[i]<<"  ";
        if ((i+1) %10 == 0) {
            cout<<endl;
        }
    }
    cout<<endl;
    cout<<"Note: more message for cmd, user cmd help qu get information."<<endl;
    return "";
}

void toolbox::show()
{
    if (!m_cmdline.size()) {
        list_cmd();
        cout<<m_cmd_head<<m_cmdline;
        return;
    }

    vector<string>  v = split(m_cmdline, " ");
    if (!v.size()) {
        list_cmd();
        cout<<m_cmd_head<<m_cmdline;
        return;
    }

    auto iter = m_func.find(v[0]);
    if (iter == m_func.end()){
        string cmd = list_cmd(v[0]);
        left_shift_cursor(m_cmdline.size());
        m_cmdline = cmd;
        m_cmd_index = m_cmdline.size();
        cout<<m_cmdline;
        return;
    }

    cmd_base *base = iter->second;
    left_shift_cursor(m_cmdline.size());
    string cmd_print;
    string line = base->show_param(m_cafs_fd, v, cmd_print);
    if(cmd_print.size()) {
        cout<<endl;
        cout<<cmd_print;
        cout<<endl;
        cout<<m_cmd_head;
    }
    if(line.size()){
        m_cmdline =v[0] + " " + line;
        m_cmd_index = m_cmdline.size();
    }
    cout<<m_cmdline;
    return;
}

void toolbox::exec()
{
    cout<<endl;
    if(!m_cmdline.size()){
        cout<<m_cmd_head;
        return;
    }

    vector<string>  v = split(m_cmdline, " ");
    if(!v.size()){
        m_cmdline = "";
        m_cmd_index = 0;
        cout<<m_cmd_head;
        return;
    }

    if(v[0] == "exit"){
        quit();
        m_cmdline = "";
        m_cmd_index = 0;
        cout<<m_cmd_head;
        return;
    }
    
    m_history.push_back(m_cmdline);
    m_history_index = m_history.size();

    auto iter = m_func.find(v[0]);
    if (iter == m_func.end()){
        cout<<"Note: sorry, we can not find cmd ["<<v[0]<<"]."<<endl;
        list_cmd();
        m_cmdline = "";
        m_cmd_index = 0;
        cout<<m_cmd_head;
        return;
    }

    cmd_base *base = iter->second;
    if (v.size() == 2 && v[1] == "help") {
        base->usage();
        m_cmdline = "";
        m_cmd_index = 0;
        cout<<m_cmd_head;
        return;
    }

    int ret = base->run(m_cafs_fd, v);
    if (ret) {
        cout<<"  ### cafs tools help message ### "<<endl;
        for(auto &iter:m_func)
            (iter.second)->usage();
    }
    
    m_cmdline = "";
    m_cmd_index = 0;
    cout<<m_cmd_head;
    return;
}

void toolbox::del()
{
    if(!m_cmdline.size()){
        return;
    }
    if (m_cmd_index >= m_cmdline.size()) {
        m_cmdline.pop_back();
        left_shift_cursor(1);
        clean_cursor_ctx();
        m_cmd_index = m_cmdline.size();
    }else if(m_cmd_index > 0) {
        left_shift_cursor(m_cmd_index);
        clean_cursor_ctx();
        m_cmdline.erase(m_cmd_index - 1, 1);
        cout<<m_cmdline;
        m_cmd_index--;
        if(m_cmdline.size() >= m_cmd_index){
            left_shift_cursor(m_cmdline.size() - m_cmd_index);
        }else{
            left_shift_cursor(m_cmdline.size());
        }
    }
}

void toolbox::quit()
{
    cout<<endl;
    cout<<endl;
    cout<<"### Thank you for using cafs tools, Good bye!!! ###"<<endl;
    cout<<endl;
    m_init = false;
}

bool toolbox::is_compose_key()
{
    if (m_cmdline_tmp.size() == 2 && m_cmdline_tmp[0] == 27 && m_cmdline_tmp[1] == 91){
        return true;
    }
    return false;
}

void toolbox::pre_cmd()
{
    if (!is_compose_key()){
        return;
    }

    if(m_history_index > m_history.size()){
        m_history_index = m_history.size();
    }

    if(m_cmdline.length()){
        left_shift_cursor(m_cmdline.length());
        clean_cursor_ctx();
    }

    if(m_history_index == 0){
        m_cmdline = "";
    }else{
        m_history_index--;
        m_cmdline = m_history[m_history_index];
    }

    m_cmd_index = m_cmdline.size();
    cout<<m_cmdline;

    return;
}

void toolbox::next_cmd()
{
    if (!is_compose_key()){
        return;
    }

    if(m_cmdline.length()){
        left_shift_cursor(m_cmdline.length());
        clean_cursor_ctx();
    }
    if(m_history_index >= m_history.size()){
        m_cmdline = "";
    }else{
        m_cmdline = m_history[m_history_index];
        m_history_index++;
    }
    m_cmd_index = m_cmdline.size();
    cout<<m_cmdline;
    return;
}

void toolbox::left_shift()
{
    if (!is_compose_key()){
        return;
    }

    if(m_cmd_index > 0){
        left_shift_cursor(1);
        m_cmd_index--;
    }
}

void toolbox::right_shift()
{
    if (!is_compose_key()){
        return;
    }

    if(m_cmd_index < m_cmdline.size()){
        right_shift_cursor(1);
        m_cmd_index++;
    }
}


void toolbox::update(const char &ch)
{
    if (!is_compose_key()){
        if(isalnum(ch) || ch == '/' || ch == ' ' || 
            ch == '_' || ch == '.'|| ch == '-' ||
            ch == '>' || ch == '|') {
            if(m_cmd_index >= m_cmdline.size()){
                m_cmdline +=ch;
                m_cmd_index = m_cmdline.size();
                cout<<ch;
            }else{
                if(m_cmd_index > 0){
                    left_shift_cursor(m_cmd_index);
                }
                clean_cursor_ctx();
                m_cmdline.insert(m_cmd_index, 1, ch);
                cout<<m_cmdline;
                m_cmd_index++;
                if(m_cmdline.size() > m_cmd_index){
                    left_shift_cursor(m_cmdline.size() - m_cmd_index);
                }
            }
        }
    }
    m_cmdline_tmp +=ch;
    if(m_cmdline_tmp.size() > 2){ // 保留两个输入
        m_cmdline_tmp = m_cmdline_tmp.erase(0, m_cmdline_tmp.size() - 2);
    }
}

void toolbox::dispatch(bool &is_stop)
{

    char ch;
    cout<<endl<<endl;
    cout<<"### Welcome to use cafs tools!!! ###"<<endl;
    cout<<endl<<"Note: the key of <tab> will show all commands. more question, try <help>."<<endl;
    cout<<"      input <exit> it will help you exit this program, or <CTRL + c> same effect."<<endl;
    cout<<"      Good luck!"<<endl;
    cout<<endl<<"### Run success! ###"<<endl<<endl;
    cout<<m_cmd_head;
    while (m_init) {
        ch = getch();
        if(is_stop){
            cout<<endl<<" get signal to exit"<<endl;
            break;
        }
        switch (ch){
            case '\t':
                show();
                break;
            case '\n':
            case 13:
                exec();
                break;
            case 3:
            case 17:
                quit();
                break;
            case 8:
            case 126:
                del();
                break;
            case 'A':
                pre_cmd();
                break;
            case 'B':
                next_cmd();
                break;
            case 'C':
                right_shift();
                break;
            case 'D':
                left_shift();
                break;
            default:
                break;
        }
        update(ch);
    }
    cout<<endl;
    return;
}

void cmd_ls::usage() const
{
     cout<<endl<<"  ## <ls> ##"<<endl;
     cout<<"  descript: a cmd to list cafs file on mds."<<endl;
     cout<<"  cmd: ls <path> "<<endl;
     cout<<"  exp: ls ./ ;  ls"<<endl;
     cout<<"  help: ls help "<<endl<<endl;
}

int cmd_ls::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;

    if(args.size() >= 2){
        cwd = args[1].c_str();
    }else{
        cwd = cafs_getcwd(cafs_fd);
        if(!cwd){
            cout<<"cafs_getcwd fail "<<endl;
            return -1;
        }
    }

	ret = cafs_opendir(cafs_fd, cwd, &dirp);
	if(!cwd){
        cout<<"cafs_opendir fail "<<endl;
        return -1;
    }
    int i = 1;
    cout<<endl;
	while((pde = cafs_readdir(cafs_fd, dirp)) != NULL) {
        if(pde->d_name){
            cout<<string(pde->d_name)<<"  ";
            if(i % 10 == 0) {
                cout<<endl;
            }
            i++;
        }
	}
    cout<<endl;
	ret = cafs_closedir(cafs_fd, dirp);
	if(ret){
        cout<<"cafs_closedir fail "<<endl;
    }

	return 0;
}

void cmd_mkdirs::usage() const
{
     cout<<endl<<"  ## <mkdir> ##"<<endl;
     cout<<"  descript: create a directory on mds, and support create recursive."<<endl;
     cout<<"  cmd: mkdir <path> "<<endl;
     cout<<"  exp: mkdir /home/root/dir1 "<<endl;
     cout<<"  help: mkdir help "<<endl<<endl;
}

int cmd_mkdirs::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;

    if(args.size() < 2){
        return -1;
    }

    vector<string>  path = split(args[1], "/");
    string realpath;
    for(auto &iter:path){
        if(iter.size()){
            realpath +=iter + "/";
            ret = cafs_mkdir(cafs_fd, realpath.c_str(), 0777);
            if(ret){
                cout<<"mkdirs directory <"<<realpath<<"> fail."<<endl;
                continue;
            }
            cout<<"mkdir directory:"<<realpath<<endl;
        }else{
            realpath +="/";
        }
    }
	return 0;
}

void cmd_cd::usage() const
{
     cout<<endl<<"  ## <cd> ##"<<endl;
     cout<<"  descript: change current work path."<<endl;
     cout<<"  cmd: cd <path> "<<endl;
     cout<<"  exp: cd /home "<<endl;
     cout<<"  exp: cd "<<endl;
     cout<<"  help: cd help "<<endl<<endl;
}

int cmd_cd::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;
    const char *cwd;
    if(args.size() < 2){
        ret = cafs_chdir(cafs_fd, "/");
        if(ret){
            cout<<"cd /"<< " fail."<<endl;
        }
    }else{
        cwd = cafs_getcwd(cafs_fd);
        if(!cwd){
            cout<<"cafs_getcwd fail "<<" fail."<<endl;
            return -1;
        }
        string realpath = string(cwd) + "/" + args[1];
        ret = cafs_chdir(cafs_fd, realpath.c_str());
        if(ret){
            cout<<"cd "<<realpath<< " fail."<<endl;
        }
    }
	return 0;
}

string cmd_cd::list_cwddir(const cafs_mount_handle_t cafs_fd) const
{
    int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;

    cwd = cafs_getcwd(cafs_fd);
    if(!cwd){
        cout<<"cafs_getcwd fail "<<endl;
        return "";
    }

    ret = cafs_opendir(cafs_fd, cwd, &dirp);
	if(ret){
        cout<<"cafs_opendir fail "<<endl;
        return "";
    }
    int i = 1;
    string list_print;
	while((pde = cafs_readdir(cafs_fd, dirp)) != NULL) {
        if(pde->d_name && DT_DIR == pde->d_type && 
            strcmp(pde->d_name, ".") != 0 && 
            strcmp(pde->d_name, "..") != 0){
            
            list_print +=string(pde->d_name)+"  ";
            if(i % 10 == 0) {
                list_print +="\n";
            }
            i++;
        }
	}

	ret = cafs_closedir(cafs_fd, dirp);
	if(ret){
        cout<<"cafs_closedir fail "<<endl;
    }

	return list_print;
}


string cmd_cd::show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const
{
    int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;

    if (args.size() <= 1) {
        cmd_print = list_cwddir(cafs_fd);
        return "";
    }

    vector<string>  path = split(args[1], "/");
    string realpath;
    string valid_path;
    string lastdir;
    for(auto &iter:path){
        if(!iter.size()){
            realpath +="/";
            valid_path = realpath;
            continue;
        }
        realpath +=iter + "/";
        ret = cafs_opendir(cafs_fd, realpath.c_str(), &dirp);
        if(ret || !dirp){
            lastdir = iter;
            break;
        }
        valid_path = realpath;
        cafs_closedir(cafs_fd, dirp);
    }
    
    if (valid_path.size() == 0){
        cwd = cafs_getcwd(cafs_fd);
        if(!cwd){
            cout<<"cafs_getcwd fail "<<endl;
            return "";
        }
        ret = cafs_opendir(cafs_fd, cwd, &dirp);
    }else{
        ret = cafs_opendir(cafs_fd, valid_path.c_str(), &dirp);
    }

	if(ret){
        cout<<"cafs_opendir fail: "<<valid_path<<endl;
        return "";
    }

    vector<string> dir_name;
	while((pde = cafs_readdir(cafs_fd, dirp)) != NULL) {
        if(!pde->d_name || DT_DIR != pde->d_type 
            || strcmp(pde->d_name, ".") == 0 
            || strcmp(pde->d_name, "..") == 0){
            continue;
        }
        if(string(pde->d_name).find(lastdir) != 0){
            continue;
        }
        dir_name.push_back(string(pde->d_name));
	}

    cafs_closedir(cafs_fd, dirp);

    if (dir_name.size() == 0) {
        return "";
    }

    if (dir_name.size() == 1) {
        valid_path += dir_name[0];
        return valid_path;
    }

    string comm_prefix;
    for (auto i = 0; i < dir_name.size(); i++) {
        cmd_print +=dir_name[i] + " ";
        //公共最长前缀
        comm_prefix = get_longest_comm_prefix(comm_prefix, dir_name[i]);
        if((i+1) % 10 == 0) {
            cmd_print +="\n";
        }
    }
    valid_path += comm_prefix;
	return valid_path;
}

void cmd_write::usage() const
{
     cout<<endl<<"  ## <write> ##"<<endl;
     cout<<"  descript: test write data to remote server of pfile with mds."<<endl;
     cout<<"  cmd: write <local file> <remote file>"<<endl;
     cout<<"  exp: write /home/file1  /home/pfile/file_new_1"<<endl;
     cout<<"  help: write help "<<endl<<endl;
}

void cmd_write::show_local_file(const std::string &local_path) const
{
    DIR *dp;
    struct dirent *pde;
    if((dp = opendir(local_path.c_str())) == NULL){
        return;
    }
    int i = 1;
    cout<<endl;
	while((pde = readdir(dp)) != NULL) {
        if(pde->d_name && (DT_DIR == pde->d_type || DT_REG == pde->d_type)){
            cout<<string(pde->d_name)<<"  ";
            if(i % 10 == 0) {
                cout<<endl;
            }
            i++;
        }
	}
    cout<<endl;
    closedir(dp);
    return;
}

void cmd_write::show_remote_file(const cafs_mount_handle_t cafs_fd, const std::string &remote_path) const
{
    int ret = 0;
	struct cafs_dir *dirp;
	struct dirent *pde;

	ret = cafs_opendir(cafs_fd, remote_path.c_str(), &dirp);
	if(ret){
        return;
    }
    int i = 1;
    cout<<endl;
	while((pde = cafs_readdir(cafs_fd, dirp)) != NULL) {
        if(pde->d_name && DT_DIR == pde->d_type){
            cout<<string(pde->d_name)<<"  ";
            if(i % 10 == 0) {
                cout<<endl;
            }
            i++;
        }
	}
    cout<<endl;
	ret = cafs_closedir(cafs_fd, dirp);
	if(ret){
        cout<<"cafs_closedir fail "<<endl;
    }
    return;
}

string cmd_write::show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const
{
    int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;

    if (args.size() <= 2) {
        show_local_file(args[1]);
    }else if(args.size() == 3){
        show_remote_file(cafs_fd, args[2]);
    }
	return "";
}

int cmd_write::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;
    int file_fd;
    if(args.size() < 3){
        return -1;
    }

    ifstream out(args[1], ios::out | ios::binary | ios::ate);
    if(!out.good()) {
        cout<<"local file "<<args[1]<< " not existed."<<endl;
        return -1;
    }

    file_fd = cafs_open(cafs_fd, args[2].c_str(), O_CREAT|O_WRONLY, 0666);
	if(file_fd < 0) {
        cout<<"can't create remote file "<<args[2]<<endl;
        return -1;
    }
    int64_t size = out.tellg();
    out.seekg(0, ios::beg);

    char *buffer = new char[1024*1024];
    int64_t r_size = 0;
    int64_t w_size = 0;
    int64_t offset = 0;
    while(size > 0){
        r_size = out.readsome(buffer, 1024*1024);
        size -=r_size;
        w_size = cafs_write(cafs_fd, file_fd, buffer, r_size, offset);
        if(w_size <= 0) {
            cout<<"can't write remote file: "<<args[2]<<endl;
            cout<<"offset:"<<offset<<" write size:"<<r_size<<endl;
            break;
        }
        offset +=w_size;
    }
    delete []buffer;
    out.close();
    cafs_close(cafs_fd, file_fd);
	return 0;
}

cmd_iotest::cmd_iotest()
{
     m_cmd.add<string>("dir", 'd', "remote dir where to save test file", false, "/");
     m_cmd.add<string>("name", 'n', "file name for test io on remote server", false, "cafs-io-tst");
     m_cmd.add<int64_t>("size", 's', "io size of per write or read, KB", false, 1024);
     m_cmd.add<int>("file", 'f', "file num for testing at the same time that on diffrent thread", false, 4);
     m_cmd.add<int64_t>("count", 'c', "the counts of io test every time", false, 1000);
     m_cmd.add("help", 0, "help that show all options for iotest");
}

void cmd_iotest::usage() const
{
     cout<<endl<<"  ## <iotest> ##"<<endl;
     cout<<"  descript: to test write/read io with cafstools."<<endl;
     cout<<m_cmd.usage();
     cout<<"  exp: iotest // to send all size (1000*1M*4) with 4 thread on dir[/cafs_io_test_*]"<<endl;
     cout<<"  exp: iotest --dir=/new_dir --name=new_name ; // to send file on dir[/new_dir/new_name_*]"<<endl;
     cout<<"  exp: iotest -s 128 -f 8 ; // to send all size (1000*128KB*8) with 8 thread"<<endl<<endl;
}

void cmd_iotest::iorun_write(const cafs_mount_handle_t cafs_fd, 
                    int64_t io_count,
					int64_t io_size, 
					const std::string dir, 
					const std::string name, 
					int sn)
{
    int file_fd;

    string io_file = dir + "/" + name + "_"+ to_string(sn);
    file_fd = cafs_open(cafs_fd, io_file.c_str(), O_CREAT|O_WRONLY, 0666);
	if(file_fd < 0) {
        cout<<"thread_"<<sn<<" can't create remote file "<<io_file<<endl;
        return;
    }
    char *buffer = new char[io_size*1024];
    int64_t w_size = 0;
    int64_t offset = 0;
    for (int64_t i =0; i < io_count; i++) {
        w_size = cafs_write(cafs_fd, file_fd, buffer, io_size*1024, offset);
        if (w_size < 0) {
            cout<<"thread_"<<sn<<" write "<<io_file<<"fail, writed:"<<offset<<endl;
            break;
        }
        offset += w_size;
    }
    delete []buffer;
    cafs_close(cafs_fd, file_fd);
    return;
}

void cmd_iotest::iorun_read(const cafs_mount_handle_t cafs_fd, 
                    int64_t io_count,
					int64_t io_size, 
					const std::string dir, 
					const std::string name, 
					int sn)
{
    int file_fd;

    string io_file = dir + "/" + name + "_"+ std::to_string(sn);
    file_fd = cafs_open(cafs_fd, io_file.c_str(), O_RDONLY, 0666);
	if(file_fd < 0) {
        cout<<"thread_"<<sn<<" can't read remote file "<<io_file<<endl;
        return;
    }
    char *buffer = new char[io_size*1024 + 1];
    int64_t r_size = 0;
    int64_t offset = 0;
    for (int64_t i =0; i < io_count; i++) {
        r_size = cafs_read(cafs_fd, file_fd, buffer, io_size*1024, offset);
        if (r_size < 0) {
            cout<<"thread_"<<sn<<" read "<<io_file<<"fail, read size:"<<offset<<endl;
            break;
        }
        offset += r_size;
    }
    delete []buffer;
    cafs_close(cafs_fd, file_fd);
    cafs_unlink(cafs_fd, io_file.c_str());
    return;
}

int cmd_iotest::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    if (!m_cmd.parse(args)){
        cerr<<m_cmd.error()<<endl;
        return -1;
    }
    int64_t io_count = m_cmd.get<int64_t>("count");
	int64_t io_size  = m_cmd.get<int64_t>("size");
    int thread_num = m_cmd.get<int>("file");

    vector<thread*> thread_pool;
    struct timeval old;
    struct timeval now;

    gettimeofday(&old, NULL);	// 线程安全
    for(int i = 0; i < thread_num; i++){
        thread *io_thread = new thread(&iorun_write, cafs_fd, io_count, io_size, m_cmd.get<string>("dir"), m_cmd.get<string>("name"), i);
        thread_pool.push_back(io_thread);
    }

    for(auto &iter:thread_pool) {
        iter->join();
        delete iter;
    }
    thread_pool.clear();

    gettimeofday(&now, NULL);	// 线程安全
    long long tims_us = (now.tv_sec - old.tv_sec)*1000000 + now.tv_usec - old.tv_usec;
    now.tv_sec = (tims_us/1000000);
    now.tv_usec = (tims_us%1000000);
    cout<<" write thread num: "<<thread_num<<endl;
    cout<<" write io size(KB): "<<(thread_num*io_count*io_size)<<" KB"<<endl;
    cout<<" write io size(MB): "<<(thread_num*io_count*io_size)/1024<<" MB"<<endl;
    cout<<" run times: "<<now.tv_sec<<"."<<setw(6)<<setfill('0')<<now.tv_usec<<endl;
    long tims_s = (now.tv_sec > 0)?now.tv_sec:1;
    cout<<" IOPS: "<<thread_num*io_count/tims_s<<" /s"<<endl;
    cout<<" Write KB/s: "<<(thread_num*io_count*io_size)/tims_s<<" KB/s"<<endl;
    cout<<" Write MB/s: "<<(thread_num*io_count*io_size)/tims_s/1024<<" MB/s"<<endl;

    gettimeofday(&old, NULL);	// 线程安全
    for(int i = 0; i < thread_num; i++){
        thread *io_thread = new thread(&iorun_read, cafs_fd, io_count, io_size, m_cmd.get<string>("dir"), m_cmd.get<string>("name"), i);
        thread_pool.push_back(io_thread);
    }

    for(auto &iter:thread_pool) {
        iter->join();
        delete iter;
    }

    gettimeofday(&now, NULL);	// 线程安全
    tims_us = (now.tv_sec - old.tv_sec)*1000000 + now.tv_usec - old.tv_usec;
    now.tv_sec = (tims_us/1000000);
    now.tv_usec = (tims_us%1000000);
    cout<<" read thread num: "<<thread_num<<endl;
    cout<<" read io size(KB): "<<(thread_num*io_count*io_size)<<" KB"<<endl;
    cout<<" read io size(MB): "<<(thread_num*io_count*io_size)/1024<<" MB"<<endl;
    cout<<" run times: "<<now.tv_sec<<"."<<setw(6)<<setfill('0')<<now.tv_usec<<endl;
    tims_s = (now.tv_sec > 0)?now.tv_sec:1;
    cout<<" IOPS: "<<thread_num*io_count/tims_s<<" /s"<<endl;
    cout<<" read KB/s: "<<(thread_num*io_count*io_size)/tims_s<<" KB/s"<<endl;
    cout<<" read MB/s: "<<(thread_num*io_count*io_size)/tims_s/1024<<" MB/s"<<endl;

    return 0;
}


cmd_qps::cmd_qps()
{
     m_cmd.add<string>("dir", 'd', "remote dir where to save test file", false, "/");
     m_cmd.add<int>("file", 'f', "file num for testing at the same time that on diffrent thread", false, 4);
     m_cmd.add<int64_t>("count", 'c', "the counts of qps test every time", false, 1000);
     m_cmd.add("help", 0, "help that show all options for qps");
}

void cmd_qps::usage() const
{
     cout<<endl<<"  ## <qps> ##"<<endl;
     cout<<"  descript: to test qps with cafstools(mkdir, open, close, rmdir)."<<endl;
     cout<<m_cmd.usage();
     cout<<"  exp: iotest --dir=/new_dir ; // to send file on dir[/new_dir/new_name_*]"<<endl;
     cout<<"  exp: iotest -f 4 -c 1000 ; // to send 4*1000 request with 4 thread"<<endl<<endl;
}

void cmd_qps::qps_test(const cafs_mount_handle_t cafs_fd, 
                    int64_t io_count,
					const std::string dir,
					int sn)
{
    int file_fd;
    int ret;
    struct stat stbuf;
    while(io_count-- > 0){
        string io_dir = dir + "/" +"cafs_dir_"+ to_string(sn);
        ret = cafs_mkdir(cafs_fd, io_dir.c_str(), 0777);
        if(ret) {
            cout<<"thread_"<<sn<<" can't create dir"<<io_dir<<endl;
            break;
        }
        string io_file = io_dir + "/" +"cafs_file_"+ to_string(sn);
        file_fd = cafs_open(cafs_fd, io_file.c_str(), O_CREAT|O_WRONLY, 0666);
        if(file_fd < 0) {
            cout<<"thread_"<<sn<<" can't create remote file "<<io_file<<endl;
            break;
        }
        cafs_close(cafs_fd, file_fd);

        ret = cafs_stat(cafs_fd, io_file.c_str(), &stbuf);
        if(ret) {
            cout<<"thread_"<<sn<<" can't stat file:"<<io_file<<endl;
            break;
        }

        ret = cafs_unlink(cafs_fd, io_file.c_str());
        if(ret) {
            cout<<"thread_"<<sn<<" can't delete file:"<<io_file<<endl;
            break;
        }

        ret = cafs_rmdir(cafs_fd, io_dir.c_str());
        if(ret) {
            cout<<"thread_"<<sn<<" can't delete dir:"<<io_dir<<endl;
            break;
        }
    }
    
    return;
}


int cmd_qps::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    if (!m_cmd.parse(args)){
        cerr<<m_cmd.error()<<endl;
        return -1;
    }
    int64_t count = m_cmd.get<int64_t>("count");
    int thread_num = m_cmd.get<int>("file");

    vector<thread*> thread_pool;
    struct timeval old;
    struct timeval now;

    gettimeofday(&old, NULL);	// 线程安全
    for(int i = 0; i < thread_num; i++){
        thread *io_thread = new thread(&qps_test, cafs_fd, count, m_cmd.get<string>("dir"), i);
        thread_pool.push_back(io_thread);
    }

    for(auto &iter:thread_pool) {
        iter->join();
        delete iter;
    }
    thread_pool.clear();

    gettimeofday(&now, NULL);	// 线程安全
    long long tims_us = (now.tv_sec - old.tv_sec)*1000000 + now.tv_usec - old.tv_usec;
    now.tv_sec = (tims_us/1000000);
    now.tv_usec = (tims_us%1000000);
    cout<<" qps thread num: "<<thread_num<<endl;
    cout<<" request count: "<<(thread_num * count * 5)<<endl;
    cout<<" run times: "<<now.tv_sec<<"."<<setw(6)<<setfill('0')<<now.tv_usec<<endl;
    long tims_s = (now.tv_sec > 0)?now.tv_sec:1;
    cout<<" IOPS: "<<(thread_num * count * 5)/ tims_s<<" /s"<<endl;
    cout<<" mkdir: "<<(thread_num * count)<<endl;
    cout<<" rmdir: "<<(thread_num * count)<<endl;
    cout<<" unlink: "<<(thread_num * count)<<endl;
    cout<<" stat: "<<(thread_num * count)<<endl;
    return 0;
}

void cmd_rm::usage() const
{
     cout<<endl<<"  ## <rm> ##"<<endl;
     cout<<"  descript: rm a file or a empty dir."<<endl;
     cout<<"  cmd: rm -r <path> "<<endl;
     cout<<"  exp: rm -r /home "<<endl;
     cout<<"  exp: rm file1 "<<endl;
     cout<<"  help: rm help "<<endl<<endl;
}

int cmd_rm::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;
    const char *cwd;
    if(args.size() < 2){
        return 0;
    }

    if (args[1] == "-r") {
        if (args.size() > 2) {
            cafs_rmdir(cafs_fd, args[2].c_str());
        }
    }else{
        cafs_unlink(cafs_fd, args[1].c_str());
    }

	return 0;
}

string cmd_rm::list_cwddir(const cafs_mount_handle_t cafs_fd) const
{
    int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;

    cwd = cafs_getcwd(cafs_fd);
    if(!cwd){
        cout<<"cafs_getcwd fail "<<endl;
        return "";
    }

    ret = cafs_opendir(cafs_fd, cwd, &dirp);
	if(ret){
        cout<<"cafs_opendir fail "<<endl;
        return "";
    }
    int i = 1;
    string list_print;
	while((pde = cafs_readdir(cafs_fd, dirp)) != NULL) {
        if(pde->d_name && DT_DIR == pde->d_type && 
            strcmp(pde->d_name, ".") != 0 && 
            strcmp(pde->d_name, "..") != 0){
            
            list_print +=string(pde->d_name)+"  ";
            if(i % 10 == 0) {
                list_print +="\n";
            }
            i++;
        }
	}

	ret = cafs_closedir(cafs_fd, dirp);
	if(ret){
        cout<<"cafs_closedir fail "<<endl;
    }

	return list_print;
}


string cmd_rm::show_param(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args, std::string &cmd_print) const
{
    int ret = 0;
	struct cafs_dir *dirp;
	const char *cwd;
	struct dirent *pde;

    if (args.size() <= 1) {
        cmd_print = list_cwddir(cafs_fd);
        return "";
    }

    vector<string>  path = split(args[1], "/");
    string realpath;
    string valid_path;
    string lastdir;
    for(auto &iter:path){
        if(!iter.size()){
            realpath +="/";
            valid_path = realpath;
            continue;
        }
        realpath +=iter + "/";
        ret = cafs_opendir(cafs_fd, realpath.c_str(), &dirp);
        if(ret || !dirp){
            lastdir = iter;
            break;
        }
        valid_path = realpath;
        cafs_closedir(cafs_fd, dirp);
    }
    
    if (valid_path.size() == 0){
        cwd = cafs_getcwd(cafs_fd);
        if(!cwd){
            cout<<"cafs_getcwd fail "<<endl;
            return "";
        }
        ret = cafs_opendir(cafs_fd, cwd, &dirp);
    }else{
        ret = cafs_opendir(cafs_fd, valid_path.c_str(), &dirp);
    }

	if(ret){
        cout<<"cafs_opendir fail: "<<valid_path<<endl;
        return "";
    }

    vector<string> dir_name;
	while((pde = cafs_readdir(cafs_fd, dirp)) != NULL) {
        if(!pde->d_name || DT_DIR != pde->d_type 
            || strcmp(pde->d_name, ".") == 0 
            || strcmp(pde->d_name, "..") == 0){
            continue;
        }
        if(string(pde->d_name).find(lastdir) != 0){
            continue;
        }
        dir_name.push_back(string(pde->d_name));
	}

    cafs_closedir(cafs_fd, dirp);

    if (dir_name.size() == 0) {
        return "";
    }

    if (dir_name.size() == 1) {
        valid_path += dir_name[0];
        return valid_path;
    }

    string comm_prefix;
    for (auto i = 0; i < dir_name.size(); i++) {
        cmd_print +=dir_name[i] + " ";
        //公共最长前缀
        comm_prefix = get_longest_comm_prefix(comm_prefix, dir_name[i]);
        if((i+1) % 10 == 0) {
            cmd_print +="\n";
        }
    }
    valid_path += comm_prefix;
	return valid_path;
}
void cmd_echo::usage() const
{
     cout<<endl<<"  ## <echo> ##"<<endl;
     cout<<"  descript: echo string to a file or new file."<<endl;
     cout<<"  cmd: echo \" string \" > newfile or echo \" string \" >> file"<<endl;
     cout<<"  help: echo help "<<endl<<endl;
}

int cmd_echo::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;
    const char *cwd;
    if(args.size() < 2){
        return 0;
    }
    if(args.size() < 4){
        cout<<endl<<args[1]<<endl;
        return 0;
    }

    string file_path=args[3];
    if (args[2] == ">") {
        int fd = cafs_open(cafs_fd, file_path.c_str(), O_CREAT|O_WRONLY, 0666);
        if (fd < 0) {
            return -1;
        }
        ret = cafs_write(cafs_fd, fd, args[1].c_str(), args[1].size(), 0);
        if (ret < 0) {
            cout<<"write data fail"<<endl;
        }
        cafs_close(cafs_fd, fd);

    }else if (args[2] == ">>"){
        int fd = cafs_open(cafs_fd, file_path.c_str(), O_CREAT|O_WRONLY, 0666);
        if (fd < 0) {
            return -1;
        }
        cafs_lseek(cafs_fd, fd, 0, SEEK_END);
        ret = cafs_write(cafs_fd, fd, args[1].c_str(), args[1].size(), -1);
        if (ret < 0) {
            cout<<"write data fail"<<endl;
        }
        cafs_close(cafs_fd, fd);
    }else{
        cout<<"unkown parameter: "<<args[2]<<endl;
        return -1;
    }

	return 0;
}

void cmd_cat::usage() const
{
     cout<<endl<<"  ## <cat> ##"<<endl;
     cout<<"  descript: print file context to stdio."<<endl;
     cout<<"  cmd: cat <path> "<<endl;
     cout<<"  help: cat help "<<endl<<endl;
}

int cmd_cat::run(const cafs_mount_handle_t cafs_fd, const std::vector<std::string> &args)
{
    int ret = 0;
    const char *cwd;
    if(args.size() < 2){
        return 0;
    }

    string file_path = args[1];

    int fd = cafs_open(cafs_fd, file_path.c_str(), O_RDONLY, 0666);
    if (fd < 0) {
        return -1;
    }
    char read_buf[1024] = {};
    int64_t offset = 0;
    int64_t read_size = 0;
    while(1){
        read_size = cafs_read(cafs_fd, fd, read_buf, sizeof(read_buf), offset);
        if (read_size <= 0) {
            break;
        }
        offset +=read_size;
        read_buf[read_size] = 0;
        cout<<string(read_buf);
    }
    cout<<endl;
    cafs_close(cafs_fd, fd);

	return 0;
}