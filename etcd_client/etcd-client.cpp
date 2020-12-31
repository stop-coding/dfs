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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "etcd-client.hpp"

#include <thread>
#include <vector>
#include "etcd/Client.hpp"
#include "etcd/SyncClient.hpp"
#include "etcd/Watcher.hpp"
#include "json/json.h"

#define ETCD_LOG_ERROR(format, arg...)
	    //fprintf(stderr, 	"[   ETCD] [ ERROR] file:%s func: %s|%d --- " format "\n", __FILE__, __FUNCTION__, __LINE__, ##arg)
#define ETCD_LOG_NOTICE(format, arg...)
	//syslog(LOG_NOTICE, "[   ETCD] [NOTICE] func: %s|%d --- " format "\n",__FUNCTION__, __LINE__, ##arg);\
	//fprintf(stdout, "[   ETCD] [NOTICE] func: %s|%d --- " format "\n",__FUNCTION__, __LINE__, ##arg)

#define unlikely(x)    __builtin_expect(!!(x), 0)

#define LOG_THEN_GOTO_TAG_IF_VAL_TRUE(val, tag, format, arg...)	\
do{\
	if(unlikely((val))){\
		ETCD_LOG_ERROR(format,##arg);\
		goto tag;\
	}\
}while(0);

#define LOG_THEN_RETURN_IF_VAL_TRUE(val, format, arg...)	\
do{\
	if(unlikely((val))){\
		ETCD_LOG_ERROR(format,##arg);\
		return;\
	}\
}while(0);

#define LOG_THEN_RETURN_VAL_IF_TRUE(val, ret, format, arg...)\
do{\
	if(unlikely((val))){\
		ETCD_LOG_ERROR(format, ##arg);\
		return ret;\
	}\
}while(0);

//
namespace etcd_cli {
  class etcd_obj
  {
    public:
        etcd_obj(const std::string &uri)
        { 
            m_etcd_uri = uri;
            isstop = false;
        }
        etcd_obj(){
            m_etcd_uri = "http://127.0.0.1:2379";
            isstop = false;
        }
        ~etcd_obj();
        int etcd_request(const std::string &key, std::string &msg);
        int etcd_ls(const std::string &key, std::vector<std::string> &list);
        int etcd_watch(const std::string &key, std::function<int(const char *, void *)> callback, void *ctx);
    private:
        std::string m_etcd_uri;
        bool isstop;
        std::vector<etcd::Watcher*> m_watch_set;
  };
}

// c++
etcd_cli::etcd_obj::~etcd_obj()
{
    isstop = true;
    for(auto &iter:m_watch_set){
        iter->Cancel();
    }
}

int etcd_cli::etcd_obj::etcd_request(const std::string &key, std::string &msg)
{
    etcd::SyncClient etcd(m_etcd_uri);

    etcd::Response rsp = etcd.get(key);
    LOG_THEN_RETURN_VAL_IF_TRUE(0 != rsp.error_code(), -1, "get the key[%s] fail", key.c_str());
    msg = rsp.value().as_string();
    ETCD_LOG_ERROR("%s", msg.c_str());
    return 0;
}

int etcd_cli::etcd_obj::etcd_ls(const std::string &key, std::vector<std::string> &list)
{
    etcd::SyncClient etcd(m_etcd_uri);

    etcd::Response rsp = etcd.ls(key);
    LOG_THEN_RETURN_VAL_IF_TRUE(!rsp.is_ok(), -1, "get the key[%s] fail", key.c_str());
    list = rsp.keys();
    return 0;
}


int etcd_cli::etcd_obj::etcd_watch(const std::string &key, std::function<int(const char *, void *)> callback, void *ctx)
{
    etcd::Watcher *watcher = new etcd::Watcher(m_etcd_uri, key, 
        [=](const etcd::Response &resp){
            try{
                std::cout << resp.action() << " " << resp.value().as_string() << std::endl;
                if (callback){
                    callback(resp.value().as_string().c_str(), ctx);
                }
            }
            catch(...) {
                ETCD_LOG_ERROR("some err, callback:%p, ctx:%p", callback, ctx);
            }
            if(!isstop) {
                etcd_watch(key, callback, ctx);
            }
        }, 
        true);
    m_watch_set.push_back(watcher);

    /*m_watch_set.push_back();
    m_wach->watch(key, true).then([=](pplx::task<etcd::Response> resp_task)
    {
        try{
            etcd::Response resp = resp_task.get();
            std::cout << resp.action() << " " << resp.value().as_string() << std::endl;
            if (callback){
                ETCD_LOG_ERROR("callback:%p, ctx:%p", callback, ctx);
                callback(resp.value().as_string().c_str(), ctx);
            }
        }
        catch(...) {
            ETCD_LOG_ERROR("some err, callback:%p, ctx:%p", callback, ctx);
        }
        if(!isstop) {
            etcd_watch(key, callback, ctx);
        }
    });*/
    return 0;
}


#ifdef __cplusplus
extern "C" {
#endif

struct etcd_ctx
{
    etcd_cli::etcd_obj *etcd;
};


#define ETCD_CTX(ctx_name, obj, ret)\
struct etcd_ctx *ctx_name;\
LOG_THEN_RETURN_VAL_IF_TRUE(!obj, ret, "obj is null");\
ctx_name = (struct etcd_ctx *)obj->ctx;

struct etcd_client_obj *create_etcd_client(const struct etcd_client_param *param)
{
    struct etcd_client_obj *obj = NULL;
    struct etcd_ctx *ctx;
    LOG_THEN_RETURN_VAL_IF_TRUE(!param->uri, NULL, "uri is null");
    obj = (struct etcd_client_obj *)calloc(1, sizeof(struct etcd_client_obj) + sizeof(struct etcd_ctx));
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, NULL, "calloc fail");

    ctx = (struct etcd_ctx*)obj->ctx;
    ctx->etcd = new etcd_cli::etcd_obj(std::string(param->uri));
    return obj;
}

void destroy_etcd_client(struct etcd_client_obj *obj)
{
    ETCD_CTX(ctx, obj, ;);
    if(ctx->etcd){
        delete ctx->etcd;
        ctx->etcd = NULL;
    }
    free(obj);

    return;
}

int etcd_request(struct etcd_client_obj *obj, const char *key, char *msg, uint32_t msg_len)
{
    int ret;
    std::string rsp_msg;
    ETCD_CTX(ctx, obj, -1);

    LOG_THEN_RETURN_VAL_IF_TRUE(!key, -1, "key is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!msg, -1, "msg is null.");

    ret = ctx->etcd->etcd_request(std::string(key), rsp_msg);
    LOG_THEN_RETURN_VAL_IF_TRUE(ret, -1, "etcd_sync_request fail");
    
    LOG_THEN_RETURN_VAL_IF_TRUE(rsp_msg.length() >= msg_len, -1, 
                                "msg_len[%u] is low with rsp msg len[%u]", 
                                msg_len,
                                (uint32_t)rsp_msg.length());
    memcpy(msg, rsp_msg.c_str(), rsp_msg.length());
    msg[rsp_msg.length()] = '\0';
    return 0;
}

int etcd_list(struct etcd_client_obj *obj, const char *key, struct etcd_vector *vec)
{
    int ret;
    size_t i;
    std::vector<std::string> *plist;
    ETCD_CTX(ctx, obj, -1);

    LOG_THEN_RETURN_VAL_IF_TRUE(!key, -1, "key is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!vec, -1, "vec is null.");

    plist  = new std::vector<std::string>;//TODO 异常

    ret = ctx->etcd->etcd_ls(std::string(key), *plist);
    LOG_THEN_RETURN_VAL_IF_TRUE(ret, -1, "etcd_sync_request fail");
    vec->size = plist->size();

    if (vec->size == 0) {
        delete plist;
        vec->ctx = NULL;
        return 0;
    }
    vec->ctx = plist;
    return 0;
}

const char *get_element(const struct etcd_vector *vec, size_t i)
{
    LOG_THEN_RETURN_VAL_IF_TRUE(!vec, NULL, "vec is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!vec->ctx, NULL, "ctx is null");

    std::vector<std::string> &vec_obj = (*(std::vector<std::string> *)vec->ctx);
    LOG_THEN_RETURN_VAL_IF_TRUE(vec_obj.size() <= i, NULL, "i[%u] is over max[%u].", i, vec_obj.size());
    return vec_obj[i].c_str();
}

void free_vector(struct etcd_vector *vec)
{
    if(!vec || !vec->ctx){
        return;
    }
    delete (std::vector<std::string> *)vec->ctx;
    vec->size = 0;
    vec->ctx = NULL;
    return;
}




int etcd_watch(struct etcd_client_obj *obj, const char *key, watch_cb_t watch_call, void *usr_ctx)
{
    ETCD_CTX(ctx, obj, -1);

    LOG_THEN_RETURN_VAL_IF_TRUE(!ctx->etcd, -1, "etcd object is null");
    LOG_THEN_RETURN_VAL_IF_TRUE(!key, -1, "key is null.");

    return ctx->etcd->etcd_watch(std::string(key), watch_call, usr_ctx);
}

int json_parse(const char *jsonstr, struct json_obj *obj)
{
    int ret;
    Json::Value *root;
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;

    LOG_THEN_RETURN_VAL_IF_TRUE(!jsonstr, -1, "jsonstr null");
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, -1, "obj null");

    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    
    root = new Json::Value;
    ret = reader->parse(jsonstr, jsonstr + strlen(jsonstr), root, &err);
    LOG_THEN_GOTO_TAG_IF_VAL_TRUE(!ret, delete_ptr, "parse[%s] fail", jsonstr);
    obj->ctx = root;
    return 0;
delete_ptr:
    delete root;
    obj->ctx =NULL;
    return -1;
}

static void SplitString(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while(std::string::npos != pos2)
     {
         v.push_back(s.substr(pos1, pos2-pos1));
         pos1 = pos2 + c.size();
         pos2 = s.find(c, pos1);
     }
     if(pos1 != s.length())
         v.push_back(s.substr(pos1));
}

static bool StringisNum(std::string str)  
{  
     for (int i = 0; i < str.size(); i++)
     {
         int tmp = (int)str[i];
         if (tmp >= 48 && tmp <= 57)
         {
            continue;
         }
        else
         {
             return false;
         }
     } 
     return true;
 }  

int json_getstring(const struct json_obj *obj, const char *key, char *val, uint32_t val_len)
{
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, -1, "obj is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj->ctx, -1, "obj ctx is null.");

    Json::Value *find_node = (Json::Value *)obj->ctx;
    std::vector<std::string> keys;

    SplitString(std::string(key), keys, "|");
    LOG_THEN_RETURN_VAL_IF_TRUE(!keys.size(), -1, "keys [%s] is null.");

    for(auto iter = keys.begin(); iter != keys.end(); iter++) {
        if(StringisNum((*iter))){
            LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isArray(), -1, "key [%s] find is not array.", (*iter).c_str());
            int index = stoi((*iter));
            LOG_THEN_RETURN_VAL_IF_TRUE(index < 0, -1, "index[%d] is negative.", index);
            LOG_THEN_RETURN_VAL_IF_TRUE((uint32_t)index >= find_node->size(), -1, "index[%d] is over.", index);
            find_node = &(*find_node)[index];
        }else{
            LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isArray(), -1, "key [%s] find is array.", (*iter).c_str());
            find_node = &(*find_node)[(*iter)];
        }
        LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isNull(), -1, "key [%s] find is null.", (*iter).c_str());
    }
    const std::string value_str = find_node->asString();
    LOG_THEN_RETURN_VAL_IF_TRUE(val_len <= value_str.length(), -1, "value [%s] out fail", value_str.c_str());
    memcpy(val, value_str.c_str(), value_str.length());
    val[value_str.length()] = '\0';

    return 0;
}

int json_getint(const struct json_obj *obj, const char *key, int32_t *val)
{
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, -1, "obj is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj->ctx, -1, "obj ctx is null.");

    Json::Value *find_node = (Json::Value *)obj->ctx;
    std::vector<std::string> keys;

    SplitString(std::string(key), keys, "|");
    LOG_THEN_RETURN_VAL_IF_TRUE(!keys.size(), -1, "keys [%s] is null.");

    for(auto iter = keys.begin(); iter != keys.end(); iter++) {
        if(StringisNum((*iter))){
            LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isArray(), -1, "key [%s] find is not array.", (*iter).c_str());
            int index = stoi((*iter));
            LOG_THEN_RETURN_VAL_IF_TRUE(index < 0, -1, "index[%d] is negative.", index);
            LOG_THEN_RETURN_VAL_IF_TRUE((uint32_t)index >= find_node->size(), -1, "index[%d] is over.", index);
            find_node = &(*find_node)[index];
        }else{
            LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isArray(), -1, "key [%s] find is array.", (*iter).c_str());
            find_node = &(*find_node)[(*iter)];
        }
        LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isNull(), -1, "key [%s] find is null.", (*iter).c_str());
    }
    LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isInt(), -1, "keys [%s] find is not int.", key);
    *val = find_node->asInt();

    return 0;
}

int json_getuint(const struct json_obj *obj, const char *key, uint32_t *val)
{
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, -1, "obj is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj->ctx, -1, "obj ctx is null.");

    Json::Value *find_node = (Json::Value *)obj->ctx;
    std::vector<std::string> keys;

    SplitString(std::string(key), keys, "|");
    LOG_THEN_RETURN_VAL_IF_TRUE(!keys.size(), -1, "keys [%s] is null.");

    for(auto iter = keys.begin(); iter != keys.end(); iter++) {
        if(StringisNum((*iter))){
            LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isArray(), -1, "key [%s] find is not array.", (*iter).c_str());
            int index = stoi((*iter));
            LOG_THEN_RETURN_VAL_IF_TRUE(index < 0, -1, "index[%d] is negative.", index);
            LOG_THEN_RETURN_VAL_IF_TRUE((uint32_t)index >= find_node->size(), -1, "index[%d] is over.", index);
            find_node = &(*find_node)[index];
        }else{
            LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isArray(), -1, "key [%s] find is array.", (*iter).c_str());
            find_node = &(*find_node)[(*iter)];
        }
        LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isNull(), -1, "key [%s] find is null.", (*iter).c_str());
    }
    LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isUInt(), -1, "keys [%s] find is not int.", key);
    *val = find_node->asUInt();

    return 0;
}

int json_getint64(const struct json_obj *obj, const char *key, int64_t *val)
{
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, -1, "obj is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj->ctx, -1, "obj ctx is null.");

    Json::Value *find_node = (Json::Value *)obj->ctx;
    std::vector<std::string> keys;

    SplitString(std::string(key), keys, "|");
    LOG_THEN_RETURN_VAL_IF_TRUE(!keys.size(), -1, "keys [%s] is null.");

    for(auto iter = keys.begin(); iter != keys.end(); iter++) {
        if(StringisNum((*iter))){
            LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isArray(), -1, "key [%s] find is not array.", (*iter).c_str());
            int index = stoi((*iter));
            LOG_THEN_RETURN_VAL_IF_TRUE(index < 0, -1, "index[%d] is negative.", index);
            LOG_THEN_RETURN_VAL_IF_TRUE((uint32_t)index >= find_node->size(), -1, "index[%d] is over.", index);
            find_node = &(*find_node)[index];
        }else{
            LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isArray(), -1, "key [%s] find is array.", (*iter).c_str());
            find_node = &(*find_node)[(*iter)];
        }
        LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isNull(), -1, "key [%s] find is null.", (*iter).c_str());
    }
    LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isInt64(), -1, "keys [%s] find is not Int64.", key);
    *val = find_node->asInt64();

    return 0;
}

int json_getuint64(const struct json_obj *obj, const char *key, uint64_t *val)
{
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj, -1, "obj is null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!obj->ctx, -1, "obj ctx is null.");

    Json::Value *find_node = (Json::Value *)obj->ctx;
    std::vector<std::string> keys;

    SplitString(std::string(key), keys, "|");
    LOG_THEN_RETURN_VAL_IF_TRUE(!keys.size(), -1, "keys [%s] is null.");

    for(auto iter = keys.begin(); iter != keys.end(); iter++) {
        if(StringisNum((*iter))){
            LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isArray(), -1, "key [%s] find is not array.", (*iter).c_str());
            int index = stoi((*iter));
            LOG_THEN_RETURN_VAL_IF_TRUE(index < 0, -1, "index[%d] is negative.", index);
            LOG_THEN_RETURN_VAL_IF_TRUE((uint32_t)index >= find_node->size(), -1, "index[%d] is over.", index);
            find_node = &(*find_node)[index];
        }else{
            LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isArray(), -1, "key [%s] find is array.", (*iter).c_str());
            find_node = &(*find_node)[(*iter)];
        }
        LOG_THEN_RETURN_VAL_IF_TRUE(find_node->isNull(), -1, "key [%s] find is null.", (*iter).c_str());
    }
    LOG_THEN_RETURN_VAL_IF_TRUE(!find_node->isUInt64(), -1, "keys [%s] find is not UInt64.", key);
    *val = find_node->asUInt64();

    return 0;
}

void free_json_obj(struct json_obj *obj)
{
    if(obj->ctx){
        delete (Json::Value *)obj->ctx;
        obj->ctx =NULL;
    }
}
#ifdef __cplusplus
}
#endif
