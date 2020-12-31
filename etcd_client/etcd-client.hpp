/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */

/*!
* \file xxx.x
* \brief xxx
* 
* 包含..
*
* \copyright 2020 Ruijie Network. All rights reserved.
* \author hongchunhua@ruijie.com.cn
* \version v1.0.0
* \date 2020.08.05
* \note none 
*/

#ifndef _ETCD_CLIENT_H_
#define _ETCD_CLIENT_H_

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


struct etcd_vector
{
  size_t size;
  void *ctx;
};


struct etcd_client_obj
{
  int flags;
  char ctx[0];
};

struct etcd_client_param
{
  const char *uri;
};

typedef int (*watch_cb_t)(const char *msg, void *usr_ctx);

struct etcd_client_obj *create_etcd_client(const struct etcd_client_param *param);
void destroy_etcd_client(struct etcd_client_obj *obj);

int etcd_list(struct etcd_client_obj *obj, const char *key, struct etcd_vector *vec);
const char *get_element(const struct etcd_vector *vec, size_t i);
void free_vector(struct etcd_vector *vec);

int etcd_request(struct etcd_client_obj *obj, const char *key, char *msg, uint32_t msg_len);
int etcd_watch(struct etcd_client_obj *obj, const char *key, watch_cb_t watch_call, void *usr_ctx);

/*
*key=key1|key2|key3
*
*/
struct json_obj
{
  void *ctx;
};

int json_parse(const char *jsonstr, struct json_obj *obj);
int json_getstring(const struct json_obj *obj, const char *key, char*val, uint32_t val_len);
int json_getint(const struct json_obj *obj, const char *key, int32_t *val);
int json_getuint(const struct json_obj *obj, const char *key, uint32_t *val);
int json_getint64(const struct json_obj *obj, const char *key, int64_t *val);
int json_getuint64(const struct json_obj *obj, const char *key, uint64_t *val);
void free_json_obj(struct json_obj *obj);

#ifdef __cplusplus
}
#endif

#endif /* _DENTRY_H */
