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

#ifndef _CAFS_PUBLIC_H_
#define _CAFS_PUBLIC_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>

#include "cafs_log.h"


#ifdef __cplusplus
extern "C" {
#endif

#ifndef	unlikely
#define unlikely(x)    __builtin_expect(!!(x), 0)
#endif

#define CAFS_ERR		-1
#define CAFS_OK		 	0

#define CAFS_NO			-1
#define CAFS_YES		 0

#define CAFS_TRUE		 1
#define CAFS_FALSE		 0

typedef uint8_t CAFS_BOOL;

#define CAFS_ALLOC(size, usr_context) malloc(size)
#define CAFS_FREE(p, usr_context) free(p)

#define SAFE_CAFS_FREE(p)\
do{\
	if (p){\
		CAFS_FREE(p, NULL);\
		p = NULL;\
	}\
}while(0);

#define SAFE_DESTROY_OBJ(obj, destroy_cb, ret)\
do{\
	if (obj){\
		ret = destroy_cb(obj);\
		if (!ret) {obj = NULL;};\
	}\
}while(0);

#define IS_SET(flag, tag) (flag&(tag))
#define SET_FLAG(flag, tag) flag=(flag|(tag))
#define CLR_FLAG(flag, tag) flag=(flag&~(tag))

// 互斥锁
struct cafs_mutex{
  pthread_mutex_t     lock;	    			/* lock */
  uint8_t is_inited;
};

inline static int cafs_mutex_init(struct cafs_mutex *m)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(pthread_mutex_init(&m->lock, NULL), CAFS_ERR, "mutex initialize fail.");
	m->is_inited = CAFS_TRUE;
	return CAFS_OK;
}

inline static int cafs_mutex_lock(struct cafs_mutex *m)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!m->is_inited, CAFS_ERR, "lock have not inited.");
	return pthread_mutex_lock(&m->lock);
}

inline static int cafs_mutex_unlock(struct cafs_mutex *m)
{
	LOG_THEN_RETURN_VAL_IF_TRUE(!m->is_inited, CAFS_ERR, "lock have not inited.");
	return pthread_mutex_unlock(&m->lock);
}

inline static int cafs_mutex_destroy(struct cafs_mutex *m)
{
	return m->is_inited ? pthread_mutex_destroy(&m->lock): 0;
}

// 读写锁
struct cafs_rwlock{
  pthread_rwlock_t lock;	    			/* lock */
};

inline static int cafs_rwlock_init(struct cafs_rwlock *rw)
{
	return pthread_rwlock_init(&rw->lock, NULL);
}

inline static int cafs_rwlock_rdlock(struct cafs_rwlock *rw)
{
	return pthread_rwlock_rdlock(&rw->lock);
}

inline static int cafs_rwlock_wrlock(struct cafs_rwlock *rw)
{
	return pthread_rwlock_wrlock(&rw->lock);
}

inline static int cafs_rwlock_unlock(struct cafs_rwlock *rw)
{
	return pthread_rwlock_unlock(&rw->lock);
}

inline static int cafs_rwlock_destroy(struct cafs_rwlock *rw)
{
	return pthread_rwlock_destroy(&rw->lock);
}


int is_file_not_existed(const char *file);

static inline void cafs_sleep(uint64_t s)
{
	struct timeval time;
	time.tv_sec = s;
	time.tv_usec = 0;
	select(0, NULL, NULL, NULL, &time);
	return;
}

static inline void cafs_usleep(uint64_t us)
{
	struct timeval time;
	time.tv_sec = 0;
	time.tv_usec = us;
	select(0, NULL, NULL, NULL, &time);
	return;
}

// 信号量
struct cafs_cond{
  pthread_cond_t cond;	    			/* cond */
  pthread_mutex_t     lock;	    			/* lock */
};

inline static int cafs_cond_init(struct cafs_cond *cond)
{
	pthread_mutex_init(&cond->lock, NULL); /* 初始化互斥锁 */
	pthread_cond_init(&cond->cond, NULL);	 /* 初始化条件变量 */
	return CAFS_OK;
}

inline static int cafs_cond_lock(struct cafs_cond *cond)
{
	return pthread_mutex_lock(&cond->lock);
}

inline static int cafs_cond_unlock(struct cafs_cond *cond)
{
	return pthread_mutex_unlock(&cond->lock);
}

inline static int cafs_cond_wait_timeout(struct cafs_cond *cond, uint64_t timeout_ms)
{
	struct timespec abstime;
	struct timeval now;
	uint64_t nsec;

	gettimeofday(&now, NULL);	// 线程安全
	nsec = now.tv_usec * 1000 + (timeout_ms % 1000) * 1000000;
	abstime.tv_sec=now.tv_sec + nsec / 1000000000 + timeout_ms / 1000;
	abstime.tv_nsec=nsec % 1000000000;
	return pthread_cond_timedwait(&cond->cond, &cond->lock, &abstime);
}

inline static int cafs_cond_wait(struct cafs_cond *cond)
{
	return pthread_cond_wait(&cond->cond, &cond->lock);
}

inline static int cafs_cond_notify(struct cafs_cond *cond)
{
	return pthread_cond_signal(&cond->cond);
}

inline static int cafs_cond_notify_all(struct cafs_cond *cond)
{
	return pthread_cond_broadcast(&cond->cond);
}

inline static int cafs_cond_destroy(struct cafs_cond *cond)
{
	pthread_cond_destroy(&cond->cond);
	pthread_mutex_destroy(&cond->lock);
	return 0;
}

const char *cafs_uri_get_resource_ptr(const char *uri);
const char *cafs_uri_get_port_ptr(const char *uri);
int cafs_uri_get_portal(const char *uri, char *portal, int portal_len);
int cafs_uri_get_resource(const char *uri, char *resource, int resource_len);
int cafs_uri_get_proto(const char *uri, char *proto, int proto_len);

#ifdef __cplusplus
}
#endif

#endif /*XIO_API_H */
