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

#ifndef _CAFS_LOG_H_
#define _CAFS_LOG_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>


#ifdef __cplusplus
extern "C" {
#endif

enum cafs_log_level{
	CAFS_LOG_LEVEL_E_FATAL = 0,
	CAFS_LOG_LEVEL_E_ERROR,
	CAFS_LOG_LEVEL_E_WARN,
	CAFS_LOG_LEVEL_E_INFO,
	CAFS_LOG_LEVEL_E_DEBUG,
	CAFS_LOG_LEVEL_E_TRACE,
	CAFS_LOG_LEVEL_E_MAX,
};
void cafs_vlog(enum cafs_log_level level, const char *module, const char *file,unsigned line, const char *function, const char *fmt, ...);

//#define CAFS_DEBUG_ON
#define CAFS_LOG_ERROR(format, arg...) \
	cafs_vlog(CAFS_LOG_LEVEL_E_ERROR, "CA", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define CAFS_LOG_WARN(format, arg...) \
	cafs_vlog(CAFS_LOG_LEVEL_E_WARN, "CA", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define CAFS_LOG_NOTICE(format, arg...) \
	cafs_vlog(CAFS_LOG_LEVEL_E_INFO, "CA", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define CAFS_LOG_DEBUG(format, arg...)\
	 cafs_vlog(CAFS_LOG_LEVEL_E_DEBUG, "CA", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define CAFS_LOG_TRACE(format, arg...)\
	 cafs_vlog(CAFS_LOG_LEVEL_E_TRACE, "CA", __FILE__, __LINE__, __FUNCTION__, format, ##arg);

#define unlikely(x)    __builtin_expect(!!(x), 0)

#define LOG_THEN_GOTO_TAG_IF_VAL_TRUE(val, tag, format, arg...)	\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format,##arg);\
		goto tag;\
	}\
}while(0);

#define LOG_EXC_GOTO__IF_VAL_TRUE(val, exc, tag, format, arg...)	\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format,##arg);\
		exc;\
		goto tag;\
	}\
}while(0);

#define LOG_THEN_RETURN_IF_VAL_TRUE(val, format, arg...)	\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format,##arg);\
		return;\
	}\
}while(0);

#define LOG_EXC_RETURN_IF_VAL_TRUE(val, exc, format, arg...)	\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format,##arg);\
		exc;\
		return;\
	}\
}while(0);

#define LOG_THEN_RETURN_VAL_IF_TRUE(val, ret, format, arg...)\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format, ##arg);\
		return ret;\
	}\
}while(0);

// 一些场景，不需要报错
#define LOG_DEBUG_GOTO_TAG_IF_VAL_TRUE(val, tag, format, arg...)	\
do{\
	if(unlikely((val))){\
		CAFS_LOG_DEBUG(format,##arg);\
		goto tag;\
	}\
}while(0)
// 一些场景，不需要报错，如查找文件是否存在
#define LOG_DEBUG_RETURN_VAL_IF_TRUE(val, ret, format, arg...)\
do{\
	if(unlikely((val))){\
		CAFS_LOG_DEBUG(format, ##arg);\
		return ret;\
	}\
}while(0);

#define LOG_EXC_RETURN_VAL_IF_TRUE(val, exc, ret, format, arg...)\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format, ##arg);\
		exc;\
		return ret;\
	}\
}while(0);

#define CAFS_ASSERT(condition, format, arg...)	\
do{\
	if(unlikely((!condition))){\
		CAFS_LOG_ERROR(format, ##arg);\
		assert(condition);\
	}\
}while(0);

#define LOG_ERROR_IF_VAL_TRUE(val, format, arg...)	\
do{\
	if(unlikely((val))){\
		CAFS_LOG_ERROR(format,##arg);\
	}\
}while(0);

#ifdef __cplusplus
}
#endif

#endif /*XIO_API_H */
