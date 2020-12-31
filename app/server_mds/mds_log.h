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

#ifndef _MDS_LOG_H_
#define _MDS_LOG_H_

#include <cafs_log.h>



#ifdef __cplusplus
extern "C" {
#endif

//#define CAFS_DEBUG_ON
#define MDS_LOG_ERROR(format, arg...) \
	cafs_vlog(CAFS_LOG_LEVEL_E_ERROR, "MDS", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define MDS_LOG_WARN(format, arg...) \
	cafs_vlog(CAFS_LOG_LEVEL_E_WARN, "MDS", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define MDS_LOG_NOTICE(format, arg...) \
	cafs_vlog(CAFS_LOG_LEVEL_E_INFO, "MDS", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define MDS_LOG_DEBUG(format, arg...)\
	 cafs_vlog(CAFS_LOG_LEVEL_E_DEBUG, "MDS", __FILE__, __LINE__, __FUNCTION__, format, ##arg);
#define MDS_LOG_TRACE(format, arg...)\
	 cafs_vlog(CAFS_LOG_LEVEL_E_TRACE, "MDS", __FILE__, __LINE__, __FUNCTION__, format, ##arg);

#ifdef __cplusplus
}
#endif

#endif /*XIO_API_H */
