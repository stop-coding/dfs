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

#include "cafs_public.h"

#include <unistd.h>
/*!
 *  @brief  
 *
 *  @param[inout] file 
 *  @return  int; (<em>-1</em>: fail ; ( <em>0</em>: succeed
 *
 */
int is_file_not_existed(const char *file)
{
  if (!file) {
    return -1;
  }

  return access(file, F_OK);
}

const char *cafs_uri_get_resource_ptr(const char *uri)
{
	const char *start;
	const char *p1, *p2 = NULL;

	start = strstr(uri, "://");
	if (!start)
		return NULL;
	return start + 3;
}

const char *cafs_uri_get_port_ptr(const char *uri)
{
	const char *start;

	start = cafs_uri_get_resource_ptr(uri);
	if (!start)
		return NULL;
	start = strstr(start, ":");
	return start + 1;
}


int cafs_uri_get_portal(const char *uri, char *portal, int portal_len)
{
	const char *res = cafs_uri_get_port_ptr(uri);
	int len = (res) ? strlen(res) : 0;

	if (len < portal_len && len > 0) {
		strncpy(portal, res, len);
		portal[len] = 0;
		return 0;
	}

	return -1;
}

/*---------------------------------------------------------------------------*/
/* cafs_uri_get_resource							     */
/*---------------------------------------------------------------------------*/
int cafs_uri_get_resource(const char *uri, char *resource, int resource_len)
{
	const char *res ;
	const char *port;
	int  len, port_len;

	res = cafs_uri_get_resource_ptr(uri);
	if (res) {
		len = strlen(res);
		port = cafs_uri_get_port_ptr(uri);
		if (port) {
			port_len = strlen(port);
			if (port_len) {
				len -= (port_len + 1);
			}
		}
		if (len < resource_len) {
			strncpy(resource, res, len);
			resource[len] = 0;
			return 0;
		}
	}
	return -1;
}

int cafs_uri_get_proto(const char *uri, char *proto, int proto_len)
{
	char *start = (char *)uri;
	const char *end;
	char *p;
	int  i;

	end = strstr(uri, "://");
	if (!end)
		return -1;

	p = start;
	for (i = 0; i < proto_len; i++) {
		if (p == end) {
			proto[i] = 0;
			return 0;
		}
		proto[i] = *p;
		p++;
	}

	return -1;
}