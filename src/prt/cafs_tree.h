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

#ifndef _CAFS_TREE_H_
#define _CAFS_TREE_H_

#include "cafs_public.h"

#ifdef __cplusplus
extern "C" {
#endif

struct prt_tree_node{
	char *path;
	uint32_t path_len;
	uint64_t node_id;
	char node_ctx[0];
};

struct prt_tree_node *prt_create_tree(uint32_t id);
struct prt_tree_node *prt_insert(const char *path, uint32_t id, struct prt_tree_node *root);
const struct prt_tree_node *prt_search(const struct prt_tree_node *root, const char *path);
int prt_remove(const char *path, struct prt_tree_node *root);
void prt_destroy_tree(struct prt_tree_node *root);
void prt_dump_tree(const struct prt_tree_node *root);
#ifdef __cplusplus
}
#endif

#endif
