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
#include "cafs_common.h"


CAFS_BOOL is_sub_dir(const char *root_dir, const char *sub_dir)
{
    return (strncmp(root_dir, sub_dir, strlen(root_dir)) == 0)?CAFS_TRUE: CAFS_FALSE;
}

uint32_t get_parent_dir(const char *cwd_path, char *parent_buf, uint32_t buf_len)
{
    uint32_t parent_len = 0;
    uint32_t i, cwd_len;
    LOG_THEN_RETURN_VAL_IF_TRUE(!cwd_path, 0, "cwd_path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!parent_buf, 0, "parent null.");
    
    if (strcmp(cwd_path, "/") == 0) {
        parent_buf[0] = '/';
        parent_len = 1;
    }else if (strncmp(cwd_path, "/", 1) == 0){
        cwd_len = strlen(cwd_path);
        LOG_THEN_RETURN_VAL_IF_TRUE(cwd_len > buf_len, 0, "buf len small.");
        for ( i = cwd_len - 1; i > 0; i--) {
            if (cwd_path[i -1] == '/') {
                break;
            }
        }
        memcpy(parent_buf, cwd_path, i);
        parent_len = i;
    }else {
        parent_len = 0;
    }
    parent_buf[parent_len] = '\0';
    return parent_len;
}

uint32_t get_parent_dir_on_root(const char *root_path, const char *child_path, char *parent_buf, uint32_t buf_len)
{
    uint32_t parent_len = 0;
    uint32_t i, cwd_len;
    int flag = 0;
    const char *cpy;
    LOG_THEN_RETURN_VAL_IF_TRUE(!root_path, 0, "root_path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!child_path, 0, "child_path null.");
    
    if (strncmp(child_path, root_path, strlen(root_path)) == 0) {
        cwd_len = strlen(child_path);
        for(i = cwd_len; i > 0; i--){
            if(child_path[i - 1] == '/'){
                if(flag){
                    break;
                }
                continue;
            }
            flag = 1;
        }
        if (i > 0) {
            parent_len = i;
            cpy = child_path;
        }else{
            parent_len = strlen(root_path);
            cpy = root_path;
        }
    }else{
        parent_len = strlen(root_path);
        cpy = root_path;
    }
    if (parent_buf && buf_len > parent_len ) {
        memcpy(parent_buf, cpy, parent_len);
        parent_buf[parent_len] = '\0';
    }
    return parent_len;
}

static int is_repeat(const char *path, uint32_t path_len, uint32_t *next_path_offset)
{
    if (path[0] == '/') {
        *next_path_offset = 1;
        return 1;
    }
    return 0;
}

static int is_cur(const char *path, uint32_t path_len, uint32_t *next_path_offset)
{
    if (path_len > 1 && strncmp(path, "./", 2) == 0) {
        *next_path_offset = 2;
        return 1;
    }else if (path_len == 1 && path[0] == '.') {
        *next_path_offset = 1;
        return 1;
    }
    return 0;
}

static int is_pre(const char *path, uint32_t path_len, uint32_t *next_path_offset)
{
    if (path_len > 2 && strncmp(path, "../", 2) == 0) {
        *next_path_offset = 3;
        return 1;
    }else if (path_len == 2 && strcmp(path, "..") == 0) {
        *next_path_offset = 2;
        return 1;
    }
    return 0;
}

static int is_dir(const char *path, uint32_t path_len, uint32_t *next_path_offset)
{
    uint32_t i;

    if (path[0] != '/') {
        for(i =0; i < path_len; i++) {
            if(path[i] == '/'){
                *next_path_offset = i + 1;
                return 1;
            }
        }
        *next_path_offset = i;
        return 1;
    }
    return 0;
}

static int is_same_dir(const char *path1, const char *path2)
{
    uint32_t i;
    uint32_t cmp_len;
    uint32_t path1_len = strlen(path1);
    uint32_t path2_len = strlen(path2);
    if (path1_len < path2_len) {
        cmp_len = path1_len;
        for (i = path1_len; i < path2_len; i++) {
            if(path2[i] != '/') {
                return 0;
            }
        }
    }else if (path1_len > path2_len) {
        cmp_len = path2_len;
        for (i = path2_len; i < path1_len; i++) {
            if(path1[i] != '/') {
                return 0;
            }
        }
    }else{
        cmp_len = path1_len;
    }

    if (strncmp(path1, path2, cmp_len) != 0) {
        return 0;
    }

    return 1;
}

int get_abspath(const char *path, const char *root_path, const char *cwd_path, char *new_path, uint32_t buf_len)
{
    int ret = 0;
    uint32_t path_len = 0;
    uint32_t parent_len = 0;
    uint32_t i;
    uint32_t path_start = 0;
    uint32_t new_path_len = 0;
    uint32_t split_len = 0;

    LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!cwd_path, CAFS_ERR, "cwd_path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!new_path, CAFS_ERR, "new_path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!root_path, CAFS_ERR, "root_path null.");

    path_len = strlen(path);
    LOG_THEN_RETURN_VAL_IF_TRUE(!path_len, CAFS_ERR, "path_len is 0.");
    
    if (path_len && path[0] == '/') {
         memcpy(new_path, root_path, strlen(root_path));
         path_start = 1;
         new_path_len =strlen(root_path);
         LOG_THEN_RETURN_VAL_IF_TRUE((new_path_len>=buf_len), (-ENOENT), 
                        "new path buf over, max:%u, but now offset:%u.", buf_len, new_path_len);
    }else if (path_len && strncmp(path, "..", 2) == 0) {
        new_path_len = get_parent_dir_on_root(root_path, cwd_path, new_path, buf_len);
        path_start = 2;
        LOG_THEN_RETURN_VAL_IF_TRUE((new_path_len>=buf_len), (-ENOENT), 
                        "new path buf over, max:%u, but now offset:%u.", buf_len, new_path_len);
    }else if (path_len && path[0] == '.') {
        memcpy(new_path, cwd_path, strlen(cwd_path));
        path_start = 1;
        new_path_len =strlen(cwd_path);
        LOG_THEN_RETURN_VAL_IF_TRUE((new_path_len>=buf_len), (-ENOENT), 
                        "new path buf over, max:%u, but now offset:%u.", buf_len, new_path_len);
    }else{
        memcpy(new_path, cwd_path, strlen(cwd_path));
        path_start = 0;
        new_path_len =strlen(cwd_path);
        LOG_THEN_RETURN_VAL_IF_TRUE((new_path_len>=buf_len), (-ENOENT), 
                        "new path buf over, max:%u, but now offset:%u.", buf_len, new_path_len);
    }

    for (i = path_start; i < path_len; i +=split_len) {
        if (is_repeat(path + i, path_len - i, &split_len)){
            CAFS_LOG_DEBUG("repeat path:%s, i:%u split_len:%u",path + i, i, split_len);
            continue;
        }

        if (is_cur(path + i, path_len - i, &split_len)){
            CAFS_LOG_DEBUG("cur path:%s, i:%u split_len:%u",path + i, i, split_len);
            continue;
        }

        if (is_pre(path + i, path_len - i, &split_len)){
            CAFS_LOG_DEBUG("pre path:%s, i:%u split_len:%u",path + i, i, split_len);
            new_path_len = get_parent_dir_on_root(root_path, new_path, NULL, 0);
            new_path[new_path_len] = 0;
            continue;
        }

        if (is_dir(path + i, path_len - i, &split_len)){
            CAFS_LOG_DEBUG("copy path:%s, i:%u split_len:%u",path + i, i, split_len);
            memcpy(new_path + new_path_len, path + i, split_len);
            new_path_len +=split_len;
            LOG_THEN_RETURN_VAL_IF_TRUE((new_path_len>=buf_len), (-ENOENT), 
                        "new path buf over, max:%u, but now offset:%u.", buf_len, new_path_len);
            continue;
        }
        CAFS_LOG_DEBUG("invalid path, user path:%s, cur [%u][%s], root path:%s, cwd path:%s", path, i, (path + i), root_path, cwd_path);
        return (-ENOENT);
    }
    if (!is_sub_dir(root_path, new_path)) {
        memcpy(new_path, root_path, strlen(root_path));
        new_path_len = strlen(root_path);
    }
    LOG_THEN_RETURN_VAL_IF_TRUE((new_path_len + 1 >= buf_len), (-ENOENT), 
                        "new path buf over, max:%u, but now offset:%u.", buf_len, new_path_len);

    if(new_path[new_path_len -1] != '/') {
        new_path[new_path_len] = '/';
        new_path_len++;
    }
    new_path[new_path_len] = '\0';
    CAFS_LOG_DEBUG("user path:%s, root path:%s, cwd path:%s new path:%s",path, root_path, cwd_path, new_path);
    return 0;
}

int check_valid_path(const char *path)
{
	return 0;
}

const char *get_usr_cwdpath(const char *root_path, const char *cwd_path)
{
    uint32_t root_len = 0;
    uint32_t cwd_len = 0;
    uint32_t i;

    LOG_THEN_RETURN_VAL_IF_TRUE(!root_path, NULL, "root_path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!cwd_path, NULL, "cwd_path null.");
    
    LOG_THEN_RETURN_VAL_IF_TRUE(!is_sub_dir(root_path, cwd_path), NULL, 
                                "not sub dir, root_path[%s], cwd_path[%s].",root_path, cwd_path);

    root_len = strlen(root_path);
    cwd_len = strlen(cwd_path);
    LOG_THEN_RETURN_VAL_IF_TRUE(cwd_len < root_len, NULL, "cwd_len invalid.");
    if (root_path[0] == '/' && root_len <= 1) {
        return cwd_path;
    }

    return &cwd_path[root_len - 1];
}
int get_abspath_r(const char *path, char *new_path, uint32_t buf_len)
{
    uint32_t path_len = 0;
    LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!new_path, CAFS_ERR, "new_path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(path[0] != '/', CAFS_ERR, "path not abs.");
    path_len = strlen(path);
    LOG_THEN_RETURN_VAL_IF_TRUE(buf_len < path_len + 1, CAFS_ERR, "buf_len is small.");
    memcpy(new_path, path, path_len);
    if (path[path_len -1] != '/') {
        new_path[path_len] = '/';
        path_len++;
    }
    new_path[path_len] = '\0';
    return 0;
}

int get_file_name(const char *path, char *file_name, uint32_t buf_len)
{
    uint32_t path_len = 0;
    uint32_t i;

    LOG_THEN_RETURN_VAL_IF_TRUE(!path, CAFS_ERR, "path null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(!file_name, CAFS_ERR, "file_name null.");
    LOG_THEN_RETURN_VAL_IF_TRUE(path[0] != '/', CAFS_ERR, "path not abs.");

    path_len = strlen(path);
    if (path[path_len - 1] == '/') {
        file_name[0] = '\0';
        return 0;
    }
    for(i = 0; i < path_len; i++){
        if (path[path_len - i - 1] == '/') {
            break;
        }
    }
    LOG_THEN_RETURN_VAL_IF_TRUE(buf_len < i, CAFS_ERR, "buf_len[%u] is small, but expect [%u].", buf_len, i);
    memcpy(file_name, &path[path_len - i], i);
    file_name[i] = '\0';
    return 0;
}