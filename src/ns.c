#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>

#include "lru.h"
#include "rbtree.h"
#include "ccp.h"
#include "ss_api.h"
// #include "heap.h"

int ss_compare(const void* a, const void* b)
{
    return ((ss_info)a)->ss_uid - ((ss_info)b)->ss_uid;
}

int global_delete_compar_strlen;

int delete_compar(const void* a, const void* b)
{
    return strncmp(a, b, global_delete_compar_strlen);
}

void ss_destroy(void* a)
{
    free(a);
}

int path_info_compare(const void* a, const void* b)
{
    return strcmp(((path_info)a)->path, ((path_info)b)->path);
}

void path_info_destroy(void* a)
{
    pthread_rwlock_unlock(&((path_info)a)->lock);
    free(((path_info)a)->path);
    free(((path_info)a));
}

uint64_t next_ss_uid = 1;
sem_t next_ss_uid_lock;

rbtree* ss_rbtree;
pthread_rwlock_t ss_rbtree_lock;

rbtree* paths_rbtree;
pthread_rwlock_t paths_rbtree_lock;

ss_info GLOBAL_SS1_INFO;
ss_info GLOBAL_SS2_INFO;

pthread_rwlock_t cache_lock;

// Returns number of deletions, -1 on error
int64_t delete_path(char* path, int pathlen)
{
    path_info temppathinfo = malloc(sizeof(st_path_info));
    if (temppathinfo == NULL)
    {
        perror("malloc");
        return -1;
    }
    
    temppathinfo->path = path;

    int64_t num_deletes = 0;
    pthread_rwlock_wrlock(&paths_rbtree_lock);
    global_delete_compar_strlen = pathlen;
    paths_rbtree->compare = delete_compar;
    pthread_rwlock_wrlock(&cache_lock);
    do
    {
        // Check if its in the rbtree, if so, delete it
        rbnode* node = rb_find(paths_rbtree, temppathinfo);

        if (node != NULL)
        {
            // Check if its in the cache, if so, delete it
            remove_from_cache(path);

            pthread_rwlock_wrlock(&((path_info)node->data)->lock);
            rb_delete(paths_rbtree, node, 0);

            num_deletes++;
            continue;
        }
        break;
    } while (path[pathlen - 1] == '/');
    pthread_rwlock_unlock(&cache_lock);
    paths_rbtree->compare = path_info_compare;
    pthread_rwlock_unlock(&paths_rbtree_lock);

    free(temppathinfo);
    return num_deletes;
}

response search_path(char* path)
{
    response r = malloc(sizeof(st_response));

    // First search cache
    pthread_rwlock_rdlock(&cache_lock);
    path_info info;
    if ((info = find_in_cache(path)) != NULL)
    {
        pthread_rwlock_unlock(&cache_lock);
        r->code = 0;
        r->data = info;
        return r;
    }
    pthread_rwlock_unlock(&cache_lock);
    // Cache miss
    // Check if path exists
    path_info temppathinfo = malloc(sizeof(st_path_info));
    temppathinfo->path = path;
    rbnode* node;
    if ((r->code = pthread_rwlock_rdlock(&paths_rbtree_lock)) == 0)
    {
        node = rb_find(paths_rbtree, temppathinfo);
        pthread_rwlock_unlock(&paths_rbtree_lock);
    }
    else
    {
        perror("pthread_rwlock_rdlock");
        free(temppathinfo);
        free(r);
        return NULL;
    }

    free(temppathinfo);

    r->code = 0;
    r->data = NULL;
    // If path exists, add to cache
    if (node != NULL)
    {
        pthread_rwlock_wrlock(&cache_lock);
        add_to_cache(((path_info)node->data)->path, (path_info)node->data);
        pthread_rwlock_unlock(&cache_lock);
        r->data = (path_info)node->data;
    }

    return r;
}

void copy_paths(rbnode* node1, rbnode* node2, ss_info ss2_info, uint64_t ss1_uid)
{   
    // Start an inorder from node1. Every time we come across a path with same prefix
    // as node1, we send a create/copy request to node2.
    if (((path_info)node1->data)->path[((path_info)node1->data)->pathlen-1] != '/')
    {
        // grab basename
        char* pathcopy = strdup(((path_info)node1->data)->path);
        char* base = basename(pathcopy);
        char* newpath = malloc(strlen(((path_info)node2->data)->path)+strlen(base)+1);
        memcpy(newpath, ((path_info)node2->data)->path, strlen(((path_info)node2->data)->path));
        memcpy(newpath+strlen(((path_info)node2->data)->path), base, strlen(base));
        newpath[strlen(((path_info)node2->data)->path)+strlen(base)] = 0;
        free(pathcopy);

        char* from;
        if (ss1_uid == 0)
        {
            from = ((path_info)node1->data)->path;
        }
        else
        {
            from = malloc(snprintf(0,0,"%lu/", ss1_uid) + strlen(((path_info)node1->data)->path) + 1);
            sprintf(from, "%lu/", ss1_uid);
            memcpy(from+snprintf(0,0,"%lu/", ss1_uid), ((path_info)node1->data)->path, strlen(((path_info)node1->data)->path));
            from[snprintf(0,0,"%lu/", ss1_uid) + strlen(((path_info)node1->data)->path)] = 0;
        }

        // Now send the request
        sockinfo ss2sock = port_connect(ss2_info->ip, ss2_info->ns_port);
        int64_t retval = ss_command(ss2sock, from, strlen(from), 2, newpath, strlen(newpath), ((path_info)node1->data)->info);
        if (retval == -1)
        {
            printf("ss_command failed\n");
            exit(EXIT_FAILURE);
        }
        path_info newpathinfo = malloc(sizeof(st_path_info));
        newpathinfo->info = ss2_info;
        newpathinfo->path = newpath;
        newpathinfo->pathlen = strlen(newpath);
        pthread_rwlock_init(&newpathinfo->lock, NULL);
        pthread_rwlock_wrlock(&paths_rbtree_lock);
        rb_insert(paths_rbtree, newpathinfo);
        pthread_rwlock_unlock(&paths_rbtree_lock);
        close(ss2sock->fd);
        free(ss2sock);
        if (ss1_uid != 0)
            free(from);
        return;
    }

    int prev_slash_loc = 0;
    
    ((path_info)node1->data)->path[((path_info)node1->data)->pathlen-1] = 0;
    char* prev_slash = strrchr(((path_info)node1->data)->path, '/');
    if (prev_slash != NULL)
        prev_slash_loc = prev_slash-((path_info)node1->data)->path+1;
    ((path_info)node1->data)->path[((path_info)node1->data)->pathlen-1] = '/';

    rbnode* curr;
    for ( curr = node1; curr != NULL; curr = rb_successor(paths_rbtree, curr))
    {
        // printf("%s %s %d\n", ((path_info)node1->data)->path, ((path_info)curr->data)->path, ((path_info)node1->data)->pathlen);
        if (strncmp(((path_info)node1->data)->path, ((path_info)curr->data)->path, ((path_info)node1->data)->pathlen) != 0)
        {
            continue;
        }
        sockinfo ss2sock = port_connect(ss2_info->ip, ss2_info->ns_port);
        // Valid path.
        if (((path_info)curr->data)->path[((path_info)curr->data)->pathlen - 1] == '/')
        {
            // If it is a directory, send create request.
            // First create path
            char* new_path = malloc(((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc + 1);
            memcpy(new_path, ((path_info)node2->data)->path, ((path_info)node2->data)->pathlen);
            memcpy(new_path+((path_info)node2->data)->pathlen, ((path_info)curr->data)->path+prev_slash_loc, ((path_info)curr->data)->pathlen - prev_slash_loc);
            new_path[((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc] = 0;
            int64_t retval = ss_command(ss2sock, new_path, ((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc, 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }
            path_info newpathinfo = malloc(sizeof(st_path_info));
            newpathinfo->info = ss2_info;
            newpathinfo->path = new_path;
            newpathinfo->pathlen = strlen(new_path);
            pthread_rwlock_init(&newpathinfo->lock, NULL);
            pthread_rwlock_wrlock(&paths_rbtree_lock);
            rb_insert(paths_rbtree, newpathinfo);
            pthread_rwlock_unlock(&paths_rbtree_lock);
            close(ss2sock->fd);
            free(ss2sock);
            // free(new_path);
            continue;
        }
        // Else we issue a copy request, dir already exists as it would have come earlier
        // in our inorder.
        char* from;
        if (ss1_uid == 0)
        {
            from = ((path_info)curr->data)->path;
        }
        else
        {
            from = malloc(snprintf(0,0,"%lu/", ss1_uid) + strlen(((path_info)curr->data)->path) + 1);
            sprintf(from, "%lu/", ss1_uid);
            memcpy(from+snprintf(0,0,"%lu/", ss1_uid), ((path_info)curr->data)->path, strlen(((path_info)curr->data)->path));
            from[snprintf(0,0,"%lu/", ss1_uid) + strlen(((path_info)curr->data)->path)] = 0;
        }
        // First create path
        char* new_path = malloc(((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc + 1);
        memcpy(new_path, ((path_info)node2->data)->path, ((path_info)node2->data)->pathlen);
        memcpy(new_path+((path_info)node2->data)->pathlen, ((path_info)curr->data)->path+prev_slash_loc, ((path_info)curr->data)->pathlen - prev_slash_loc);
        new_path[((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc] = 0;
        int64_t retval;
        if (((path_info)node2->data) == ((path_info)curr->data))
            retval = ss_command(ss2sock, from, strlen(from), 2, new_path, ((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc, NULL);
        else
            retval = ss_command(ss2sock, from, strlen(from), 2, new_path, ((path_info)node2->data)->pathlen + ((path_info)curr->data)->pathlen - prev_slash_loc, ((path_info)curr->data)->info);
        if (retval == -1)
        {
            printf("ss_command failed\n");
            exit(EXIT_FAILURE);
        }
        path_info newpathinfo = malloc(sizeof(st_path_info));
        newpathinfo->info = ss2_info;
        newpathinfo->path = new_path;
        newpathinfo->pathlen = strlen(new_path);
        pthread_rwlock_init(&newpathinfo->lock, NULL);
        pthread_rwlock_wrlock(&paths_rbtree_lock);
        rb_insert(paths_rbtree, newpathinfo);
        pthread_rwlock_unlock(&paths_rbtree_lock);
        if (ss1_uid != 0)
            free(from);
        close(ss2sock->fd);
        free(ss2sock);
        // free(new_path);
    }
}

void* ss_thread(void* arg)
{
    sockinfo ss_sock = arg;

    // Allocate a new ss_info struct
    ss_info info = malloc(sizeof(st_ss_info));
    
    // First get the header
    char buff[4097];
    int32_t retval = recv_message(ss_sock, buff);
    if (retval == -1)
    {
        printf("recv_message failed\n");
        return NULL;
    }
    if (retval != INET_ADDRSTRLEN + 2*sizeof(in_port_t) + sizeof(uint64_t))
    {
        printf("Malformed ss_connect header received!\n");
        return NULL;
    }
    
    memcpy(&info->ip, buff, INET_ADDRSTRLEN);
    memcpy(&info->client_port, buff+INET_ADDRSTRLEN, sizeof(in_port_t));
    info->client_port = ntohs(info->client_port);
    memcpy(&info->ns_port, buff+INET_ADDRSTRLEN+sizeof(in_port_t), sizeof(in_port_t));
    info->ns_port = ntohs(info->ns_port);

    uint64_t num_paths;
    memcpy(&num_paths, buff+INET_ADDRSTRLEN+2*sizeof(in_port_t), sizeof(uint64_t));
    num_paths = ntohll(num_paths);

    printf("Received connection from SS at %s:%hu\n", ss_sock->ip, ss_sock->port);
    printf("SS listening for NS messages at %s:%hu\n", info->ip, info->ns_port);
    printf("SS listening for client messages at %s:%hu\n", info->ip, info->client_port);
    printf("Number of paths received is %lu\n", num_paths);

    if (num_paths == -1)
    {
        uint64_t ss_uuid;
        retval = recv_message(ss_sock, (char*)&ss_uuid);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }

        printf("SS %lu reconnected\n", ss_uuid);
        info->ss_uid = ss_uuid;

        // update in sstree
        pthread_rwlock_wrlock(&ss_rbtree_lock);
        rbnode* node = rb_find(ss_rbtree, info);
        ((ss_info)node->data)->ns_port = info->ns_port;
        ((ss_info)node->data)->client_port = info->client_port;
        memcpy(((ss_info)node->data)->ip, info->ip, INET_ADDRSTRLEN);
        pthread_rwlock_unlock(&ss_rbtree_lock);

        retval = send_messages(ss_sock, &ss_uuid, sizeof(uint64_t), 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        
        free(info);
        return 0;
    }
    
    // Give it an uid
    sem_wait(&next_ss_uid_lock);
    info->ss_uid = next_ss_uid++;
    sem_post(&next_ss_uid_lock);

    path_info* paths = malloc(sizeof(path_info)*num_paths);

    // Now get the paths
    for (uint64_t i = 0; i < num_paths; i++)
    {
        retval = recv_message(ss_sock, buff);
        buff[retval] = 0;
        printf("Received path %s\n", buff);
        // Add path to our rbtree
        path_info p = malloc(sizeof(st_path_info));
        pthread_rwlock_init(&p->lock, NULL);
        p->info = info;
        p->pathlen = retval;
        p->path = strdup(buff);
        paths[i] = p;
    }

    // Now send the ss it's uid
    info->ss_uid = htonll(info->ss_uid);
    int64_t retval2 = send_messages(ss_sock, &info->ss_uid, sizeof(uint64_t), 1);
    if (retval2 == -1)
    {
        printf("send_messages failed\n");
        printf("Failed to send SS_%lu it's UID!\n", info->ss_uid);
    }
    info->ss_uid = ntohll(info->ss_uid);

    printf("Alloted SS the ss_uid %lu\n", info->ss_uid);

    // If more than 2 storage servers, copy to 1 and 2
    if (info->ss_uid > 2)
    {
        info->uid_redundant_ss1 = GLOBAL_SS1_INFO;
        info->uid_redundant_ss2 = GLOBAL_SS2_INFO;
        // First to 1
        // Check if we can connect
        response r = timed_port_connect(GLOBAL_SS1_INFO->ip, GLOBAL_SS1_INFO->ns_port);
        if (r->code == -1)
        {
            printf("timed_port_connect failed\n");
            exit(EXIT_FAILURE);
        }
        // Timed out
        if (r->code == 1)
        {
            free(r);
        }
        else
        {
            sockinfo ss1sock = r->data;
            // Now create the redundant folder
            char redundpath[snprintf(0, 0, "%lu/", info->ss_uid) + 1];
            sprintf(redundpath, "%lu/", info->ss_uid);
            retval = ss_command(ss1sock, redundpath, snprintf(0, 0, "%lu/", info->ss_uid), 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }
            close(ss1sock->fd);
            free(ss1sock);
            // Now copy everything
            for (int i = 0; i < num_paths; i++)
            {
                ss1sock = port_connect(GLOBAL_SS1_INFO->ip, GLOBAL_SS1_INFO->ns_port);
                // First create path
                char* new_path = malloc(snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen + 1);
                sprintf(new_path, "%lu/", info->ss_uid);
                memcpy(new_path+snprintf(0, 0, "%lu/", info->ss_uid), paths[i]->path, paths[i]->pathlen);
                new_path[snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen] = 0;
                if (paths[i]->path[paths[i]->pathlen - 1] == '/')
                {
                    // If it is a directory, send create request.
                    int64_t retval = ss_command(ss1sock, new_path, snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen, 0, NULL, 0, NULL);
                    if (retval == -1)
                    {
                        printf("ss_command failed\n");
                        exit(EXIT_FAILURE);
                    }
                    free(new_path);
                    close(ss1sock->fd);
                    free(ss1sock);
                    continue;
                }
                // Else we issue a copy request, dir already exists as it would have come earlier in our inorder.
                int64_t retval = ss_command(ss1sock, paths[i]->path, paths[i]->pathlen, 2, new_path, snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen, info);
                if (retval == -1)
                {
                    printf("ss_command failed\n");
                    exit(EXIT_FAILURE);
                }
                free(new_path);
                close(ss1sock->fd);
                free(ss1sock);
            }
        }
        free(r);
        r = timed_port_connect(GLOBAL_SS2_INFO->ip, GLOBAL_SS2_INFO->ns_port);
        if (r->code == -1)
        {
            printf("timed_port_connect failed\n");
            exit(EXIT_FAILURE);
        }
        // Timed out
        if (r->code == 1)
        {
            free(r);
        }
        else
        {
            sockinfo ss2sock = r->data;
            // Now create the redundant folder
            char redundpath[snprintf(0, 0, "%lu/", info->ss_uid) + 1];
            sprintf(redundpath, "%lu/", info->ss_uid);
            retval = ss_command(ss2sock, redundpath, snprintf(0, 0, "%lu/", info->ss_uid), 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }
            close(ss2sock->fd);
            free(ss2sock);
            // Now copy everything
            for (int i = 0; i < num_paths; i++)
            {
                ss2sock = port_connect(GLOBAL_SS2_INFO->ip, GLOBAL_SS2_INFO->ns_port);
                // First create path
                char* new_path = malloc(snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen + 1);
                sprintf(new_path, "%lu/", info->ss_uid);
                memcpy(new_path+snprintf(0, 0, "%lu/", info->ss_uid), paths[i]->path, paths[i]->pathlen);
                new_path[snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen] = 0;
                if (paths[i]->path[paths[i]->pathlen - 1] == '/')
                {
                    // If it is a directory, send create request.
                    int64_t retval = ss_command(ss2sock, new_path, snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen, 0, NULL, 0, NULL);
                    if (retval == -1)
                    {
                        printf("ss_command failed\n");
                        exit(EXIT_FAILURE);
                    }
                    free(new_path);
                    close(ss2sock->fd);
                    free(ss2sock);
                    continue;
                }
                // Else we issue a copy request, dir already exists as it would have come earlier in our inorder.
                int64_t retval = ss_command(ss2sock, paths[i]->path, paths[i]->pathlen, 2, new_path, snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen, info);
                if (retval == -1)
                {
                    printf("ss_command failed\n");
                    exit(EXIT_FAILURE);
                }
                free(new_path);
                close(ss2sock->fd);
                free(ss2sock);
            }
        }
    }
    else if (info->ss_uid == 2)
    {
        GLOBAL_SS1_INFO->uid_redundant_ss1 = info;
        info->uid_redundant_ss1 = GLOBAL_SS1_INFO;
        GLOBAL_SS2_INFO = info;
        // Send to 1
        // Check if we can connect
        response r = timed_port_connect(GLOBAL_SS1_INFO->ip, GLOBAL_SS1_INFO->ns_port);
        if (r->code == -1)
        {
            printf("timed_port_connect failed\n");
            exit(EXIT_FAILURE);
        }
        // Timed out
        if (r->code == 1)
        {
            free(r);
        }
        else
        {
            sockinfo ss1sock = r->data;
            // Now create the redundant folder
            char redundpath[snprintf(0, 0, "%lu/", info->ss_uid) + 1];
            sprintf(redundpath, "%lu/", info->ss_uid);
            retval = ss_command(ss1sock, redundpath, snprintf(0, 0, "%lu/", info->ss_uid), 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }
            close(ss1sock->fd);
            free(ss1sock);
            // Now copy everything
            for (int i = 0; i < num_paths; i++)
            {
                ss1sock = port_connect(GLOBAL_SS1_INFO->ip, GLOBAL_SS1_INFO->ns_port);
                // First create path
                char* new_path = malloc(snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen + 1);
                sprintf(new_path, "%lu/", info->ss_uid);
                memcpy(new_path+snprintf(0, 0, "%lu/", info->ss_uid), paths[i]->path, paths[i]->pathlen);
                new_path[snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen] = 0;
                if (paths[i]->path[paths[i]->pathlen - 1] == '/')
                {
                    // If it is a directory, send create request.
                    int64_t retval = ss_command(ss1sock, new_path, snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen, 0, NULL, 0, NULL);
                    if (retval == -1)
                    {
                        printf("ss_command failed\n");
                        exit(EXIT_FAILURE);
                    }
                    free(new_path);
                    close(ss1sock->fd);
                    free(ss1sock);
                    continue;
                }
                // Else we issue a copy request, dir already exists as it would have come earlier in our inorder.
                int64_t retval = ss_command(ss1sock, paths[i]->path, paths[i]->pathlen, 2, new_path, snprintf(0, 0, "%lu/", info->ss_uid) + paths[i]->pathlen, info);
                if (retval == -1)
                {
                    printf("ss_command failed\n");
                    exit(EXIT_FAILURE);
                }
                free(new_path);
                close(ss1sock->fd);
                free(ss1sock);
            }
        }
        free(r);
    }

    close(ss_sock->fd);
    free(ss_sock);

    // Add the paths to the tree
    for (uint64_t i = 0; i < num_paths; i++)
    {
        pthread_rwlock_wrlock(&paths_rbtree_lock);
        if (NULL == rb_insert(paths_rbtree, paths[i]))
        {
            printf("rb_insert failed\n");
            exit(EXIT_FAILURE);
        }
        pthread_rwlock_unlock(&paths_rbtree_lock);
    }

    // Now add this ss to the ss_rbtree
    pthread_rwlock_wrlock(&ss_rbtree_lock);
    rb_insert(ss_rbtree, info);
    pthread_rwlock_unlock(&ss_rbtree_lock);

    if (info->ss_uid == 2 || info->ss_uid == 3)
    {
        // Copy over ss1's shit to 2/3
        response r = timed_port_connect(info->ip, info->ns_port);
        if (r->code == -1)
        {
            printf("timed_port_connect failed\n");
            exit(EXIT_FAILURE);
        }
        // Timed out
        if (r->code == 1)
        {
            free(r);
        }
        else
        {
            sockinfo sssssock = r->data;
            // Now create the redundant folder
            char redundpath[snprintf(0, 0, "1/") + 1];
            sprintf(redundpath, "1/");
            retval = ss_command(sssssock, redundpath, snprintf(0, 0, "1/"), 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }
            close(sssssock->fd);
            free(sssssock);
            // Now copy everything
            pthread_rwlock_rdlock(&paths_rbtree_lock);
            for (rbnode* curr = RB_MINIMAL(paths_rbtree); curr!=NULL ; curr=rb_successor(paths_rbtree, curr))
            {
                if (((path_info)curr->data)->info->ss_uid != 1)
                    continue;
                path_info p = ((path_info)curr->data);
                
                sssssock = port_connect(info->ip, info->ns_port);
                // First create path
                char* new_path = malloc(snprintf(0, 0, "1/") + p->pathlen + 1);
                sprintf(new_path, "1/");
                memcpy(new_path+snprintf(0, 0, "1/"), p->path, p->pathlen);
                new_path[snprintf(0, 0, "1/") + p->pathlen] = 0;
                if (p->path[p->pathlen - 1] == '/')
                {
                    // If it is a directory, send create request.
                    int64_t retval = ss_command(sssssock, new_path, snprintf(0, 0, "1/") + p->pathlen, 0, NULL, 0, NULL);
                    if (retval == -1)
                    {
                        printf("ss_command failed\n");
                        exit(EXIT_FAILURE);
                    }
                    free(new_path);
                    close(sssssock->fd);
                    free(sssssock);
                    continue;
                }
                // Else we issue a copy request, dir already exists as it would have come earlier in our inorder.
                int64_t retval = ss_command(sssssock, p->path, p->pathlen, 2, new_path, snprintf(0, 0, "1/") + p->pathlen, GLOBAL_SS1_INFO);
                if (retval == -1)
                {
                    printf("ss_command failed\n");
                    exit(EXIT_FAILURE);
                }
                free(new_path);
                close(sssssock->fd);
                free(sssssock);
            }
            pthread_rwlock_unlock(&paths_rbtree_lock);
        }
        free(r);
    }
    if (info->ss_uid == 3)
    {
        info->uid_redundant_ss1 = GLOBAL_SS1_INFO;
        info->uid_redundant_ss2 = GLOBAL_SS2_INFO;
        GLOBAL_SS2_INFO->uid_redundant_ss2 = info;
        GLOBAL_SS1_INFO->uid_redundant_ss2 = info;
        // Copy 2's shit to 3
        response r = timed_port_connect(info->ip, info->ns_port);
        if (r->code == -1)
        {
            printf("timed_port_connect failed\n");
            exit(EXIT_FAILURE);
        }
        // Timed out
        if (r->code == 1)
        {
            free(r);
        }
        else
        {
            sockinfo sssssock = r->data;
            // Now create the redundant folder
            char redundpath[snprintf(0, 0, "2/") + 1];
            sprintf(redundpath, "2/");
            retval = ss_command(sssssock, redundpath, snprintf(0, 0, "2/"), 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }
            close(sssssock->fd);
            free(sssssock);
            // Now copy everything
            pthread_rwlock_rdlock(&paths_rbtree_lock);
            for (rbnode* curr = RB_MINIMAL(paths_rbtree); curr!=NULL ; curr=rb_successor(paths_rbtree, curr))
            {
                if (((path_info)curr->data)->info->ss_uid != 2)
                    continue;
                path_info p = ((path_info)curr->data);
                sssssock = port_connect(info->ip, info->ns_port);
                // First create path
                char* new_path = malloc(snprintf(0, 0, "2/") + p->pathlen + 1);
                sprintf(new_path, "2/");
                memcpy(new_path+snprintf(0, 0, "2/"), p->path, p->pathlen);
                new_path[snprintf(0, 0, "2/") + p->pathlen] = 0;
                if (p->path[p->pathlen - 1] == '/')
                {
                    // If it is a directory, send create request.
                    int64_t retval = ss_command(sssssock, new_path, snprintf(0, 0, "2/") + p->pathlen, 0, NULL, 0, NULL);
                    if (retval == -1)
                    {
                        printf("ss_command failed\n");
                        exit(EXIT_FAILURE);
                    }
                    free(new_path);
                    close(sssssock->fd);
                    free(sssssock);
                    continue;
                }
                // Else we issue a copy request, dir already exists as it would have come earlier in our inorder.
                int64_t retval = ss_command(sssssock, p->path, p->pathlen, 2, new_path, snprintf(0, 0, "2/") + p->pathlen, GLOBAL_SS2_INFO);
                if (retval == -1)
                {
                    printf("ss_command failed\n");
                    exit(EXIT_FAILURE);
                }
                free(new_path);
                close(sssssock->fd);
                free(sssssock);
            }
            pthread_rwlock_unlock(&paths_rbtree_lock);
        }
        free(r);
    }

    if (info->ss_uid == 1)
        GLOBAL_SS1_INFO = info;
    else if (info->ss_uid == 2)
        GLOBAL_SS2_INFO = info;
    else
        free(paths);
    
    return EXIT_SUCCESS;
}

void handle_ss_request(sockinfo ss_sock)
{
    sockinfo client_sock = port_accept(ss_sock);
    if (client_sock == NULL)
    {
        printf("port_accept failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Accepted server\n");

    pthread_t t;
    int retval = pthread_create(&t, NULL, ss_thread, client_sock);
    if (retval == -1)
    {
        printf("pthread_create failed\n");
        exit(EXIT_FAILURE);
    }
    retval = pthread_detach(t);
    if (retval == -1)
    {
        printf("pthread_detach failed\n");
        exit(EXIT_FAILURE);
    }
}

void* client_thread(void* arg)
{
    sockinfo client = arg;

    // Continuously wait for commands until client disconnects
    char* buf = malloc(sizeof(char) * 4097);
    while (1)
    {
        // First get command
        int64_t retval = recv_message(client, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        if (retval == 0)
        {
            printf("client disconnected\n");
            break;
        }
        if (retval != 1)
        {
            printf("Received malformed header!\n");
            break;
        }

        uint8_t command = buf[0];

        printf("Client %s:%hu requested command %d\n", client->ip, client->port, command);

        // If command is create/copy/delete, complete the operation and then send ack to client.
        // Create
        if (command == 0)
        {
            // Get path
            retval = recv_message(client, buf);
            if (retval == 1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            buf[retval] = 0;

            // Search for parent dir, if not tell client
            char* temp_path = strdup(buf);
            char* parent_dir = dirname(temp_path);
            printf("Searching for %s (create)\n", parent_dir);
            // Invalid path
            if (strcmp(".", parent_dir) == 0)
            {
                char msg = 1;
                retval = send_messages(client, &msg, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                continue;
            }
            // Get position of end of parent_dir
            int parent_dir_strlen = strlen(parent_dir)+1;
            free(temp_path);
            char temp_replace = buf[parent_dir_strlen];
            buf[parent_dir_strlen] = 0;

            response r = search_path(buf);
            if (r == NULL)
            {
                printf("search_path failed\n");
                exit(EXIT_FAILURE);
            }
            else if (r->data == NULL)
            {
                // Path not found, tell client
                char msg = 1;
                retval = send_messages(client, &msg, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r);
                continue;
            }

            // Parent dir was found, so send request to ss
            // Check if ss is accessible
            response r1 = timed_port_connect(((path_info)r->data)->info->ip, ((path_info)r->data)->info->ns_port);
            if (r1->code == -1)
            {
                printf("timed_port_connect failed\n");
                exit(EXIT_FAILURE);
            }
            // ss not accessible client can fuck off
            if (r1->code == 1)
            {
                buf[0] = 2;
                retval = send_messages(client, buf, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r1);
                free(r);
                continue;
            }
            sockinfo sssock = r1->data;

            buf[parent_dir_strlen] = temp_replace;

            retval = ss_command(sssock, buf, strlen(buf), 0, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }

            // Now add path to tree
            path_info new_path = malloc(sizeof(st_path_info));
            new_path->info = ((path_info)r->data)->info;
            new_path->path = strdup(buf);
            new_path->pathlen = strlen(buf);
            pthread_rwlock_init(&new_path->lock, NULL);

            pthread_rwlock_wrlock(&paths_rbtree_lock);
            rb_insert(paths_rbtree, new_path);
            pthread_rwlock_unlock(&paths_rbtree_lock);

            // Send ack to client
            char msg = 0;
            retval = send_messages(client, &msg, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }

            close(sssock->fd);
            free(sssock);
            
            // // Replicate in redundants
            // response r2 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss1->ip, ((path_info)r->data)->info->uid_redundant_ss1->ns_port);
            // if (r2->code == -1)
            // {
            //     printf("timed_port_connect failed\n");
            //     exit(EXIT_FAILURE);
            // }
            // // timed out, skip
            // if (r2->code == 1)
            // {
            //     free(r2);
            // }
            // else
            // {
            //     sockinfo r1sock = r2->data;
            //     char buf2[4096];
            //     sprintf(buf2, "%lu/%s", ((path_info)r->data)->info->uid_redundant_ss1->ss_uid, buf);
            //     retval = ss_command(r1sock, buf2, strlen(buf2), 0, NULL, 0, NULL);
            //     if (retval == -1)
            //     {
            //         printf("ss_command failed\n");
            //         exit(EXIT_FAILURE);
            //     }
            //     close(r1sock->fd);
            //     free(r1);
            //     free(r2);
            // }
            // r2 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss2->ip, ((path_info)r->data)->info->uid_redundant_ss2->ns_port);
            // if (r2->code == -1)
            // {
            //     printf("timed_port_connect failed\n");
            //     exit(EXIT_FAILURE);
            // }
            // // timed out, skip
            // if (r2->code == 1)
            // {
            //     free(r2);
            // }
            // else
            // {
            //     sockinfo r2sock = r2->data;
            //     char buf2[4096];
            //     sprintf(buf2, "%lu/%s", ((path_info)r->data)->info->uid_redundant_ss2->ss_uid, buf);
            //     retval = ss_command(r2sock, buf2, strlen(buf2), 0, NULL, 0, NULL);
            //     if (retval == -1)
            //     {
            //         printf("ss_command failed\n");
            //         exit(EXIT_FAILURE);
            //     }
            //     close(r2sock->fd);
            //     free(r1);
            //     free(r2);
            // }

            free(r);
            continue;
        }
        // Delete
        if (command == 1)
        {
            // Get path
            retval = recv_message(client, buf);
            if (retval == 1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            buf[retval] = 0;

            // Check if path exists
            response r = search_path(buf);
            if (r == NULL)
            {
                printf("search_path failed\n");
                exit(EXIT_FAILURE);
            }
            else if (r->data == NULL)
            {
                // Path not found, tell client
                char msg = 1;
                retval = send_messages(client, &msg, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r);
                continue;
            }

            // Check if ss is accessible
            response r1 = timed_port_connect(((path_info)r->data)->info->ip, ((path_info)r->data)->info->ns_port);
            if (r1->code == -1)
            {
                printf("timed_port_connect failed\n");
                exit(EXIT_FAILURE);
            }
            // ss not accessible client can fuck off
            if (r1->code == 1)
            {
                buf[0] = 2;
                retval = send_messages(client, buf, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r1);
                free(r);
                continue;
            }
            sockinfo sssock = r1->data;

            // Delete from tree and cache
            retval = delete_path(buf, retval);
            if (retval == -1)
            {
                printf("delete_path failed\n");
                exit(EXIT_FAILURE);
            }

            // Ask ss to delete
            retval = ss_command(sssock, buf, strlen(buf), 1, NULL, 0, NULL);
            if (retval == -1)
            {
                printf("ss_command failed\n");
                exit(EXIT_FAILURE);
            }

            // Send ack to client
            char msg = 0;
            retval = send_messages(client, &msg, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }

            close(sssock->fd);
            free(sssock);

            // // Replicate in redundants
            // response r2 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss1->ip, ((path_info)r->data)->info->uid_redundant_ss1->ns_port);
            // if (r2->code == -1)
            // {
            //     printf("timed_port_connect failed\n");
            //     exit(EXIT_FAILURE);
            // }
            // // timed out, skip
            // if (r2->code == 1)
            // {
            //     free(r2);
            // }
            // else
            // {
            //     sockinfo r1sock = r2->data;
            //     char buf2[4096];
            //     sprintf(buf2, "%lu/%s", ((path_info)r->data)->info->uid_redundant_ss1->ss_uid, buf);
            //     retval = ss_command(r1sock, buf2, strlen(buf2), 1, NULL, 0, NULL);
            //     if (retval == -1)
            //     {
            //         printf("ss_command failed\n");
            //         exit(EXIT_FAILURE);
            //     }
            //     close(r1sock->fd);
            //     free(r1);
            //     free(r2);
            // }
            // r2 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss2->ip, ((path_info)r->data)->info->uid_redundant_ss2->ns_port);
            // if (r2->code == -1)
            // {
            //     printf("timed_port_connect failed\n");
            //     exit(EXIT_FAILURE);
            // }
            // // timed out, skip
            // if (r2->code == 1)
            // {
            //     free(r2);
            // }
            // else
            // {
            //     sockinfo r2sock = r2->data;
            //     char buf2[4096];
            //     sprintf(buf2, "%lu/%s", ((path_info)r->data)->info->uid_redundant_ss2->ss_uid, buf);
            //     retval = ss_command(r2sock, buf2, strlen(buf2), 1, NULL, 0, NULL);
            //     if (retval == -1)
            //     {
            //         printf("ss_command failed\n");
            //         exit(EXIT_FAILURE);
            //     }
            //     close(r2sock->fd);
            //     free(r1);
            //     free(r2);
            // }

            free(r);
            continue;
        }
        // Copy
        if (command == 2)
        {
            // Receive both paths first
            char* buf2 = malloc(sizeof(char) * (2*MAX_MSG_LEN + 2));
            retval = recv_messages(client, buf2);
            if (retval == -1)
            {
                printf("recv_messages failed\n");
                free(buf2);
                break;
            }
            buf2[retval] = 0;
            
            // Now search both
            printf("[%s]\n", buf2);
            response r1 = search_path(buf2);
            if (r1 == NULL)
            {
                printf("search_path failed\n");
                free(buf2);
                break;
            }
            // Invalid path, tell client
            if (r1->data == NULL)
            {
                char msg = 1;
                retval = send_messages(client, &msg, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r1);
                free(buf2);
                continue;
            }
            printf("[%s]\n", buf2+strlen(buf2)+1);
            response r2 = search_path(buf2 + strlen(buf2) + 1);
            if (r2 == NULL)
            {
                printf("search_path failed\n");
                free(buf2);
                break;
            }
            // Invalid path, tell client
            if (r2->data == NULL)
            {
                char msg = 1;
                retval = send_messages(client, &msg, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r2);
                free(buf2);
                continue;
            }

            uint64_t ss1_uid = 0;
            // Check if ss1 is accessible
            response conn_r = timed_port_connect(((path_info)r1->data)->info->ip, ((path_info)r1->data)->info->ns_port);
            if (conn_r->code == -1)
            {
                printf("timed_port_connect failed\n");
                exit(EXIT_FAILURE);
            }
            // ss not accessible go for a redundant
            if (conn_r->code == 1)
            {
                ss1_uid = ((path_info)r1->data)->info->uid_redundant_ss1->ss_uid;
                free(conn_r);
                conn_r = timed_port_connect(((path_info)r1->data)->info->uid_redundant_ss1->ip, ((path_info)r1->data)->info->uid_redundant_ss1->ns_port);
                if (conn_r->code == -1)
                {
                    printf("timed_port_connect failed\n");
                    exit(EXIT_FAILURE);
                }
                // redundant not accessible go for 2
                if (conn_r->code == 1)
                {
                    ss1_uid = ((path_info)r1->data)->info->uid_redundant_ss2->ss_uid;
                    free(conn_r);
                    conn_r = timed_port_connect(((path_info)r1->data)->info->uid_redundant_ss2->ip, ((path_info)r1->data)->info->uid_redundant_ss2->ns_port);
                    if (conn_r->code == -1)
                    {
                        printf("timed_port_connect failed\n");
                        exit(EXIT_FAILURE);
                    }
                    // nothing available, client can fuck off
                    if (conn_r->code == 1)
                    {
                        char msg = 2;
                        memcpy(buf, &msg, 1);
                        retval = send_messages(client, buf, 1, 1);
                        if (retval == -1)
                        {
                            printf("send_messages failed\n");
                            exit(EXIT_FAILURE);
                        }
                        free(conn_r);
                        free(r1);
                        continue;
                    }
                }
            }
            sockinfo ss1sock = conn_r->data;
            free(conn_r);

            // Check if ss2 is accessible
            conn_r = timed_port_connect(((path_info)r2->data)->info->ip, ((path_info)r2->data)->info->ns_port);
            if (conn_r->code == -1)
            {
                printf("timed_port_connect failed\n");
                exit(EXIT_FAILURE);
            }
            // ss not accessible client can fuck off
            if (conn_r->code == 1)
            {
                buf[0] = 2;
                retval = send_messages(client, buf, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                // Tell ss1 this was just a ping.
                buf[0] = 40;
                retval = send_messages(ss1sock, buf, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                retval = recv_message(ss1sock, buf);
                if (retval == -1)
                {
                    printf("recv_message failed\n");
                    exit(EXIT_FAILURE);
                }
                if (retval != 1 || *buf != 1)
                {
                    printf("Malformed ack received!\n");
                    exit(EXIT_FAILURE);
                }
                close(ss1sock->fd);
                free(ss1sock);
                free(conn_r);
                free(r2);
                free(r1);
                continue;
            }
            sockinfo ss2sock = conn_r->data;
            free(conn_r);
            // Tell ss1 this was just a ping.
            buf[0] = 40;
            retval = send_messages(ss2sock, buf, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            retval = recv_message(ss2sock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || *buf != 1)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }
            close(ss2sock->fd);
            buf[0] = 40;
            retval = send_messages(ss1sock, buf, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            retval = recv_message(ss1sock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || *buf != 1)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }
            close(ss1sock->fd);
            free(ss1sock);
            free(ss2sock);

            // Both paths are valid, start copying.
            pthread_rwlock_rdlock(&paths_rbtree_lock);
            rbnode* node1 = rb_find(paths_rbtree, r1->data);
            rbnode* node2 = rb_find(paths_rbtree, r2->data);
            pthread_rwlock_unlock(&paths_rbtree_lock);
            copy_paths(node1, node2, ((path_info)r2->data)->info, ss1_uid);

            // Send client ack
            char msg = 0;
            retval = send_messages(client, &msg, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }

            free(r1);
            free(r2);
        }
        // Read
        if (command == 3)
        {
            // Get file path
            retval = recv_message(client, buf);
            if (retval == 1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            buf[retval] = 0;

            // Search for file
            response r = search_path(buf);
            if (r == NULL)
            {
                printf("search_path failed\n");
                exit(EXIT_FAILURE);
            }
            // Path not found
            if (r->data == NULL)
            {
                uint64_t msg = -1;
                memcpy(buf, &msg, sizeof(uint64_t));
                retval = send_messages(client, buf, sizeof(uint64_t)+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r);
                continue;
            }

            uint64_t ss_uid = 0;
            in_port_t cliport = ((path_info)r->data)->info->client_port;
            // Check if ss is accessible
            response r1 = timed_port_connect(((path_info)r->data)->info->ip, ((path_info)r->data)->info->ns_port);
            if (r1->code == -1)
            {
                printf("timed_port_connect failed\n");
                exit(EXIT_FAILURE);
            }
            // ss not accessible go for a redundant
            if (r1->code == 1)
            {
                ss_uid = ((path_info)r->data)->info->ss_uid;
                cliport = ((path_info)r->data)->info->uid_redundant_ss1->client_port;
                free(r1);
                r1 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss1->ip, ((path_info)r->data)->info->uid_redundant_ss1->ns_port);
                if (r1->code == -1)
                {
                    printf("timed_port_connect failed\n");
                    exit(EXIT_FAILURE);
                }
                // redundant not accessible go for 2
                if (r1->code == 1)
                {
                    cliport = ((path_info)r->data)->info->uid_redundant_ss2->client_port;
                    free(r1);
                    r1 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss2->ip, ((path_info)r->data)->info->uid_redundant_ss2->ns_port);
                    if (r1->code == -1)
                    {
                        printf("timed_port_connect failed\n");
                        exit(EXIT_FAILURE);
                    }
                    // nothing available, client can fuck off
                    if (r1->code == 1)
                    {
                        uint64_t msg = -1;
                        memcpy(buf, &msg, sizeof(uint64_t));
                        retval = send_messages(client, buf, sizeof(uint64_t)+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
                        if (retval == -1)
                        {
                            printf("send_messages failed\n");
                            exit(EXIT_FAILURE);
                        }
                        free(r1);
                        free(r);
                        continue;
                    }
                }
            }
            sockinfo sssock = r1->data;
            free(r1);
            buf[0] = 40;
            retval = send_messages(sssock, buf, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            retval = recv_message(sssock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || *buf != 1)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }
            pthread_rwlock_rdlock(&((path_info)r->data)->lock);
            ss_uid = htonll(ss_uid);
            memcpy(buf, &ss_uid, sizeof(uint64_t));
            memcpy(buf+sizeof(uint64_t), sssock->ip, INET_ADDRSTRLEN);
            cliport = htons(cliport);
            memcpy(buf+sizeof(uint64_t)+INET_ADDRSTRLEN, &cliport, sizeof(in_port_t));
            cliport = ntohs(cliport);
            retval = send_messages(client, buf, sizeof(uint64_t)+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }

            // Wait for client ack
            char msg;
            retval = recv_message(client, &msg);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || msg != 0)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }

            pthread_rwlock_unlock(&((path_info)r->data)->lock);
            free(r);
            close(sssock->fd);
            free(sssock);
            continue;
        }
        // Write
        if (command == 4)
        {
            retval = recv_message(client, buf);
            if (retval == 1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            buf[retval] = 0;

            // Check if path exists
            response r = search_path(buf);
            if (r == NULL)
            {
                printf("search_path failed\n");
                exit(EXIT_FAILURE);
            }
            else if (r->data == NULL)
            {
                // Path not found, tell client
                char msg = 1;
                retval = send_messages(client, &msg, 1, 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r);
                continue;
            }

            // Check if ss is accessible
            response r1 = timed_port_connect(((path_info)r->data)->info->ip, ((path_info)r->data)->info->ns_port);
            if (r1->code == -1)
            {
                printf("timed_port_connect failed\n");
                exit(EXIT_FAILURE);
            }
            // ss not accessible client can fuck off
            if (r1->code == 1)
            {
                buf[0] = -1;
                retval = send_messages(client, buf, 1+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r1);
                free(r);
                continue;
            }

            // Tell ss this was just a ping
            in_port_t cliport = ((path_info)r->data)->info->client_port;
            sockinfo sssock = r1->data;
            free(r1);
            buf[0] = 40;
            retval = send_messages(sssock, buf, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            retval = recv_message(sssock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || *buf != 1)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }
            close(sssock->fd);
            // Lock file
            pthread_rwlock_wrlock(&((path_info)r->data)->lock);

            buf[0] = 0;
            memcpy(buf+1, sssock->ip, INET_ADDRSTRLEN);
            cliport = htons(cliport);
            memcpy(buf+1+INET_ADDRSTRLEN, &cliport, sizeof(in_port_t));
            cliport = ntohs(cliport);
            retval = send_messages(client, buf, 1+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }

            // Wait for client ack
            char msg;
            retval = recv_message(client, &msg);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || msg != 0)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }

            pthread_rwlock_unlock(&((path_info)r->data)->lock);
            free(sssock);
            free(r);
            continue;
        }
        // Info
        if (command == 5)
        {
            // Get file path
            retval = recv_message(client, buf);
            if (retval == 1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            buf[retval] = 0;

            // Search for file
            response r = search_path(buf);
            if (r == NULL)
            {
                printf("search_path failed\n");
                exit(EXIT_FAILURE);
            }
            // Path not found
            if (r->data == NULL)
            {
                uint64_t msg = -1;
                memcpy(buf, &msg, sizeof(uint64_t));
                retval = send_messages(client, buf, sizeof(uint64_t)+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
                if (retval == -1)
                {
                    printf("send_messages failed\n");
                    exit(EXIT_FAILURE);
                }
                free(r);
                continue;
            }

            uint64_t ss_uid = 0;
            // Check if ss is accessible
            in_port_t cliport = ((path_info)r->data)->info->client_port;
            response r1 = timed_port_connect(((path_info)r->data)->info->ip, ((path_info)r->data)->info->ns_port);
            if (r1->code == -1)
            {
                printf("timed_port_connect failed %lu\n", ((path_info)r->data)->info->ss_uid);
                exit(EXIT_FAILURE);
            }
            // ss not accessible go for a redundant
            if (r1->code == 1)
            {
                ss_uid = ((path_info)r->data)->info->ss_uid;
                cliport = ((path_info)r->data)->info->uid_redundant_ss1->client_port;
                free(r1);
                r1 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss1->ip, ((path_info)r->data)->info->uid_redundant_ss1->ns_port);
                if (r1->code == -1)
                {
                    printf("timed_port_connect failed\n");
                    exit(EXIT_FAILURE);
                }
                // redundant not accessible go for 2
                if (r1->code == 1)
                {
                    cliport = ((path_info)r->data)->info->uid_redundant_ss2->client_port;
                    free(r1);
                    r1 = timed_port_connect(((path_info)r->data)->info->uid_redundant_ss2->ip, ((path_info)r->data)->info->uid_redundant_ss2->ns_port);
                    if (r1->code == -1)
                    {
                        printf("timed_port_connect failed\n");
                        exit(EXIT_FAILURE);
                    }
                    // nothing available, client can fuck off
                    if (r1->code == 1)
                    {
                        uint64_t msg = -1;
                        memcpy(buf, &msg, sizeof(uint64_t));
                        retval = send_messages(client, buf, sizeof(uint64_t)+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
                        if (retval == -1)
                        {
                            printf("send_messages failed\n");
                            exit(EXIT_FAILURE);
                        }
                        free(r1);
                        free(r);
                        continue;
                    }
                }
            }
            sockinfo sssock = r1->data;
            free(r1);
            buf[0] = 40;
            retval = send_messages(sssock, buf, 1, 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            retval = recv_message(sssock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || *buf != 1)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }
            pthread_rwlock_rdlock(&((path_info)r->data)->lock);

            ss_uid = htonll(ss_uid);
            memcpy(buf, &ss_uid, sizeof(uint64_t));
            memcpy(buf+sizeof(uint64_t), sssock->ip, INET_ADDRSTRLEN);
            cliport = htons(cliport);
            memcpy(buf+sizeof(uint64_t)+INET_ADDRSTRLEN, &cliport, sizeof(in_port_t));
            cliport = ntohs(cliport);
            retval = send_messages(client, buf, sizeof(uint64_t)+INET_ADDRSTRLEN+sizeof(in_port_t), 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }

            // Wait for client ack
            char msg;
            retval = recv_message(client, &msg);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || msg != 0)
            {
                printf("Malformed ack received!\n");
                exit(EXIT_FAILURE);
            }

            pthread_rwlock_unlock(&((path_info)r->data)->lock);
            close(sssock->fd);
            free(sssock);
            free(r);
            continue;
        }
    }
    free(buf);
    return 0;
}

void handle_client_request(sockinfo client_sock)
{
    sockinfo clt_sock = port_accept(client_sock);
    if (clt_sock == NULL)
    {
        printf("port_accept failed\n");
        exit(EXIT_FAILURE);
    }

    pthread_t t;
    int retval = pthread_create(&t, NULL, client_thread, clt_sock);
    if (retval == -1)
    {
        printf("pthread_create failed\n");
        exit(EXIT_FAILURE);
    }
    retval = pthread_detach(t);
    if (retval == -1)
    {
        printf("pthread_detach failed\n");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    sem_init(&next_ss_uid_lock, 0, 1);

    pthread_rwlock_init(&ss_rbtree_lock, NULL);
    pthread_rwlock_init(&paths_rbtree_lock, NULL);
    pthread_rwlock_init(&cache_lock, NULL);

    // Initialize our rbtree for ss'
    ss_rbtree = rb_create(ss_compare, ss_destroy);
    // Initialize our rbtree for paths
    paths_rbtree = rb_create(path_info_compare, path_info_destroy);

    // Create 2 sockets, one for clients and one for storage servers.
    sockinfo ss_sock = port_bind(0);
    if (ss_sock == NULL)
    {
        printf("port_bind failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Listening for storage servers at %s:%hu\n", ss_sock->ip, ss_sock->port);

    sockinfo client_sock = port_bind(0);
    if (client_sock == NULL)
    {
        printf("port_bind failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Listening for clients at %s:%hu\n", client_sock->ip, client_sock->port);

    int retval = listen(ss_sock->fd, 10);
    if (retval == -1)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    retval = listen(client_sock->fd, 10);
    if (retval == -1)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    struct pollfd pfds[2];

    pfds[0].fd = ss_sock->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = client_sock->fd;
    pfds[1].events = POLLIN;

    while (1)
    {
        poll(pfds, 2, -1);
        if (pfds[0].revents & POLLIN)
        {
            printf("test\n");
            handle_ss_request(ss_sock);
        }
        if (pfds[1].revents & POLLIN)
            handle_client_request(client_sock);
    }
}
