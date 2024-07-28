#include <string.h>
#include "uthash.h"
#include "ccp.h"

// this is an example of how to do a LRU cache in C using uthash
// http://uthash.sourceforge.net/
// by Jehiah Czebotar 2011 - jehiah@gmail.com
// this code is in the public domain http://unlicense.org/

#define MAX_CACHE_SIZE 10000

typedef struct path_info
{
    char* path;
    pthread_rwlock_t lock;
    uint16_t pathlen;
    ss_info info;
} st_path_info;

typedef st_path_info* path_info;

struct CacheEntry {
    char *key;
    path_info value;
    UT_hash_handle hh;
};
struct CacheEntry *cache = NULL;

path_info find_in_cache(char *key)
{
    struct CacheEntry *entry;
    HASH_FIND_STR(cache, key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, cache, entry);
        HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);
        return entry->value;
    }
    return NULL;
}

int remove_from_cache(char* key)
{
    struct CacheEntry *entry;
    HASH_FIND_STR(cache, key, entry);
    if (entry) {
        // remove it
        HASH_DELETE(hh, cache, entry);
        return 0;
    }
    return 1;
}

void add_to_cache(char *key, path_info value)
{
    struct CacheEntry *entry, *tmp_entry;
    entry = malloc(sizeof(struct CacheEntry));
    entry->key = strdup(key);
    entry->value = value;
    HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);
    
    // prune the cache to MAX_CACHE_SIZE
    if (HASH_COUNT(cache) >= MAX_CACHE_SIZE) {
        HASH_ITER(hh, cache, entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, cache, entry);
            free(entry->key);
            free(entry);
            break;
        }
    }    
}