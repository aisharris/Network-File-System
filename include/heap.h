#ifndef __HEAP_H_
#define __HEAP_H_

typedef struct heap
{
    void** elems;
    int size;
    int curr;
    pthread_mutex_t lock;
    pthread_cond_t signal;
    int (*compar_func)(void*, void*);
} st_heap;

typedef st_heap* heap;

void heap_up(heap h, int pos);
void heap_insert(heap h, void* b);
void heap_down(heap h, int pos);
void* heap_pop(heap h);
heap heap_init(int max_size, int (*compar_func)(void*, void*));

#endif