#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "heap.h"

void heap_up(heap h, int pos)
{
    for (int i = pos; i > 0; i = (i-1)/2)
    {
        if (h->compar_func(h->elems[i], h->elems[(i-1)/2]) >= 0)
            break;
        void* temp = h->elems[i];
        h->elems[i] = h->elems[(i-1)/2];
        h->elems[(i-1)/2] = temp;
    }
}

void heap_insert(heap h, void* b)
{
    if (h->curr == h->size)
    {
        printf("inserting into full heap...\n");
        exit(EXIT_FAILURE);
    }
    h->elems[h->curr++] = b;
    heap_up(h, h->curr-1);
}

void heap_down(heap h, int pos)
{
    for (int i = pos; i*2 + 1 < h->curr;)
    {
        int swap = i;
        if (h->compar_func(h->elems[2*i + 1], h->elems[i]) < 0)
            swap = 2*i + 1;
        if (h->compar_func(h->elems[2*i + 2], h->elems[swap]) < 0)
            swap = 2*i + 2;
        if (swap == i)
            break;
        void* temp = h->elems[i];
        h->elems[i] = h->elems[swap];
        h->elems[swap] = temp;
        i = swap;
    }
}

void* heap_pop(heap h)
{
    if (h->curr == 0)
    {
        printf("popping from empty heap...\n");
        exit(EXIT_FAILURE);
    }
    void* ret = h->elems[0];
    h->elems[0] = h->elems[--h->curr];
    heap_down(h, 0);
    return ret;
}

heap heap_init(int max_size, int (*compar_func)(void*, void*))
{
    heap h = malloc(sizeof(st_heap));
    h->curr = 0;
    h->elems = malloc(sizeof(void*)*max_size);
    h->size = max_size;
    h->compar_func = compar_func;
    pthread_mutex_init(&h->lock, NULL);
    pthread_cond_init(&h->signal, NULL);
    return h;
}