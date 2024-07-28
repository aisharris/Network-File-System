#ifndef __SS_H_
#define __SS_H_

void* client_thread(void* arg);
void* ns_thread(void* arg);

int create_file(char* buf, int pathlen);
int delete_file(char* buf, int pathlen);
void copy_file(char * src_file, char* dest_dir, char* ip, in_port_t port);

void handle_ns_request(sockinfo ns_sock);
void handle_client_request(sockinfo client_sock);

int slashSort(const void* a, const void* b);

#endif