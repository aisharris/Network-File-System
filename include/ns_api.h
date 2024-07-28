#ifndef __NS_H_
#define __NS_H_

#include "ccp.h"

ss_socks add_storage_server(char* ns_ip, in_port_t ns_ss_port, char** paths, uint64_t num_paths);
int client_command(sockinfo ns_sock, char* path, char cmd, char* copy_to);

#endif