#ifndef __CCP_H_
#define __CCP_H_

#include <stdint.h>
#include <arpa/inet.h>

#define MAX_MSG_LEN 4096ULL

typedef struct sockinfo
{
    int fd;
    char ip[INET_ADDRSTRLEN];
    in_port_t port;
} st_sockinfo;

typedef st_sockinfo* sockinfo;

typedef struct ss_socks
{
    uint64_t ss_uid;
    sockinfo ns_sock;
    sockinfo client_sock;
} st_ss_socks;

typedef st_ss_socks* ss_socks;

typedef struct ss_info
{
    uint64_t ss_uid;
    struct ss_info* uid_redundant_ss1;
    struct ss_info* uid_redundant_ss2;
    char ip[INET_ADDRSTRLEN];
    in_port_t client_port;
    in_port_t ns_port;
} st_ss_info;

typedef st_ss_info* ss_info;

typedef struct response
{
    int code;
    void* data;
} st_response;

typedef st_response* response;

// ntohl but for uint64_t
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
// htonl but for uint64_t
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

// Binds to the provided local port. If port is 0 it randomly chooses a free one
sockinfo port_bind(in_port_t port);
// Binds to the provided port on the given IP address.
sockinfo port_connect(char* hostip, in_port_t port);
// If connect does not occur in some time, return prematurely
response timed_port_connect(char* hostip, in_port_t port);
// Waits for connection on given socket. Returns sockinfo of connected client.
sockinfo port_accept(sockinfo sock);

// Send as many messages as required to transmit data. Returns number of messages sent or -1 on failure.
int64_t send_messages(sockinfo sock, void* data, uint64_t len, int single_message);
// Recieve a single message. Returns -1 on failure.
int32_t recv_message(sockinfo sock, char* buf);
// Recieve more than one message. Returns -1 on failure
// ONLY USE THIS IF YOU ARE CERTAIN THAT BUF WILL HOLD THE ENTIRE MESSAGE
int64_t recv_messages(sockinfo sock, char* buf);

#endif