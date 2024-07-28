#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include "ccp.h"

// Binds to the provided local port. If port is 0 it randomly chooses a free one.
sockinfo port_bind(in_port_t port)
{
    int sock_fd, retval;
    struct sockaddr_in sock_addr = {0};
    socklen_t sock_addrlen = sizeof(sock_addr);

    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1)
    {
        perror("socket");
        return NULL;
    }

    int yes=1;
    if (setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
        perror("setsockopt");
        exit(1);
    }

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    sock_addr.sin_addr.s_addr = INADDR_ANY;

    retval = bind(sock_fd, (struct sockaddr*)&sock_addr, sock_addrlen);
    if (retval == -1)
    {
        perror("bind");
        return NULL;
    }

    memset(&sock_addr, 0, sock_addrlen);
    retval = getsockname(sock_fd, (struct sockaddr*)&sock_addr, &sock_addrlen);
    if (retval == -1)
    {
        perror("getsockname");
        return NULL;
    }

    sockinfo s = malloc(sizeof(st_sockinfo));
    s->fd = sock_fd;
    s->port = ((struct sockaddr_in*)&sock_addr)->sin_port;
    s->port = ntohs(s->port);
    const char* temp_ret = inet_ntop(AF_INET, &((struct sockaddr_in*)&sock_addr)->sin_addr, s->ip, INET6_ADDRSTRLEN);
    if (temp_ret == NULL)
    {
        perror("inet_ntop");
        return NULL;
    }

    return s;
}

// Credits to https://stackoverflow.com/a/61960339/9873902 for such a beautiful solution
int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned int timeout_ms)
{
    int rc = 0;
    // Set O_NONBLOCK
    int sockfd_flags_before;
    if((sockfd_flags_before=fcntl(sockfd,F_GETFL,0)<0)) return -1;
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before | O_NONBLOCK)<0) return -1;
    // Start connecting (asynchronously)
    do {
        if (connect(sockfd, addr, addrlen)<0) {
            // Did connect return an error? If so, we'll fail.
            if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
                rc = -1;
            }
            // Otherwise, we'll wait for it to complete.
            else {
                // Set a deadline timestamp 'timeout' ms from now (needed b/c poll can be interrupted)
                struct timespec now;
                if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                struct timespec deadline = { .tv_sec = now.tv_sec,
                                             .tv_nsec = now.tv_nsec + timeout_ms*1000000l};
                // Wait for the connection to complete.
                do {
                    // Calculate how long until the deadline
                    if(clock_gettime(CLOCK_MONOTONIC, &now)<0) { rc=-1; break; }
                    int ms_until_deadline = (int)(  (deadline.tv_sec  - now.tv_sec)*1000l
                                                  + (deadline.tv_nsec - now.tv_nsec)/1000000l);
                    if(ms_until_deadline<0) { rc=0; break; }
                    // Wait for connect to complete (or for the timeout deadline)
                    struct pollfd pfds[] = { { .fd = sockfd, .events = POLLOUT } };
                    rc = poll(pfds, 1, ms_until_deadline);
                    // If poll 'succeeded', make sure it *really* succeeded
                    if(rc>0) {
                        int error = 0; socklen_t len = sizeof(error);
                        int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                        if(retval==0) errno = error;
                        if(error!=0) rc=-1;
                    }
                }
                // If poll was interrupted, try again.
                while(rc==-1 && errno==EINTR);
                // Did poll timeout? If so, fail.
                if(rc==0) {
                    errno = ETIMEDOUT;
                    rc=-1;
                }
            }
        }
    } while(0);
    // Restore original O_NONBLOCK state
    if(fcntl(sockfd,F_SETFL,sockfd_flags_before)<0) return -1;
    // Success
    return rc;
}

// Binds to the provided port on the given IP address
sockinfo port_connect(char* hostip, in_port_t port)
{
    int sock_fd, retval;
    struct sockaddr_in sock_addr = {0};
    socklen_t sock_addrlen = sizeof(sock_addr);

    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1)
    {
        perror("socket");
        return NULL;
    }

    int yes=1;
    if (setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
        perror("setsockopt");
        exit(1);
    }

    sock_addr.sin_port = htons(port);
    sock_addr.sin_family = AF_INET;
    retval = inet_pton(AF_INET, hostip, &(sock_addr.sin_addr));
    if (retval == -1)
    {
        perror("inet_pton");
        return NULL;
    }
    
    retval = connect(sock_fd, (struct sockaddr*)&sock_addr, sock_addrlen);
    if (retval == -1)
    {
        perror("connect");
        return NULL;
    }

    sockinfo s = malloc(sizeof(st_sockinfo));
    s->fd = sock_fd;
    s->port = port;
    strcpy(s->ip, hostip);

    return s;
}

// If connect does not occur in 1 second, return prematurely
response timed_port_connect(char* hostip, in_port_t port)
{
    response r = malloc(sizeof(st_response));
    int sock_fd, retval;
    struct sockaddr_in sock_addr = {0};
    socklen_t sock_addrlen = sizeof(sock_addr);

    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1)
    {
        perror("socket");
        r->code = -1;
        return r;
    }

    int yes=1;
    if (setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
        perror("setsockopt");
        exit(1);
    }

    sock_addr.sin_port = htons(port);
    sock_addr.sin_family = AF_INET;
    retval = inet_pton(AF_INET, hostip, &(sock_addr.sin_addr));
    if (retval == -1)
    {
        perror("inet_pton");
        r->code = -1;
        return r;
    }
    
    retval = connect_with_timeout(sock_fd, (struct sockaddr*)&sock_addr, sock_addrlen, 1000);
    if (retval == -1 && errno != ETIMEDOUT && errno != ECONNREFUSED)
    {
        perror("connect_with_timeout");
        r->code = -1;
        return r;
    }
    else if (retval == -1 && (errno == ETIMEDOUT || errno == ECONNREFUSED))
    {
        r->code = 1;
        return r;
    }

    sockinfo s = malloc(sizeof(st_sockinfo));
    s->fd = sock_fd;
    s->port = port;
    strcpy(s->ip, hostip);

    r->code = 0;
    r->data = s;

    return r;
}

// Waits for connection on given socket. Returns sockinfo of connected client.
sockinfo port_accept(sockinfo sock)
{
    struct sockaddr clientaddr = {0};
    socklen_t clientaddrlen = sizeof(clientaddr);
    sockinfo clientsock = malloc(sizeof(st_sockinfo));
    
    clientsock->fd = accept(sock->fd, &clientaddr, &clientaddrlen);
    if (clientsock->fd == -1)
    {
        perror("accept");
        return NULL;
    }

    clientsock->port = ((struct sockaddr_in*)&clientaddr)->sin_port;
    clientsock->port = ntohs(clientsock->port);
    const char* temp_ret = inet_ntop(AF_INET, &((struct sockaddr_in*)&clientaddr)->sin_addr, clientsock->ip, INET6_ADDRSTRLEN);
    if (temp_ret == NULL)
    {
        perror("inet_ntop");
        return NULL;
    }

    return clientsock;
}

// Returns number of messages sent or -1 on failure. First message sent contains the number of messages.
int64_t send_messages(sockinfo sock, void* data, uint64_t len, int single_message)
{
    if (data == NULL)
        return -1;

    uint32_t num_sent = 0;
    uint32_t num_to_send = sizeof(uint64_t);
    // Send the number of messages as a message.
    uint64_t num_messages = (len < MAX_MSG_LEN) ? 1 : len/MAX_MSG_LEN;
    if (!single_message)
    {
        // First send message length
        num_to_send = htonl(num_to_send);
        while (num_sent != sizeof(uint32_t))
        {
            int retval = send(sock->fd, &((char*)&num_to_send)[num_sent], sizeof(uint32_t) - num_sent, 0);
            if (retval == -1)
                return -1;
            num_sent += retval;
        }
        num_to_send = ntohl(num_to_send);
        // Now send number of messages
        num_messages = htonll(num_messages);
        num_sent = 0;
        while (num_sent != sizeof(uint64_t))
        {
            int retval = send(sock->fd, &((char*)&num_messages)[num_sent], sizeof(uint64_t) - num_sent, 0);
            if (retval == -1)
                return -1;
            num_sent += retval;
        }
        num_messages = ntohll(num_messages);
    }

    uint64_t pos = 0;
    for (uint64_t i = 0; i < num_messages; i++)
    {
        num_sent = 0;
        num_to_send = MAX_MSG_LEN;
        
        // Check if last message
        if (i == num_messages-1)
            num_to_send = len - pos;
        
        // Send the message length first
        num_to_send = htonl(num_to_send);
        while (num_sent != sizeof(uint32_t))
        {
            int retval = send(sock->fd, &((char*)&num_to_send)[num_sent], sizeof(uint32_t) - num_sent, 0);
            if (retval == -1)
                return -1;
            num_sent += retval;
        }
        num_to_send = ntohl(num_to_send);

        // Now send message
        num_sent = 0;
        while (num_sent != num_to_send)
        {
            int retval = send(sock->fd, &((char*)data)[pos+num_sent], num_to_send-num_sent, 0);
            if (retval == -1)
                return -1;
            num_sent += retval;
        }
    }

    return num_messages + 1;
}

// Recieve a single message and put data in buf. Returns size of message.
int32_t recv_message(sockinfo sock, char* buf)
{
    uint32_t msglen;
    // Get message size
    int retval = recv(sock->fd, &msglen, sizeof(uint32_t), MSG_WAITALL);
    if (retval == -1)
    {
        perror("recv");
        return -1;
    }
    msglen = ntohl(msglen) & 0xFFFF;

    // Get message data
    retval = recv(sock->fd, buf, msglen, MSG_WAITALL);
    if (retval == -1)
    {
        perror("recv");
        return -1;
    }
    return msglen;
}

// Recieve more than one message. Returns -1 on failure
// ONLY USE THIS IF YOU ARE CERTAIN THAT BUF WILL HOLD THE ENTIRE MESSAGE
int64_t recv_messages(sockinfo sock, char* buf)
{
    uint32_t msglen;
    // Get message size
    int retval = recv(sock->fd, &msglen, sizeof(uint32_t), MSG_WAITALL);
    if (retval == -1)
    {
        perror("recv");
        return -1;
    }
    msglen = ntohl(msglen) & 0xFFFF;

    if (msglen != sizeof(uint64_t))
    {
        printf("Received malformed message header!\n");
        return -1;
    }

    // Get number of messages
    uint64_t num_messages;
    retval = recv(sock->fd, &num_messages, msglen, MSG_WAITALL);
    if (retval == -1)
    {
        perror("recv");
        return -1;
    }
    num_messages = ntohll(num_messages);

    printf("received number of msgs %lu\n", num_messages);

    int64_t msgsize = 0;
    // Now wait till all messages are received
    for (uint64_t i = 0; i < num_messages; i++)
    {
        int32_t retval2 = recv_message(sock, buf);
        if (retval2 == -1)
        {
            printf("recv_messages: recv_message failed\n");
            return -1;
        }
        printf("received %d\n", retval2);
        buf += retval2;
        msgsize += retval2;
    }

    return msgsize;
}