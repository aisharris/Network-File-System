#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "ccp.h"

int main()
{
    sockinfo servsock = port_bind(0);
    printf("server bound to port %hu(%s)\n", servsock->port, servsock->ip);

    int tmepmtpemtp = listen(servsock->fd, 10);
    if (tmepmtpemtp == -1)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    char buf[4096];
    while (1)
    {
        sockinfo clientsock = port_accept(servsock);

        // First get number of messages.
        int32_t retval = recv_message(clientsock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        if (retval != sizeof(uint64_t))
        {
            printf("received malformed header\n");
            continue;
        }
        uint64_t num_messages;
        memcpy(&num_messages, buf, sizeof(uint64_t));
        num_messages = ntohll(num_messages);
        printf("received number of messages - %ld\n", num_messages);

        // Now get each message.
        printf("Message Start\n");
        while (num_messages--)
        {
            retval = recv_message(clientsock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            printf("%d - %.*s", retval, retval, buf);
        }
        printf("Message End\n");
    }
}