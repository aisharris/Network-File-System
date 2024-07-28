#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>

#include "ccp.h"

int main(int argc, char** argv)
{
    in_port_t serv_port;
    scanf("%hd", &serv_port);
    sockinfo clientsock = port_connect("127.0.0.1", serv_port);
    uint64_t retval = send_messages(clientsock, "hi this is a test bruv hi tagagjad a:DDDDDDDDDDDDDDDDDDDDD\n", 60, 0);
    if (retval == -1)
    {
        printf("send_messages failed\n");
        exit(EXIT_FAILURE);
    }
    printf("%lu messages sent\n", retval);
}