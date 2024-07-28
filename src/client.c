#include <stdio.h>
#include <stdlib.h>

#include "ccp.h"
#include "ns_api.h"
#include "ss_api.h"

int path_valid(char* path)
{

}

int main()
{
    char ns_ip[INET_ADDRSTRLEN];
    in_port_t ns_port;
    printf("ns ip: ");
    scanf("%s", ns_ip);
    printf("ns port: ");
    scanf("%hu", &ns_port);

    response r = timed_port_connect(ns_ip, ns_port);
    if (r->code == -1)
    {
        printf("timed_port_connect failed\n");
        exit(EXIT_FAILURE);
    }
    else if (r->code == 1)
    {
        printf("Couldn't connect to NS: operation timed out\n");
        exit(EXIT_SUCCESS);
    }

    sockinfo ns_sock = r->data;
    free(r);

    while (1)
    {
        char cmd;
        printf("create(0)/delete(1)/copy(2)/read(3)/write(4)/info(5)/quit(6): ");
        scanf(" %c", &cmd);
        if (cmd == '2')
        {
            char path[4097];
            printf("Copy From: ");
            scanf("%s", path);
            char path1[4097];
            printf("Copy To: ");
            scanf("%s", path1);

            client_command(ns_sock, path, cmd-'0', path1);
        }
        else
        {
            char path[4097];
            printf("Path: ");
            scanf("%s", path);

            client_command(ns_sock, path, cmd-'0', NULL);
        }
    }
}