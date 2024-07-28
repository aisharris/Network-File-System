#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ns_api.h"
#include "ss_api.h"

#define ERR_INV_PATH 1
#define ERR_READ_INV_PATH -1
#define ERR_WRITE_INV_PATH -2
#define ERR_SERV_DOWN -2
#define SERVER_UNAVAILABLE -1

ss_socks add_storage_server(char* ns_ip, in_port_t ns_ss_port, char** paths, uint64_t num_paths)
{
    // First create the dedicated ports for clients and name server
    ss_socks ssinfo = malloc(sizeof(st_ss_socks));
    ssinfo->ss_uid = 0;
    ssinfo->client_sock = port_bind(0);
    if (ssinfo->client_sock == NULL)
    {
        printf("port_bind failed");
        return NULL;
    }
    ssinfo->ns_sock = port_bind(0);
    if (ssinfo->ns_sock == NULL)
    {
        printf("port_bind failed");
        return NULL;
    }

    // Now send this data to the name server
    sockinfo ns_ss_sock = port_connect(ns_ip, ns_ss_port);
    if (ns_ss_sock == NULL)
    {
        printf("port_bind failed");
        return NULL;
    }

    // We need to first send ip address + ns and client port + number of paths
    char header[INET_ADDRSTRLEN + 2*sizeof(in_port_t) + sizeof(uint64_t)];
    // Now copy info into header
    char* header_pos = header;

    // Copy ip address
    memcpy(header_pos, ssinfo->client_sock->ip, INET_ADDRSTRLEN);
    header_pos += INET_ADDRSTRLEN;

    // Copy client_port
    ssinfo->client_sock->port = htons(ssinfo->client_sock->port);
    memcpy(header_pos, &ssinfo->client_sock->port, sizeof(in_port_t));
    header_pos += sizeof(in_port_t);
    ssinfo->client_sock->port = ntohs(ssinfo->client_sock->port);

    // Copy ns_port
    ssinfo->ns_sock->port = htons(ssinfo->ns_sock->port);
    memcpy(header_pos, &ssinfo->ns_sock->port, sizeof(in_port_t));
    header_pos += sizeof(in_port_t);
    ssinfo->ns_sock->port = ntohs(ssinfo->ns_sock->port);

    // Check if ss is reconnecting
    if (paths == NULL)
    {
        // If so, send -1 as number of paths instead.
        uint64_t temp = -1;
        temp = htonll(temp);
        memcpy(header_pos, &temp, sizeof(uint64_t));
        temp = ntohll(temp);
    }
    else
    {
        // Copy number of paths
        num_paths = htonll(num_paths);
        memcpy(header_pos, &num_paths, sizeof(uint64_t));
        num_paths = ntohll(num_paths);
    }

    int64_t retval = send_messages(ns_ss_sock, header, INET_ADDRSTRLEN + 2*sizeof(in_port_t) + sizeof(uint64_t), 1);
    if (retval == -1)
    {
        printf("send_messages failed\n");
        return NULL;
    }

    // Check if ss is reconnecting
    if (paths == NULL)
    {
        // If so, send the uid
        retval = send_messages(ns_ss_sock, &num_paths, sizeof(uint64_t), 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return NULL;
        }
    }
    else
    {
        // Now send each path. We can be clever here and send each path seprately since
        // the max path name in linux is 4096 and our message size is 4096.

        for (uint64_t i = 0; i < num_paths; i++)
        {
            retval = send_messages(ns_ss_sock, paths[i], strlen(paths[i]), 1);
            if (retval == -1)
            {
                printf("send_messages failed\n");
                return NULL;
            }
        }
    }

    // Now wait for the ss_uid
    retval = recv_message(ns_ss_sock, (char*)&ssinfo->ss_uid);
    if (retval != sizeof(uint64_t))
    {
        printf("Malformed ss_uid received!\n");
        return NULL;
    }
    ssinfo->ss_uid = ntohll(ssinfo->ss_uid);

    // We are done
    return ssinfo;
}

int client_command(sockinfo ns_sock, char* path, char cmd, char* copy_to)
{
    // If command was to quit, then close socket
    if (cmd == 6)
    {
        close(ns_sock->fd);
        return 0;
    }

    // First send command
    int64_t retval = send_messages(ns_sock, &cmd, 1, 1);
    if (retval == -1)
    {
        printf("send_messages failed\n");
        return -1;
    }

    // Create
    if (cmd == 0)
    {
        // Send path
        retval = send_messages(ns_sock, path, strlen(path), 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }

        // Wait for response
        char msg;
        retval = recv_message(ns_sock, &msg);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }
        if (retval != 1)
        {
            printf("Received malformed ACK\n");
            return 1;
        }
        if (msg == ERR_INV_PATH)
        {
            printf("ns response: Invalid path!\n"); 
            return 1;
        }
        if (msg == 0)
        {
            printf("ns: %s created\n", path);
            return 0;
        }
    }

    // Delete
    if (cmd == 1)
    {
        // Send path
        retval = send_messages(ns_sock, path, strlen(path), 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }

        // Wait for response
        char msg;
        retval = recv_message(ns_sock, &msg);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }
        if (retval != 1)
        {
            printf("Received malformed ACK\n");
            return 1;
        }

        if (msg == ERR_INV_PATH)
        {
            printf("ns: Invalid path!\n");
            return 0;
        }
        if (msg == 2)
        {
            printf("ns: Insufficient permissions!\n");
            return 0;
        }

        printf("ns: %s was deleted\n", path);
        return 0;
    }

    // Copy
    if (cmd == 2)
    {
        // Send both paths
        char* msg = malloc(strlen(path) + 1 + strlen(copy_to));
        memcpy(msg, path, strlen(path));
        *(msg + strlen(path)) = 0;
        memcpy(msg + strlen(path) + 1, copy_to, strlen(copy_to));

        retval = send_messages(ns_sock, msg, strlen(path) + 1 + strlen(copy_to), 0);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }

        // Now wait for response
        retval = recv_message(ns_sock, msg);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            return -1;
        }
        if (retval != 1)
        {
            printf("Received malformed ack!\n");
            return 1;
        }
        if (*msg == ERR_INV_PATH)
        {
            printf("Invalid path!\n");
            return 1;
        }
        printf("ns: %s was copied to %s\n", path, copy_to);
        return 0;
    }

    // Read
    if (cmd == 3)
    {
        //send file path to ns(send)
        //ns should respond with ssuid, ip, port(receive)
        //if uid != 0, then its a redundant server

        int retval = send_messages(ns_sock, path, strlen(path), 1);
        if(retval == -1)
        {
            printf("sending file path to ns failed\n");
            return 1;
        }

        //(ssu_uid, ip, port) malloc then receive
        char* buf = malloc(sizeof(uint64_t) + INET_ADDRSTRLEN + sizeof(in_port_t)); 

        retval = recv_message(ns_sock, buf);
        if(retval == -1)
        {
            printf("Error receiving ss data from ns\n");
            return 1;
        }
        

        uint64_t ss_uid;
        memcpy(&ss_uid, buf, sizeof(uint64_t));

        //convert to host format
        ss_uid = ntohll(ss_uid);
        if(ss_uid == ERR_READ_INV_PATH) //bad path, garbage rest of values
        {
            printf("Error: Invalid path requested\n");
            return 1; 
        }
        else if(ss_uid == ERR_SERV_DOWN)
        {
            printf("Error: server and redundants down\n");
            return 1; 
        }

        //get ip and port
        char* ip = malloc(INET_ADDRSTRLEN);
        memcpy(ip, buf + sizeof(uint64_t), INET_ADDRSTRLEN);

        in_port_t port;
        memcpy(&port, buf + sizeof(uint64_t) + INET_ADDRSTRLEN, sizeof(in_port_t));

        port = ntohs(port);

        sockinfo ss_sock = port_connect(ip, port);
        //now client has obtained the ssuid, ip, port for executing command.
        //send the request to the ss

        if(ss_uid != 0) //redudant server
        {
            //append uid/ to path and send to ss
            char* newpath = malloc(21 + strlen(path)); //21 for uint64
            sprintf(newpath, "%lu/%s", ss_uid, path); //!check

            ss_command(ss_sock , newpath, strlen(newpath), 3, NULL, 0, NULL); 
        }
        else
        {
            //not redundant: no editing path
            ss_command(ss_sock, path, strlen(path), 3, NULL, 0, NULL); 
        }

        // send ack to ns
        char msg  = 0;
        retval = send_messages(ns_sock, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        
        close(ss_sock->fd);
        free(ss_sock);
        return 0;
    }

    // Write
    if (cmd == 4)
    {
        //send file path to ns(send)
        //ns should respond with char, ip, port(receive)

        int retval = send_messages(ns_sock, path, strlen(path), 1);
        if(retval == -1)
        {
            printf("sending file path to ns failed\n");
            return 1;
        }

        //rec_v buf structure?
        char* buf = malloc(1 + INET_ADDRSTRLEN + sizeof(in_port_t)); 

        retval = recv_message(ns_sock, buf);
        if(retval == -1)
        {
            printf("Error receiving ss data from ns\n");
            return 1;
        }

        char ss_status = buf[0];
        if(ss_status == SERVER_UNAVAILABLE) 
        {
            printf("Error: server unavailable\n");
            return 1;
        }
        else if(ss_status == ERR_WRITE_INV_PATH)
        {
            printf("Error: invalid path\n");
            return 1;
        }
 
        //get ip and port
        char* ip = malloc(INET_ADDRSTRLEN);
        memcpy(ip, buf + 1, INET_ADDRSTRLEN);

        in_port_t port;
        memcpy(&port, buf + 1 + INET_ADDRSTRLEN, sizeof(in_port_t));
        port = htons(port);

        sockinfo ss_sock = port_connect(ip, port);
        if (ss_sock == NULL)
        {
            printf("port_connect failed\n");
            exit(EXIT_FAILURE);
        }
        
        //now client has obtained the ssuid, ip, port for executing command.
        //send the request to the ss

        ss_command(ss_sock, path, strlen(path), 4, NULL, 0, NULL); 

        // send ack to ns
        char msg  = 0;
        retval = send_messages(ns_sock, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        
        close(ss_sock->fd);
        free(ss_sock);
        return 0;
    }

    // Info
    if (cmd == 5)
    {
        //send file path to ns(send)
        //ns should respond with ssuid, ip, port(receive)
        //if uid != 0, then its a redundant server(handled in client read)

        int retval = send_messages(ns_sock, path, strlen(path), 1);
        if(retval == -1)
        {
            printf("sending file path to ns failed\n");
            return 1;
        }

        char* buf = malloc(sizeof(uint64_t) + INET_ADDRSTRLEN + sizeof(in_port_t)); 

        retval = recv_message(ns_sock, buf);
        if(retval == -1)
        {
            printf("Error receiving ss data from ns\n");
            return 1;
        }

        uint64_t ss_uid;
        memcpy(&ss_uid, buf, sizeof(uint64_t));

        //convert to host format
        ss_uid = ntohll(ss_uid);

        if(ss_uid == ERR_READ_INV_PATH) //bad path, garbage rest of values
        {
            printf("Error: Invalid path requested\n");
            return 1; 
        }
        else if(ss_uid == ERR_SERV_DOWN)
        {
            printf("Error: server and redundants down\n");
            return 1; 
        }

        //get ip and port
        char* ip = malloc(INET_ADDRSTRLEN);
        memcpy(ip, buf + sizeof(uint64_t), INET_ADDRSTRLEN);

        in_port_t port;
        memcpy(&port, buf + sizeof(uint64_t) + INET_ADDRSTRLEN, sizeof(in_port_t));

        port = ntohs(port);

        sockinfo ss_sock = port_connect(ip, port);

        //now client has obtained the ss_socks for executing command.
        //send the request to the ss

        if(ss_uid != 0) //redudant server
        {
            //append uid/ to path and send to ss
            char* newpath = calloc(21 + strlen(path), 1); //21 for uint64
            sprintf(newpath, "%lu/%s", ss_uid, path); //!check

            ss_command(ss_sock, newpath, strlen(newpath), 5, NULL, 0, NULL); 
        }
        else
        {
            //not redundant: no editing path
            ss_command(ss_sock, path, strlen(path), 5, NULL, 0, NULL); 
        }

        // send ack to ns
        char msg  = 0;
        retval = send_messages(ns_sock, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }

        close(ss_sock->fd);
        free(ss_sock);
        return 0;
    }

    return 0;
}