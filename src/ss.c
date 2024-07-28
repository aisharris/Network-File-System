#define _POSIX_C_SOURCE 200809L
//client thread handles read, write requests
//ns thread handles create, delete, copy

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <libgen.h>

#include "ccp.h"
#include "ns_api.h"
#include "ss.h"
#include "ss_api.h"

#define MAX_PATH_LEN 4096
#define MAX_CONN_REQUESTS 10

FILE* ss_logfp;
pthread_mutex_t ss_log_lock = PTHREAD_MUTEX_INITIALIZER;

void* client_thread(void* arg)
{
    sockinfo client_sock = arg;

    //read request from ns_sock

    //create buffer of size 4096
    char* buf = malloc(sizeof(char) * (MAX_PATH_LEN+1));
    if(buf == NULL)
    {
        printf("malloc failed\n");
        exit(EXIT_FAILURE);
    }

    //pass into recvmessages
    int64_t retval = recv_message(client_sock, buf);
    if(retval == -1)
    {
        printf("recv_message failed\n");
        exit(EXIT_FAILURE);
    }   

    uint8_t command;

    //ping
    if(retval != 1)
    {
        printf("Received malformed ping!\n");
        close(client_sock->fd);
        free(client_sock);
        return NULL;
    }
    else
    {
        command = buf[0];

        //send ack
        char msg = 1;
        retval = send_messages(client_sock, &msg, 1, 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Received command (%d) from IP: %s, port: %hu\n", command, client_sock->ip, client_sock->port);
    }

    //! what are the commands for read and write?
    if(command == 3) //read
    {
        // Get path first
        retval = recv_message(client_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;
        //add to log
        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "%s:%hu %hhu %s\n", client_sock->ip, client_sock->port, command, buf); //buf contains path 
        pthread_mutex_unlock(&ss_log_lock);

        //send number of packets to expect
        uint64_t num_packets = 0;
        FILE* fp = fopen(buf, "r");
        //ns should have checked this:
        if(fp == NULL)
        {
            printf("fopen failed\n");
            exit(EXIT_FAILURE);
        }

        //move fp to end of file, get file size, move fp back to start
        fseek(fp, 0L, SEEK_END);
        uint64_t file_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        num_packets = file_size / MAX_MSG_LEN;

        if(file_size % MAX_MSG_LEN != 0)
            num_packets++;
        
        //send num_packets to clientint
        retval = send_messages(client_sock, &num_packets, sizeof(uint64_t), 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        //receive ack
        retval = recv_message(client_sock, buf);
        if(retval != 1)
        {
            printf("recv_message ack from client failed\n");
            exit(EXIT_FAILURE);
        }
        //add to log
        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "Successfully received ACK from client for read packet count\n");  
        pthread_mutex_unlock(&ss_log_lock);
        printf("Received ack from client for read packet count");

        //send packets
        char* packet = malloc(sizeof(char) * MAX_MSG_LEN);
        if(packet == NULL)
        {
            printf("malloc failed\n");
            exit(EXIT_FAILURE);
        }
        for(uint64_t i = 0; i < num_packets; i++)
        {
            //read from file
            retval = fread(packet, sizeof(char), MAX_MSG_LEN, fp);
            if(retval == -1)
            {
                printf("fread failed\n");
                exit(EXIT_FAILURE);
            }
            //send to client
            retval = send_messages(client_sock, packet, retval, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            //receive ack after client has appended to its local file
            retval = recv_message(client_sock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || (buf[0] != 1 && buf[0] != 2))
            {
                printf("Receieved malformed ack!\n");
                close(client_sock->fd);
                free(client_sock);
                return 0;
            }
            if(buf[0] == 2) //!STOP signal is a size 2 ack
            {
                printf("STOP packet received\n");
                close(client_sock->fd);
                free(client_sock);
                break;
            }
            //add to log
            pthread_mutex_lock(&ss_log_lock);
            //ip:port command path
            fprintf(ss_logfp, "Successfully received ACK from client for read\n");  
            pthread_mutex_unlock(&ss_log_lock);
            printf("Received ack from client for read");
        }

        fclose(fp);
        free(packet);
        //done sending file
    }
    if(command == 4) //write
    {
        //we have to take the file and send it to the client
        //buf contains the path of the file to be sent
        //file size/4096 = no. of packets to send
        //first message to client will be the number of packets to expect
        //then send the packets, which the client should append to local file in order and empty the buffer
        //send a ping after completion

        // Get path first
        retval = recv_message(client_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;
        //add to log
        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "%s:%hu %hhu %s\n", client_sock->ip, client_sock->port, command, buf); //buf contains path 
        pthread_mutex_unlock(&ss_log_lock);
        printf("Received write command from client");

        char* filepath = strdup(buf);

        //send number of packets to expect
        uint64_t num_packets = 0;
        FILE* fp = fopen(buf, "r");
        //ns should have checked this:
        if(fp == NULL)
        {
            printf("fopen failed\n");
            exit(EXIT_FAILURE);
        }

        //move fp to end of file, get file size, move fp back to start
        fseek(fp, 0L, SEEK_END);
        uint64_t file_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        num_packets = file_size / MAX_MSG_LEN;

        if(file_size % MAX_MSG_LEN != 0)
            num_packets++;
        
        //send num_packets to clientint
        retval = send_messages(client_sock, &num_packets, sizeof(uint64_t), 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        //receive ack
        retval = recv_message(client_sock, buf);
        if(retval == -1)
        {
            printf("recv_message ack from client failed\n");
            exit(EXIT_FAILURE);
        }
        //add to log
        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "Successfully received ACK from client for write packet count\n");  
        pthread_mutex_unlock(&ss_log_lock);
        printf("Received ack from client for write packet count");

        //send packets
        char* packet = malloc(sizeof(char) * MAX_MSG_LEN);
        if(packet == NULL)
        {
            printf("malloc failed\n");
            exit(EXIT_FAILURE);
        }
        for(uint64_t i = 0; i < num_packets; i++)
        {
            //read from file
            retval = fread(packet, sizeof(char), MAX_MSG_LEN, fp);
            if(retval == -1)
            {
                printf("fread failed\n");
                exit(EXIT_FAILURE);
            }
            //send to client
            retval = send_messages(client_sock, packet, retval, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            //receive ack after client has appended to its local file
            retval = recv_message(client_sock, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || (buf[0] != 1 && buf[0] != 2)) //!ping back will send 1 pr 2?
            {
                printf("Receieved malformed ack!\n");
                close(client_sock->fd);
                free(client_sock);
                return 0;
            }
            if(buf[0] == 2) //!STOP signal is a size 2 ack
            {
                printf("STOP packet received\n");
                break;
            }
            //add to log
            pthread_mutex_lock(&ss_log_lock);
            //ip:port command path
            fprintf(ss_logfp, "Successfully received ACK from client for write\n");  
            pthread_mutex_unlock(&ss_log_lock);
            printf("Received ack from client for write");
        }

        fclose(fp);

        //done sending. now receive file(after client makes edits) and put it back where it was
        //(overwrite on original filepath)

        //first receive number of packets
        num_packets = 0;
        retval = recv_message(client_sock, (char*)&num_packets);
        if(retval == -1)
        {
            printf("recv_messages failed hi\n");
            exit(EXIT_FAILURE);
        }
        //send ack
        char msg = 1;
        retval = send_messages(client_sock, &msg, 1, 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }

        //clear file and append
        fp = fopen(filepath, "w");
        fclose(fp);
        fp = fopen(filepath, "a");

        //receive file contents
        for(uint64_t i = 0 ; i < num_packets; i++)
        {
            //receive packet
            retval = recv_message(client_sock, packet);
            if(retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }

            //write to file
            retval = fwrite(packet, sizeof(char), retval, fp);
            if(retval == -1)
            {
                printf("fwrite failed\n");
                exit(EXIT_FAILURE);
            }

            //send ack
            retval = send_messages(client_sock, &msg, 1, 1);
            if(retval == -1)
            {
                printf("send_messages ack to client failed\n");
                exit(EXIT_FAILURE);
            }
        }
        //done updating file

        fclose(fp);
    }
    if(command == 5) //info
    {
        //use system to get the info of the input file

        //buf structure: file size(off_t), read permission(int), write permission(int), execute permission(int)

        // Get path first
        retval = recv_message(client_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;

        //add to log
        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "%s:%hu %hhu %s\n", client_sock->ip, client_sock->port, command, buf); //buf contains path 
        pthread_mutex_unlock(&ss_log_lock);
        printf("Received command info from client");

        char* filepath = strdup(buf);

        struct stat file_stat;

        off_t fsize = -1;
        int readp = -1;
        int writep = -1;
        int execp = -1;

        if (stat(filepath, &file_stat) == 0) 
        {
            fsize = file_stat.st_size;
            readp = access(filepath, R_OK) == 0;
            writep = access(filepath, W_OK) == 0;
            execp = access(filepath, X_OK) == 0;
        } 
        else 
        {
            perror("Error getting file information");
            exit(EXIT_FAILURE);
        }

        int bufsize = snprintf(NULL, 0, "%ld %d %d %d", fsize, readp, writep, execp);
        
        if (bufsize < 0) 
        {
            perror("Error in snprintf");
            close(client_sock->fd);
            free(client_sock);
            return NULL;
        }

        bufsize += 1;

        char* buffer = malloc(bufsize);

        int written = snprintf(buffer, bufsize, "%ld %d %d %d", fsize, readp, writep, execp);
        if(written == 0)
        {
            printf("snprintf for file info failed\n");
            exit(EXIT_FAILURE);
        }

        //send it to the ns
        retval = send_messages(client_sock, buffer, bufsize, 1);
        if(retval == -1)
        {
            printf("send_messages for file info failed\n");
            exit(EXIT_FAILURE);
        }

        //get ping back
//receive ack after client has appended to its local file
        retval = recv_message(client_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        if (retval != 1 || (buf[0] != 1 && buf[0] != 2)) 
        {
            printf("Receieved malformed ack!\n");
            close(client_sock->fd);
            free(client_sock);
            return 0;
        }
        //add to log
        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "Successfully received ACK from client for info\n");  
        pthread_mutex_unlock(&ss_log_lock);
        printf("Received ack from client for info");

    }

    close(client_sock->fd);
    free(client_sock);
    free(buf);

    return 0;
}

void* ns_thread(void* arg)
{
    sockinfo ns_sock = arg;

    //read request from ns_sock

    //create buffer of size 4097
    char* buf = malloc(sizeof(char) * (MAX_PATH_LEN+1));
    if(buf == NULL)
    {
        printf("malloc failed\n");
        exit(EXIT_FAILURE);
    }

    //pass into recvmessage
    int retval = recv_message(ns_sock, buf);
    if(retval == -1)
    {
        printf("recv_messages failed\n");
        exit(EXIT_FAILURE);
    }   
//!move this down after we know the ping back isnt malformed?
    printf("Received request from NS at %s:%hu, command - %d\n", ns_sock->ip, ns_sock->port, buf[0]);
    //add to log
    pthread_mutex_lock(&ss_log_lock);
    //ip:port command path
    fprintf(ss_logfp, "%s:%hu %hhu %c ", ns_sock->ip, ns_sock->port, buf[0]); 
    pthread_mutex_unlock(&ss_log_lock);

    uint8_t command;

    //ping
    if(retval != 1)
    {
        printf("Malformed ping request received!\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        command = buf[0];
        //reply:
        //send back a one byte message
        char* msg = malloc(sizeof(char));
        msg[0] = 1; //ping response
        retval = send_messages(ns_sock, msg, 1, 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        free(msg);
    }

    // ping, so leave
    if (command == 40)
    {
        close(ns_sock->fd);
        free(ns_sock);
        free(buf);
        return EXIT_SUCCESS;
    }
    
    if(command == 0) //create
    {
        retval = recv_message(ns_sock, buf);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;

        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "path: %s\n", buf); 
        pthread_mutex_unlock(&ss_log_lock);

        retval = create_file(buf, retval);
        if(retval == 1)
        {
            //send ack after completion
            char msg = 1;
            retval = send_messages(ns_sock, &msg, 1, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            pthread_mutex_lock(&ss_log_lock);
            //ip:port command path
            fprintf(ss_logfp, "Create successful\n"); 
            pthread_mutex_unlock(&ss_log_lock);
            printf("Create successful\n");
        }
        //else ping failure
        else
        {
            char msg = 0;
            retval = send_messages(ns_sock, &msg, 1, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    if(command == 1) //delete
    {
        retval = recv_message(ns_sock, buf);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;

        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "path: %s\n", buf); 
        pthread_mutex_unlock(&ss_log_lock);

        retval = delete_file(buf, retval);
        if(retval)
        {
            //send ack after completion
            char* msg = malloc(sizeof(char));
            msg[0] = 1; //ping response
            retval = send_messages(ns_sock, msg, 1, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            free(msg);

            pthread_mutex_lock(&ss_log_lock);
            //ip:port command path
            fprintf(ss_logfp, "Delete successful\n"); 
            pthread_mutex_unlock(&ss_log_lock);
            printf("Delete successful\n");
        }
    }
    if(command == 2) //copy
    {
        //first : ip and port (if port == 0, file from same ss)
        //second : copy from path
        //third : copy to path

        //buf structure: ip, port, copy from file path, null char, copy to folder path
        buf = realloc(buf, sizeof(char) * (INET_ADDRSTRLEN + sizeof(in_port_t) + 2*MAX_PATH_LEN + 1));
        
        int message_len;
        message_len = recv_messages(ns_sock, buf);
        if(message_len == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }

        //parse buf

        char* ip = strndup(buf, INET_ADDRSTRLEN);

        in_port_t port;

        memcpy(&port, buf + INET_ADDRSTRLEN, sizeof(in_port_t));

        char* copy_from_path;

        copy_from_path = strndup(buf + INET_ADDRSTRLEN + sizeof(in_port_t), message_len - (INET_ADDRSTRLEN + sizeof(in_port_t)));

        int size = strlen(copy_from_path);

        // printf("size of buf - %d\n", message_len);
        // printf("size of copy_from - %d\n", size);
        // printf("size of copy_to - %ld\n", message_len - (INET_ADDRSTRLEN + sizeof(in_port_t) + size+1));

        char* copy_to_path = malloc(sizeof(char) * (message_len - (INET_ADDRSTRLEN + sizeof(in_port_t) + size + 1)+1));
        memcpy(copy_to_path, buf + INET_ADDRSTRLEN + sizeof(in_port_t) + size+1, message_len - (INET_ADDRSTRLEN + sizeof(in_port_t) + size+1));
        copy_to_path[message_len - (INET_ADDRSTRLEN + sizeof(in_port_t) + size + 1)] = '\0';


        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "ip: %s, port: %hu, src: %s, dest: %s\n", ip, port, copy_from_path, copy_to_path); 
        pthread_mutex_unlock(&ss_log_lock);

        copy_file(copy_from_path, copy_to_path, ip, port);

        pthread_mutex_lock(&ss_log_lock);
        //ip:port command path
        fprintf(ss_logfp, "Copy successful\n"); 
        pthread_mutex_unlock(&ss_log_lock);
        printf("Copy successful\n");

        char msg = 0;
        retval = send_messages(ns_sock, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
    }
    if(command == 6) //read perm
    {
        // Get path first
        retval = recv_message(ns_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;

        int readp = access(buf, R_OK) == 0;

        if(readp == 1)
        {
            buf[0] = 1;

        }
        else if(readp == 0)
        {
            buf[0] = 0;
        }
        //send it to the ns
        retval = send_messages(ns_sock, buf, 1, 1);
        if(retval == -1)
        {
            printf("send_messages for file info failed\n");
            exit(EXIT_FAILURE);
        }

        //get ping back
        //receive ack after client has appended to its local file
        retval = recv_message(ns_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        if (retval != 1 || (buf[0] != 1 && buf[0] != 2)) 
        {
            printf("Receieved malformed ack!\n");
            close(ns_sock->fd);
            free(ns_sock);
            return 0;
        }        

    }
    if(command == 7) //write perm
    {
        // Get path first
        retval = recv_message(ns_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        buf[retval] = 0;

        int writep = -1;

        writep = access(buf, W_OK) == 0;
        
        if(writep == 1)
        {
            buf[0] = 1;

        }
        else if(writep == 0)
        {
            buf[0] = 0;
        }
        //send it to the ns
        retval = send_messages(ns_sock, buf, 1, 1);
        if(retval == -1)
        {
            printf("send_messages for file info failed\n");
            exit(EXIT_FAILURE);
        }

        //get ping back
        //receive ack after client has appended to its local file
        retval = recv_message(ns_sock, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        if (retval != 1 || (buf[0] != 1 && buf[0] != 2)) 
        {
            printf("Receieved malformed ack!\n");
            close(ns_sock->fd);
            free(ns_sock);
            return 0;
        }        
    }

    close(ns_sock->fd);
    free(ns_sock);
    free(buf);

    return 0;
}


//creates file/dir, returns 1 on success, 0 on failure
int create_file(char* buf, int pathlen)
{
    //use execvp to create a file 
    //buf contains the path of the file to be created
    printf("[%s] - %d\n", buf, pathlen);
    if(buf[pathlen - 1] == '/') //directory
    {
        buf[pathlen - 1] = '\0';
        char* command = malloc(strlen("mkdir -p ") + strlen(buf) + 1);
        *command = 0;
        strcat(command, "mkdir -p ");
        strcat(command, buf);
        printf("create dir sys command: %s\n", command);
        int ret = system(command);
        if(ret == -1)
        {
            perror("system");
            return 0;
        }
    }
    else //file
    {
        char* command = malloc(strlen("touch ") + strlen(buf) + 1);
        *command = 0;
        strcat(command, "touch ");
        strcat(command, buf);
        printf("create file sys command: %s\n", command);
        int ret = system(command);
        if(ret == -1)
        {
            perror("system");
            return 0;
        }
    }

    return 1;
}

int delete_file(char* buf, int pathlen)
{
    //use execvp to delete a file
    //buf contains the path of the file to be deleted

    if(buf[pathlen - 1] == '/') //directory
    {
        buf[pathlen - 1] = '\0';
        char* command = malloc(strlen("rm -rf ") + strlen(buf) + 1);
        *command = 0;
        strcat(command, "rm -rf ");
        strcat(command, buf);
        printf("create file sys command: %s\n", command);
        int ret = system(command);
        if(ret == -1)
        {
            perror("system");
            return 0;
        }
    }
    else //file
    {
        char* command = malloc(strlen("rm ") + strlen(buf) + 1);
        *command = 0;
        strcat(command, "rm ");
        strcat(command, buf);
        printf("create file sys command: %s\n", command);
        int ret = system(command);
        if(ret == -1)
        {
            perror("system");
            return 0;
        }
    }
    return 1;
}

void copy_file(char * src_file, char* dest_dir, char* ip, in_port_t port)
{
    //read from other ss, write to this ss
    //essentially like the read from client
    //now you already have the socket

    //check if port == 0
    if(port == 0)
    {
        //cmd: cd src_file dest_dir
        char* command = malloc(MAX_PATH_LEN*2 + 4);
        sprintf(command, "cp %s %s", src_file, dest_dir);

        // Execute the command using system
        int result = system(command);
        if (result == -1)
        {
            perror("system");
            return;
        }
    }
    else
    {
        sockinfo sockin = port_connect(ip, port);
        if (sockin == NULL)
        {
            printf("oaoajodfa\n");
            exit(EXIT_FAILURE);
        }

        //not redundant: no editing path
        ss_command(sockin , src_file, strlen(src_file), 3, NULL, 0, NULL); 

        close(sockin->fd);
        free(sockin);
        
        // Build the command string
        char command[4096*2 + 5];  // Adjust the size based on your needs

        char* duplicate = strdup(src_file);

        char* basenm = basename(duplicate);


        char* readfile = malloc(4096);
        sprintf(readfile, "./NFS_READS/%s", basenm);
        free(duplicate);

        snprintf(command, sizeof(command), "mv %s %s", readfile, dest_dir);

        // Execute the command using system
        int result = system(command);
        if (result == -1)
        {
            perror("system");
            return;
        }
    }
}

void handle_ns_request(sockinfo ns_sock)
{
    sockinfo name_sock = port_accept(ns_sock);
    if (name_sock == NULL)
    {
        printf("port_accept failed\n");
        exit(EXIT_FAILURE);
    }

    pthread_t t;
    int retval = pthread_create(&t, NULL, ns_thread, name_sock);
    if (retval == -1)
    {
        printf("pthread_create failed\n");
        exit(EXIT_FAILURE);
    }
    retval = pthread_detach(t);
    if (retval == -1)
    {
        printf("pthread_detach failed\n");
        exit(EXIT_FAILURE);
    }
}

void handle_client_request(sockinfo client_sock)
{
    sockinfo clt_sock = port_accept(client_sock);
    if (clt_sock == NULL)
    {
        printf("port_accept failed\n");
        exit(EXIT_FAILURE);
    }

    pthread_t t;
    int retval = pthread_create(&t, NULL, client_thread, clt_sock);
    if (retval == -1)
    {
        printf("pthread_create failed\n");
        exit(EXIT_FAILURE);
    }
    retval = pthread_detach(t);
    if (retval == -1)
    {
        printf("pthread_detach failed\n");
        exit(EXIT_FAILURE);
    }
}


//qsort function to compare strings based on number of slashes
int slashSort(const void* a, const void* b)
{
    char* str1 = *(char**)a;
    char* str2 = *(char**)b;

    int count1 = 0;
    int count2 = 0;

    for(int i = 0; i < strlen(str1); i++)
    {
        if(str1[i] == '/')
        {
            count1++;
        }
    }
    for(int i = 0; i < strlen(str2); i++)
    {
        if(str2[i] == '/')
        {
            count2++;
        }
    }
    if (count1 - count2 == 0)
    {
        if (str1[strlen(str1)-1] == '/')
            return -1;
        if (str2[strlen(str2)-1] == '/')
            return 1;
    }

    return count1 - count2;
}

int main()
{
    //INITIALIZE LOG FILE

    ss_logfp = fopen("ss_log.txt", "w");

    ss_socks ssinfo = 0;
    //before getting paths from user check if it had previously connected to the ns
    //check for existence of the ss_uid.txt file containing its allocated uid
    //if it exists, read the uid and tell the ns it is the ss with that uid(api handled)
    //if it doesn't exist, get paths from user, connect to ns, get uid, write to file
    if(access("ss_uid.txt", F_OK) != -1) //exists
    {
        FILE* fp = fopen("ss_uid.txt", "r");
        if(fp == NULL)
        {
            printf("Error opening file: fopen\n");
            exit(EXIT_FAILURE);
        }

        uint64_t content;
        int retval = fread(&content, sizeof(uint64_t), 1, fp);
        if(retval == -1)
        {
            printf("Error reading file: fread\n");
            exit(EXIT_FAILURE);
        }

        //get ns ip and port(how? user input:)
        char* ns_ip = malloc(sizeof(char) * INET_ADDRSTRLEN);
        in_port_t ns_port;

        printf("Enter name server ip: ");
        scanf("%s", ns_ip);
        printf("Enter name server port: ");
        scanf("%hu", &ns_port);

        ssinfo = add_storage_server(ns_ip, ns_port, NULL, content);
        if(ssinfo == NULL)
        {
            printf("add_storage_server failed\n");
            exit(EXIT_FAILURE);
        }

        //!anything else?
    }
    else //doesn't exist
    {   
        //get paths from file given by user
        char* paths[MAX_PATH_LEN];

        uint64_t num_paths = 0;
        char* line = NULL;
        size_t len = 0;
        ssize_t read;
        char* file_path = malloc(sizeof(char)*(MAX_PATH_LEN+1));

        printf("Enter file containing accessible paths: ");
        scanf("%s", file_path);

        printf("file_path: %s\n", file_path);

        FILE* fp = fopen(file_path, "r");
        if (fp == NULL)
        {
            printf("Error opening file\n");
            exit(EXIT_FAILURE);
        }

        while ((read = getline(&line, &len, fp)) != -1) 
        {
            if (line[read-1] == '\n')
                line[read-1] = 0;
            paths[num_paths] = strdup(line);  // Use strdup to allocate memory
            //checked. reads right.
            printf("%ld: %s\n", num_paths, paths[num_paths]);
            num_paths++;
        }

        fclose(fp);
        if (line)
            free(line);

        //check if paths actually accessible?
        for(int i = 0; i < num_paths; i++)
        {
            if(access(paths[i], F_OK) == -1)
            {
                printf("Path %s does not exist\n", paths[i]);
                exit(EXIT_FAILURE);
            }
        }

        //sort by number of slashes in path name
        qsort(paths, num_paths, sizeof(paths[0]), slashSort);

        //get ns ip and port(how? user input:)
        char* ns_ip = malloc(sizeof(char) * INET_ADDRSTRLEN);
        in_port_t ns_port;

        printf("Enter name server ip: ");
        scanf("%s", ns_ip);
        printf("Enter name server port: ");
        scanf("%hu", &ns_port);

        //connect to ns(add_storage_server), returns the ssinfo
        ssinfo = add_storage_server(ns_ip, ns_port, paths, num_paths);
        if(ssinfo == NULL)
        {
            printf("add_storage_server failed\n");
            exit(EXIT_FAILURE);
        }

        //add the file with the ss_uid
        fp = fopen("ss_uid.txt", "w");
        fwrite(&(ssinfo->ss_uid), sizeof(uint64_t), 1, fp);
        fclose(fp);
    }

    printf("Alotted ss_uid: %lu\n", ssinfo->ss_uid);
    printf("Listening to NS at %s:%hu\n", ssinfo->ns_sock->ip, ssinfo->ns_sock->port);
    printf("Listening for clients at %s:%hu\n", ssinfo->client_sock->ip, ssinfo->client_sock->port);

    //listen for ns connections
    int retval = listen(ssinfo->ns_sock->fd, MAX_CONN_REQUESTS);
    if(retval == -1)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //listen for ss connections
    retval = listen(ssinfo->client_sock->fd, MAX_CONN_REQUESTS);
    if(retval == -1)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //handle nm requests: wait until there is data to read from ns sock
    struct pollfd pfds[2];

    pfds[0].fd = ssinfo->ns_sock->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ssinfo->client_sock->fd;
    pfds[1].events = POLLIN;

    while (1)
    {
        poll(pfds, 2, -1);
        if (pfds[0].revents & POLLIN)
            handle_ns_request(ssinfo->ns_sock);
        if (pfds[1].revents & POLLIN)
            handle_client_request(ssinfo->client_sock);
    }
}