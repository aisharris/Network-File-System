#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <libgen.h>

#include "ss_api.h"
#include "ccp.h"

/*
Communicates with the storage server and performs the command requested by the client/nameserver. 
Returns signifies whether operation was successful or not.
*/

// Commands
// Create - 0
// Delete - 1
// Copy - 2
// Read - 3
// Write - 4
// Info - 5
// Check for read perm - 6
// Check for write perm - 7
int ss_command(sockinfo ss_to, char* path, int pathlen, uint8_t cmd, char* copy_path, int copy_pathlen,ss_info ss_from)
{
    int64_t retval = send_messages(ss_to, &cmd, 1, 1);
    if (retval == -1)
    {
        printf("send_messages failed\n");
        return -1;
    }

    uint8_t response;
    retval = recv_message(ss_to, (char*)&response);
    if (retval == -1)
    {
        printf("recv_message failed\n");
        return -1;
    }
    if (retval != 1 || response != 1)
    {
        printf("Received malformed ACK!\n");
        return -1;
    }

    if (cmd != 2)
    {
        retval = send_messages(ss_to, path, pathlen, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }
    }
    else
    {
        if (copy_path[0] == '0')
        {
            copy_path += 2;
            copy_pathlen -= 2;
        }

        char* buff = malloc(INET_ADDRSTRLEN + sizeof(in_port_t) + pathlen + 1 + copy_pathlen);
        if (ss_from != NULL)
            memcpy(buff, ss_from->ip, INET_ADDRSTRLEN);
        if (ss_from != NULL)
        {
            memcpy(buff + INET_ADDRSTRLEN, &ss_from->client_port, sizeof(in_port_t));
        }
        else
        {
            in_port_t tempcock = 0;
            memcpy(buff + INET_ADDRSTRLEN, &tempcock, sizeof(in_port_t));
        }
        memcpy(buff + INET_ADDRSTRLEN + sizeof(in_port_t), path, pathlen);
        *(buff + INET_ADDRSTRLEN + sizeof(in_port_t) + pathlen) = 0;
        memcpy(buff + INET_ADDRSTRLEN + sizeof(in_port_t) + pathlen + 1, copy_path, copy_pathlen);

        retval = send_messages(ss_to, buff, INET_ADDRSTRLEN + sizeof(in_port_t) + pathlen + 1 + copy_pathlen, 0);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }

        free(buff);
    }

    // Read
    if (cmd == 3)
    {
        // Create read file dir if it doesn't already exist
        struct stat st = {0};

        if (stat("./NFS_READS", &st) == -1) {
            mkdir("./NFS_READS", 0700);
        }

        // Now open FP to file
        char* temp_path_copy = strdup(path);
        char* temp_base_name = basename(temp_path_copy);
        char* file_name = malloc(12 + strlen(temp_base_name) + 1);
        memcpy(file_name, "./NFS_READS/", 12);
        memcpy(file_name+12, temp_base_name, strlen(temp_base_name) + 1);
        free(temp_path_copy);

        // Create/Truncate
        FILE* fp = fopen(file_name, "w");
        fclose(fp);
        fp = fopen(file_name, "a");

        // Get number of packets
        uint64_t num_packets;
        retval = recv_message(ss_to, (char*)&num_packets);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            return -1;
        }
        if (retval != sizeof(uint64_t))
        {
            printf("Malformed header received!\n");
            return -1;
        }

        // Send ack
        retval = send_messages(ss_to, &num_packets, 1, 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }

        char* buf = malloc(4096);

        // Now receive packets
        for(uint64_t i = 0 ; i < num_packets; i++)
        {
            //receive packet
            retval = recv_message(ss_to, buf);
            if(retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }

            //write to file
            retval = fwrite(buf, sizeof(char), retval, fp);
            if(retval == -1)
            {
                printf("fwrite failed\n");
                exit(EXIT_FAILURE);
            }

            //send ack
            char msg = 1;
            // Check if user wants to stop
            struct pollfd pfds[1];
            pfds[0].fd = STDIN_FILENO;
            pfds[0].events = POLLIN;
            if ((retval = poll(pfds, 1, 0)) == 1)
            {
                msg = getchar();
                if (msg == 'x')
                    msg = 2;
            }
            else if (retval == -1)
            {
                perror("poll");
                exit(EXIT_FAILURE);
            }

            retval = send_messages(ss_to, &msg, 1, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
        }

        fclose(fp);
        free(buf);
        return 0;
    }
    // Write
    if (cmd == 4)
    {
        // Create read file dir if it doesn't already exist
        struct stat st = {0};

        if (stat("./NFS_WRITES", &st) == -1) {
            mkdir("./NFS_WRITES", 0700);
        }

        // Now open FP to file
        char* temp_path_copy = strdup(path);
        char* temp_base_name = basename(temp_path_copy);
        char* file_name = malloc(13 + strlen(temp_base_name) + 1);
        memcpy(file_name, "./NFS_WRITES/", 13);
        memcpy(file_name+13, temp_base_name, strlen(temp_base_name) + 1);
        free(temp_path_copy);

        // Create/Truncate
        FILE* fp = fopen(file_name, "w");
        fclose(fp);
        fp = fopen(file_name, "a");

        // Get number of packets
        uint64_t num_packets;
        retval = recv_message(ss_to, (char*)&num_packets);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            return -1;
        }
        if (retval != sizeof(uint64_t))
        {
            printf("Malformed header received!\n");
            return -1;
        }

        // Send ack
        retval = send_messages(ss_to, &num_packets, 1, 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }

        char* buf = malloc(4096);

        // Now receive packets
        for(uint64_t i = 0 ; i < num_packets; i++)
        {
            //receive packet
            retval = recv_message(ss_to, buf);
            if(retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }

            //write to file
            retval = fwrite(buf, sizeof(char), retval, fp);
            if(retval == -1)
            {
                printf("fwrite failed\n");
                exit(EXIT_FAILURE);
            }

            //send ack
            char msg = 1;
            // Check if user wants to stop
            struct pollfd pfds[1];
            pfds[0].fd = STDIN_FILENO;
            pfds[0].events = POLLIN;
            if ((retval = poll(pfds, 1, 0)) == 1)
            {
                msg = getchar();
                if (msg == 'x')
                    msg = 2;
            }
            else if (retval == -1)
            {
                perror("poll");
                exit(EXIT_FAILURE);
            }

            retval = send_messages(ss_to, &msg, 1, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
        }

        fclose(fp);

        // Now wait for user to finish edits
        printf("Requested file copied to %s\n", file_name);
        printf("Press any key once done editing: \n");
        char msg;
        scanf(" %c", &msg);

        // Now send file back
        // If file no longer exists, exit
        if (stat(file_name, &st) == -1) {
            printf("\nCouldn't find file %s\n!", file_name);
            return 0;
        }

        num_packets = 0;
        fp = fopen(file_name, "r");

        //move fp to end of file, get file size, move fp back to start
        fseek(fp, 0L, SEEK_END);
        uint64_t file_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        num_packets = file_size / MAX_MSG_LEN;

        if(file_size % MAX_MSG_LEN != 0)
            num_packets++;
        
        //send num_packets to clientint

        retval = send_messages(ss_to, &num_packets, sizeof(uint64_t), 1);
        if(retval == -1)
        {
            printf("send_messages failed\n");
            exit(EXIT_FAILURE);
        }
        //receive ack
        retval = recv_message(ss_to, buf);
        if(retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }
        if (retval != 1)
        {
            printf("Received malformed ack!\n");
            return 0;
        }

        //send packets
        for(uint64_t i = 0; i < num_packets; i++)
        {
            //read from file
            retval = fread(buf, sizeof(char), MAX_MSG_LEN, fp);
            if(retval == -1)
            {
                printf("fread failed\n");
                exit(EXIT_FAILURE);
            }
            //send to ss
            retval = send_messages(ss_to, buf, retval, 1);
            if(retval == -1)
            {
                printf("send_messages failed\n");
                exit(EXIT_FAILURE);
            }
            //receive ack after client has appended to its local file
            retval = recv_message(ss_to, buf);
            if (retval == -1)
            {
                printf("recv_message failed\n");
                exit(EXIT_FAILURE);
            }
            if (retval != 1 || buf[0] != 1)
            {
                printf("Receieved malformed ack!\n");
                return 0;
            }
        }

        fclose(fp);
        return 0;
    }
    // Info
    if (cmd == 5)
    {
        char* buf = malloc(4096);
        retval = recv_message(ss_to, buf);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            return -1;
        }
        
        off_t fsize;
        int readp;
        int writep;
        int execp;
        sscanf(buf, "%ld %d %d %d", &fsize, &readp, &writep, &execp);
        printf("File size: %ld\n", fsize);
        printf("Read perm: %s\n", (readp == 1) ? "yes" : "no");
        printf("Write perm: %s\n", (writep == 1) ? "yes" : "no");
        printf("Exec perm: %s\n", (execp == 1) ? "yes" : "no");
        free(buf);

        char msg = 1;
        retval = send_messages(ss_to, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }
        return 0;
    }
    // Read perm
    if (cmd == 6)
    {
        char ans;
        retval = recv_message(ss_to, &ans);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }

        char msg = 1;
        retval = send_messages(ss_to, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }
        
        return ans;
    }
    // Write perm
    if (cmd == 7)
    {
        char ans;
        retval = recv_message(ss_to, &ans);
        if (retval == -1)
        {
            printf("recv_message failed\n");
            exit(EXIT_FAILURE);
        }

        char msg = 1;
        retval = send_messages(ss_to, &msg, 1, 1);
        if (retval == -1)
        {
            printf("send_messages failed\n");
            return -1;
        }
        
        return ans;
    }
    
    retval = recv_message(ss_to, (char*)&response);
    if (retval == -1)
    {
        printf("recv_message failed\n");
        return -1;
    }
    if (retval != 1)
    {
        printf("Malformed ping response received!\n");
        return -1;
    }

    return response;
}