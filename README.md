# final-project-58

## Common Communication Protocol API
Using TCP ports, we still need to identify when a specific message starts and ends. So we will use the following functions,

- `int send_messages(int sockfd, void* data, uint64_t len)` - Firsts sends a message which contains the number of messages that are part of the same data. Then sends as many messages as required to transmit the data and returns the number of messages sent. Returns -1 on error.
- `msg recv_message(int sockfd, char* buf)` - Recieves a single message and returns a pointer to a msg struct containing the message. Returns NULL on error.
- `sockinfo port_bind(in_port_t port)` - Binds to the provided local port. If port is 0 it randomly chooses a free one.
- `sockinfo port_connect(char* hostip, in_port_t port)` - Connects to the provided port on the given IP address.

## Name Server API
Provides the following functions,

### `ss_info add_storage_server(char* ns_ip, in_port_t ns_ss_port, char** paths, int num_paths)`
Creates and returns sockinfo for a dedicated ns port and a dedicated client port. "paths" is a list of paths relative to the current working directory of the ss that are to be accessible for the given ss. A unique identifier for the ss is also returned in ss_info.

### `ss_info reconnect_storage_server(char* ns_ip, in_port_t ns_ss_port, int ss_uid)`
Reconnects a ss to the ns.

### `response client_command(int nsfd, char* path, char cmd)`
Communicates with the nameserver and performs the command requested by the client. Returns a response struct with a flag indicating whether the operation was successful or not. The response struct may also contain a pointer to some additional data which may be required based on the type of operation. The following table lists the types of operations and their results.

| Operation | Additional Data Returned | Description |
| :---: | :---- | :--- |
| Create('n')/Delete('d')/Copy('c')/List('l') | no additional data is returned, however some info may be printed where necessary | The NS takes care of these operations |
| Read('r')/Write('w')/Info('i') | sockinfo of client port of relevant ss is returned | The SS takes care of these operations |

## Storage Server API

### `int ss_command(int ssfd, char* path, char cmd, char* copy_path, sockinfo copy_to)`
Communicates with the storage server and performs the command requested by the client/nameserver. Returns signifies whether operation was successful or not. The following table lists the types of operations and their results.

| Operation | Description |
| :---: | :--- |
| Create('n')/Delete('d') | The SS singlehandedly takes care of these operations |
| Read('r')/Info('i') | The SS sends requested data to caller and prints it. |
| Copy('c') | The SS copies the file/folder at path to the ss (info in copy_to) at the path copy_path. If copy_to is NULL, then it is a local copy. |
| Write('w') | Copy the file to the client and ask them to make changes and then overwrite the file. |

### `int ss_duplicate(int ss_uid, int ssfd, char* path, char cmd)`
Performs either,

| Operation | Description |
| :---: | :--- |
| Delete('d') | Deletes the file/folder at path |
| Create('c') | Creates a file/folder at path |
| Transfer('t') | Transfers the file/folder at path (in the original ss) to the same path here. This could either be an overwrite in the case that the files contents were changed. Or it could be a completely new file/folder in the case of a copy. |

## Client API
Literally nothing. Has nothing of any value. Most useless program ever. @Aisha help ashvin or me :(

## ASSUMPTIONS
- The read operation by the client results in the required file contents being copied to a local dir called NFS_READS/. Client can then read file from said directory.
- The write operation by the client results in the creation of NFS_WRITES/ directory, in which the file to be written to is transferred. The client can then make the desired edits within that.
- The user inputs a file during ss initialization containing the accessible paths. Directory names end with '/', file names do not. This file must be non-empty.
- Every file has rwx permissions.
